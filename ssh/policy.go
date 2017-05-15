package ssh

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
)

type Policy struct {
	User                string
	Command             string
	Server              string
	ApprovedAllCommands bool
	SessionOpened       bool
	NoMoreSessions      bool
	AwaitingNMSReply    bool
}

func NewPolicy(u string, c string, s string) *Policy {
	return &Policy{User: u, Command: c, Server: s,
		SessionOpened: false, NoMoreSessions: false, AwaitingNMSReply: false}
}

type policyID func(pc *Policy) ([32]byte)

func (pc *Policy) AskForApproval(store map[[32]byte]bool, makeKey policyID) error {
	reader := bufio.NewReader(os.Stdin)
	var text string
	// switch to regex
	for text != "y" && text != "n" && text != "a" {
		// if with wrapper, approval can be done only for session?
		fmt.Printf(`Approve running '%s' once on %s by %s? [y/n]
(you can also approve all commands for %s on %s for this session) [a]:
`,
		pc.Command, pc.Server, pc.User, pc.User, pc.Server)
		text, _ = reader.ReadString('\n')
		text = strings.ToLower(strings.Trim(text, " \r\n"))
	}

	var err error
	if text == "n" {
		err = errors.New("Policy rejected client request")
	}
	if text == "a" {
		pc.ApprovedAllCommands = true
		// To be changed to include client if we move to one agent total vs one agent per conn
		// similarly, if we remember single commands
		store[makeKey(pc)] = true
		return err
	}
	return err
}

func (pc *Policy) EscalateApproval() error {
	reader := bufio.NewReader(os.Stdin)
	var text string
	// switch to regex
	for text != "y" && text != "n" {
		fmt.Printf(`Approving '%s' on %s by %s will enable the client to 
potentially run all commands on %s. Proceed? [y/n]:
`, pc.Command, pc.Server, pc.User, pc.Server)
		text, _ = reader.ReadString('\n')
		text = strings.ToLower(strings.Trim(text, " \r\n"))
	}

	var err error
	if text == "n" {
		err = errors.New("Policy rejected approval escalation")
	}
	// (dimakogan) store escalation if 'y' --> pro: it is equivalent to saying yes+all,
	// con: server impl may change, asking over and over may serve a purpose.
	// Must change UX to explain consequence if we change it.
	return err	
}

func (pc *Policy) FilterServerPacket(packet []byte) (validState bool, response []byte, err error) {
	decoded, err := decode(packet)
	if err != nil {
		return true, nil, err
	}

	if pc.NoMoreSessions && pc.AwaitingNMSReply {
		switch decoded.(type) {
		case *globalRequestSuccessMsg:
			if debugProxy {
				log.Printf("Server sent no-more-sessions success.")
			}
			pc.AwaitingNMSReply = false
			return true, nil, nil
		case *globalRequestFailureMsg:
			if debugProxy {
				log.Printf("Server sent no-more-sessions failure.")
			}
			pc.AwaitingNMSReply = false

			// (dimakogan) should we enforce asking for nms if all commands approved?
			// I would argue yes, otherwise we break abstraction barrier
			if !pc.ApprovedAllCommands {
				if proceed := pc.EscalateApproval(); proceed != nil {
					return false, Marshal(disconnectMsg{Reason: 3, Message: "Policy rejected command execution (no-more-sessions failed)."}), nil
				}
			}
			return true, nil, nil
		}
	}
	return true, nil, nil
}

func (pc *Policy) FilterClientPacket(packet []byte) (allowed bool, response []byte, err error) {
	decoded, err := decode(packet)
	if err != nil {
		return false, nil, err
	}

	switch msg := decoded.(type) {
	case *channelOpenMsg:
		if msg.ChanType != "session" || pc.SessionOpened {
			return false, Marshal(channelOpenFailureMsg{}), nil
		} else {
			pc.SessionOpened = true
		}
		return true, nil, nil
	case *globalRequestMsg:
		if msg.Type != NoMoreSessionRequestName {
			return false, Marshal(globalRequestFailureMsg{}), nil
		} else {
			if debugProxy {
				log.Printf("Client sent no-more-sessions")
			}
			pc.NoMoreSessions = true
			pc.AwaitingNMSReply = true
		}
		return true, nil, nil
	case *channelRequestMsg:
		if msg.Request != "exec" {
			log.Printf("Channel request %s blocked (only 'exec' is allowed)", msg.Request)
			return false, Marshal(channelRequestFailureMsg{}), nil
		}

		var execReq execMsg
		if err := Unmarshal(msg.RequestSpecificData, &execReq); err != nil {
			return false, nil, err
		}
		if execReq.Command != pc.Command {
			log.Printf("Unexpected command: %s, (expecting: %s)", execReq.Command, pc.Command)
			return false, Marshal(channelRequestFailureMsg{}), nil
		}
		return true, nil, nil
	case *kexInitMsg:
		if !pc.NoMoreSessions {
			log.Printf("Requested kexInit without first sending no more sessions.")
			return false, Marshal(disconnectMsg{Reason: 3, Message: "Must request no-more-sessions request before requesting Kex"}), nil
		}
		return true, nil, nil
	default:
		return true, nil, nil
	}
}
