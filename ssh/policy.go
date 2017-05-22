package ssh

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
)

const (
	Inactive = iota
	AwaitingReply
	Success
	Failure
)

type PolicyKey struct {
	User	string
	Server 	string
}

type PolicyScope struct {
	AllCommands bool
	Commands 	[]string
}


type Policy struct {
	User                string
	Command             string
	Server              string
	ApprovedAllCommands bool
	SessionOpened       bool
	NMSStatus			int
}

func (pc *Policy) GetPolicyKey() (PolicyKey) {
	return PolicyKey{User: pc.User, Server: pc.Server}
} 

func NewPolicy(u string, c string, s string) *Policy {
	return &Policy{User: u, Command: c, Server: s,
		SessionOpened: false, NMSStatus: Inactive}
}

func (pc *Policy) AskForApproval(store map[PolicyKey]PolicyScope) error {
	reader := bufio.NewReader(os.Stdin)
	var text string
	// switch to regex
	for text != "y" && text != "n" && text != "a" {
		// if with wrapper, approval can be done only for session?
		fmt.Printf("Approve running '%s'/all commands once on %s@%s? [y/n/a]:",
			pc.Command, pc.User, pc.Server)
		text, _ = reader.ReadString('\n')
		text = strings.ToLower(strings.Trim(text, " \r\n"))
	}

	var err error
	if text == "n" {
		err = errors.New("Policy rejected client request")
	}
	if text == "a" {
		pc.ApprovedAllCommands = true
		scope := store[pc.GetPolicyKey()]
		scope.AllCommands = true
		store[pc.GetPolicyKey()] = scope
		return err
	}
	return err
}

func (pc *Policy) EscalateApproval() error {
	reader := bufio.NewReader(os.Stdin)
	var text string
	// switch to regex
	for text != "y" && text != "n" {
		fmt.Printf(`Allow handoff of connection %s@%s? This will enable the client to potentially run any other command on this server. [y/n]:`, pc.User, pc.Server)
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
	if pc.NMSStatus != AwaitingReply {
		return true, nil, nil
	}

	switch packet[0] {
	case msgRequestSuccess:
		if debugProxy {
			log.Printf("Server approved no-more-sessions.")
		}
		pc.NMSStatus = Success
	case msgRequestFailure:
		if debugProxy {
			log.Printf("Server sent no-more-sessions failure.")
		}
		pc.NMSStatus = Failure
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
			pc.NMSStatus = AwaitingReply
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
		if pc.NMSStatus != Success && !pc.ApprovedAllCommands {
			log.Printf("Requested kexInit without first sending no more sessions.")
			if pc.EscalateApproval() != nil {
				return false, Marshal(disconnectMsg{Reason: 2, Message: "Must issue no-more-sessions before handoff"}), nil
			}
		}
		return true, nil, nil
	default:
		return true, nil, nil
	}
}
