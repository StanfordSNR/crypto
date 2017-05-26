package ssh

import (
	"errors"
	"fmt"
	"log"
	"strings"

	"golang.org/x/crypto/sha3"
)

const (
	Inactive = iota
	AwaitingReply
	Success
	Failure
)

type PromptUserFunc func(txt string) (string, error)

type Policy struct {
	ClientHostname string
	ClientPort     uint32
	ClientUsername string

	User                string
	Command             string
	Server              string
	ApprovedAllCommands bool
	SessionOpened       bool
	NMSStatus           int
	Prompt              PromptUserFunc
}

func (pc *Policy) GetPolicyID() (hash [32]byte) {
	return sha3.Sum256([]byte(pc.User + "||" + pc.Server))
}

type policyID func(pc *Policy) [32]byte

func (pc *Policy) AskForApproval(store map[[32]byte]bool) error {
	text := "."
	var err error
	// switch to regex
	for err == nil && text != "y" && text != "n" && text != "a" && text != "" {
		// if with wrapper, approval can be done only for session?
		text, err = pc.Prompt(fmt.Sprintf("Approve %s@%s:%d running '%s' on %s@%s? Approve all future commands? [Y/n/a]:",
			pc.ClientUsername, pc.ClientHostname, pc.ClientPort, pc.Command, pc.User, pc.Server))
		text = strings.ToLower(strings.Trim(text, " \r\n"))

	}

	if err != nil {
		return err
	}
	if text == "n" {
		err = errors.New("Policy rejected client request")
	}
	if text == "a" || text == "" {
		pc.ApprovedAllCommands = true
		// To be changed to include client if we move to one agent total vs one agent per conn
		// similarly, if we remember single commands
		store[pc.GetPolicyID()] = true
		return err
	}
	return err
}

func (pc *Policy) EscalateApproval() error {
	var text string
	var err error
	// switch to regex
	for err != nil && text != "y" && text != "n" {
		text, err = pc.Prompt(fmt.Sprintf(`Allow  %s@%s:%d full control of %s@%s? [Y/n]:`, pc.ClientUsername, pc.ClientHostname, pc.ClientPort, pc.User, pc.Server))
		text = strings.ToLower(strings.Trim(text, " \r\n"))
	}
	if err != nil {
		return err
	}
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
			if err = pc.EscalateApproval(); err != nil {
				return false, Marshal(disconnectMsg{Reason: 2, Message: "Must issue no-more-sessions before handoff"}), err
			}
		}
		return true, nil, nil
	default:
		return true, nil, nil
	}
}
