package ssh

import (
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/dimakogan/ssh/gossh/policy"
)

const (
	Inactive = iota
	AwaitingReply
	Success
	Failure
)

type PromptUserFunc func(txt string) (string, error)

type Filter struct {
	// kept to validate that promised command is made command (may be unecessary since we don't check thereafter if all approved)
	Command             string
	Store 				policy.Store
	Scope 				policy.Scope
	SessionOpened       bool
	NMSStatus           int
	Prompt              PromptUserFunc
}

func NewFilter(givenScope policy.Scope, givenStore policy.Store, givenCommand string, givenPrompt PromptUserFunc) *Filter {
	return &Filter {
		Command:	givenCommand,
	   	Store:	 	givenStore,
		Scope:	 	givenScope,
		Prompt:	 	givenPrompt,
	}
}

func (fil *Filter) IsApproved() error {
    storedRule, ok := fil.Store[fil.Scope]
    if ok && storedRule.IsApproved(fil.Command) {
    	return nil
    }
    return fil.askForApproval()
}

func (fil *Filter) askForApproval() error {
    text := "."
    var err error
    // switch to regex
    for err == nil && text != "y" && text != "n" && text != "a" && text != "" {
        // if with wrapper, approval can be done only for session?
        text, err = fil.Prompt(fmt.Sprintf("Approve %s@%s:%d running '%s' on %s@%s? Approve all future commands? [Y/n/a]:",
            fil.Scope.ClientUsername, fil.Scope.ClientHostname, fil.Scope.ClientPort, fil.Command, fil.Scope.ServiceUsername, fil.Scope.ServiceHostname))
        text = strings.ToLower(strings.Trim(text, " \r\n"))
    }
    fmt.Printf("here: return is %s %s", text, err)

    if err != nil {
        return err
    }
    if text == "n" {
        err = errors.New("Policy rejected client request")
    }
    if text == "a" {
    	err = fil.Store.SetAllAllowedInScope(fil.Scope)
    }
    // add a "y" check if you want to store one time approval.
    return err
}

func (fil *Filter) EscalateApproval() error {
	var text string
	var err error
	// switch to regex
	for err == nil && text != "y" && text != "n" {
		text, err = fil.Prompt(fmt.Sprintf(`Allow  %s@%s:%d full control of %s@%s? [Y/n]:`, fil.Scope.ClientUsername, fil.Scope.ClientHostname, fil.Scope.ClientPort, fil.Scope.ServiceUsername, fil.Scope.ServiceHostname))
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

func (fil *Filter) FilterServerPacket(packet []byte) (validState bool, response []byte, err error) {
	if fil.NMSStatus != AwaitingReply {
		return true, nil, nil
	}

	switch packet[0] {
	case msgRequestSuccess:
		if debugProxy {
			log.Printf("Server approved no-more-sessions.")
		}
		fil.NMSStatus = Success
	case msgRequestFailure:
		if debugProxy {
			log.Printf("Server sent no-more-sessions failure.")
		}
		fil.NMSStatus = Failure
	}
	return true, nil, nil
}

func (fil *Filter) FilterClientPacket(packet []byte) (allowed bool, response []byte, err error) {
	decoded, err := decode(packet)
	if err != nil {
		return false, nil, err
	}

	switch msg := decoded.(type) {
	case *channelOpenMsg:
		if msg.ChanType != "session" || fil.SessionOpened {
			return false, Marshal(channelOpenFailureMsg{}), nil
		} else {
			fil.SessionOpened = true
		}
		return true, nil, nil
	case *globalRequestMsg:
		if msg.Type != NoMoreSessionRequestName {
			return false, Marshal(globalRequestFailureMsg{}), nil
		} else {
			if debugProxy {
				log.Printf("Client sent no-more-sessions")
			}
			fil.NMSStatus = AwaitingReply
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
		if execReq.Command != fil.Command {
			log.Printf("Unexpected command: %s, (expecting: %s)", execReq.Command, fil.Command)
			return false, Marshal(channelRequestFailureMsg{}), nil
		}
		return true, nil, nil
	case *kexInitMsg:
		if fil.NMSStatus != Success && !fil.Store.GetRule(fil.Scope).AllCommands {
			log.Printf("Requested kexInit without first sending no more sessions.")
			if err = fil.EscalateApproval(); err != nil {
				return false, Marshal(disconnectMsg{Reason: 2, Message: "Must issue no-more-sessions before handoff"}), err
			}
		}
		return true, nil, nil
	default:
		return true, nil, nil
	}
}
