package ssh

import (
	"errors"
	"fmt"
	"log"

	"github.com/dimakogan/ssh/gossh/common"
	"github.com/dimakogan/ssh/gossh/policy"
)

const (
	Inactive = iota
	AwaitingReply
	Success
	Failure
)

type Filter struct {
	// kept to validate that promised command is made command (may be unecessary since we don't check thereafter if all approved)
	Command       string
	Store         policy.Store
	Scope         policy.Scope
	SessionOpened bool
	NMSStatus     int
	Prompt        common.PromptUserFunc
}

func NewFilter(givenScope policy.Scope, givenStore policy.Store, givenCommand string, givenPrompt common.PromptUserFunc) *Filter {
	return &Filter{
		Command: givenCommand,
		Store:   givenStore,
		Scope:   givenScope,
		Prompt:  givenPrompt,
	}
}

func (fil *Filter) IsApproved() error {
	storedRule := fil.Store.GetRule(fil.Scope)
	if storedRule.IsApproved(fil.Command) {
		return nil
	}
	return fil.askForApproval()
}

func (fil *Filter) askForApproval() error {

	prompt := fmt.Sprintf("Allow %s@%s:%d to run '%s' on %s@%s?",
		fil.Scope.ClientUsername, fil.Scope.ClientHostname,
		fil.Scope.ClientPort, fil.Command, fil.Scope.ServiceUsername,
		fil.Scope.ServiceHostname)

	args := common.Prompt{
		Question: prompt,
		Choices: []string{
			"Disallow", "Allow once", "Allow forever",
			fmt.Sprintf("Allow %s@%s:%d to run any command on %s@%s forever",
				fil.Scope.ClientUsername, fil.Scope.ClientHostname,
				fil.Scope.ClientPort, fil.Scope.ServiceUsername,
				fil.Scope.ServiceHostname),
		},
	}
	resp, err := fil.Prompt(args)

	switch resp {
	case 1:
		err = errors.New("User rejected client request")
	case 2:
		err = nil
	case 3:
		err = fil.Store.SetCommandAllowedInScope(fil.Scope, fil.Command)
	case 4:
		err = fil.Store.SetAllAllowedInScope(fil.Scope)
	}

	return err
}

func (fil *Filter) EscalateApproval() error {

	prompt := fmt.Sprintf("Can't enforce permission for a single command. Allow %s@%s:%d to run any command on %s@%s?",
		fil.Scope.ClientUsername, fil.Scope.ClientHostname,
		fil.Scope.ClientPort, fil.Scope.ServiceUsername,
		fil.Scope.ServiceHostname)

	args := common.Prompt{
		Question: prompt,
		Choices:  []string{"Disallow", "Allow for session", "Allow forever"},
	}
	resp, err := fil.Prompt(args)

	switch resp {
	case 1:
		err = errors.New("Policy rejected approval escalation")
	case 2:
		err = nil
	case 3:
		err = fil.Store.SetAllAllowedInScope(fil.Scope)
	}

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
		}
		fil.SessionOpened = true
		return true, nil, nil
	case *globalRequestMsg:
		if msg.Type != NoMoreSessionRequestName {
			return false, Marshal(globalRequestFailureMsg{}), nil
		}
		if debugProxy {
			log.Printf("Client sent no-more-sessions")
		}
		fil.NMSStatus = AwaitingReply
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
			log.Printf("Attempting handoff without successful no-more-sessions.")
			if err = fil.EscalateApproval(); err != nil {
				return false, Marshal(disconnectMsg{Reason: 2, Message: "Must issue no-more-sessions before handoff"}), err
			}
		}
		return true, nil, nil
	default:
		return true, nil, nil
	}
}
