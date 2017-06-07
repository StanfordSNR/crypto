package ssh

import (
	"errors"
	"fmt"
	"log"
	"github.com/dimakogan/ssh/gossh/policy"
	i "github.com/sternhenri/interact"
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
    var resp int64
    var err error

	i.Run(&i.Interact{
		Questions: []*i.Question{
			{
				Quest: i.Quest{
                    Msg: fmt.Sprintf("Allow %s@%s:%d to run '%s' on %s@%s?", 
                    	fil.Scope.ClientUsername, fil.Scope.ClientHostname, 
                    	fil.Scope.ClientPort, fil.Command, fil.Scope.ServiceUsername, 
                    	fil.Scope.ServiceHostname),
                    Choices: i.Choices{
                        Alternatives: []i.Choice{
                            {
                                Text: "Disallow",
                            },
                            {
                                Text: "Allow once",
                            },
                            {
                                Text: "Allow forever",
                            },
                            {
                       		 	Text: fmt.Sprintf("Allow %s@%s:%d to run any command on %s@%s forever",
                       		 		fil.Scope.ClientUsername, fil.Scope.ClientHostname,
                       		 		fil.Scope.ClientPort, fil.Scope.ServiceUsername,
                       		 		fil.Scope.ServiceHostname),
                            },
                        },
                    },
                },
                Action: func(c i.Context) interface{} {
                	fmt.Println("1 %s", c)
                	fmt.Println("2 %s", c.Ans())
                	// fmt.Println("3 %s", c.Ans().Int())
                    resp, _ = c.Ans().Int()
                    return nil
                },
			},
		},
	})

	switch resp {
	case 1:
        err = errors.New("Policy rejected client request")
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
	var resp int64
	var err error

	i.Run(&i.Interact{
		Questions: []*i.Question{
			{
				Quest: i.Quest{
                    Msg: fmt.Sprintf("Can't enforce permission for a single command. Allow %s@%s:%d to run any command on %s@%s?", 
                    	fil.Scope.ClientUsername, fil.Scope.ClientHostname, 
                    	fil.Scope.ClientPort, fil.Scope.ServiceUsername, 
                    	fil.Scope.ServiceHostname),
                    Choices: i.Choices{
                        Alternatives: []i.Choice{
                            {
                                Text: "Disallow",
                            },
                            {
                                Text: "Allow for session",
                            },
                            {
                                Text: "Allow forever",
                            },
                        },
                    },
                },
                Action: func(c i.Context) interface{} {
                    resp, _ = c.Ans().Int()
                    return nil
                },
			},
		},
	})

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
