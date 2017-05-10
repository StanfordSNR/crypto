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
	User           string
	Command        string
	Server         string
	SessionOpened  bool
	NoMoreSessions bool
}

func NewPolicy(u string, c string, s string) *Policy {
	return &Policy{User: u, Command: c, Server: s, SessionOpened: false, NoMoreSessions: false}
}

func (pc *Policy) AskForApproval() error {
	reader := bufio.NewReader(os.Stdin)
	var text string
	// switch to regex
	for text != "y" && text != "n" {
		fmt.Printf("Approve '%s' on %s by %s? [y/n]: ", pc.Command, pc.Server, pc.User)
		text, _ = reader.ReadString('\n')
		text = strings.ToLower(strings.Trim(text, " \r\n"))
	}

	var err error
	if text == "n" {
		err = errors.New("Policy rejected client request")
	}
	return err
}

func (pc *Policy) FilterPacket(packet []byte) (allowed bool, response []byte, err error) {
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
