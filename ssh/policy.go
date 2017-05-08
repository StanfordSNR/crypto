package ssh

import (
	"bufio"
	"errors"
	"log"
	"os"
	"strings"
)

type Policy struct {
	User    string
	Command string
	Server  string
}

func NewPolicy(u string, c string, s string) *Policy {
	return &Policy{User: u, Command: c, Server: s}
}

func (pc *Policy) AskForApproval() error {
	reader := bufio.NewReader(os.Stdin)
	var text string
	// switch to regex
	for text != "y" && text != "n" {
		log.Printf("\nApprove '%s' on %s by %s? [y/n]:\n", pc.Command, pc.Server, pc.User)
		text, _ = reader.ReadString('\n')
		text = strings.ToLower(strings.Trim(text, " \r\n"))
	}

	var err error
	if text == "n" {
		err = errors.New("Policy rejected client request")
	}
	return err
}

func (pc *Policy) FilterPacket(packet []byte) (allowed bool, err error) {
	decoded, err := decode(packet)
	if err != nil {
		return false, err
	}

	switch msg := decoded.(type) {
	case *channelRequestMsg:
		if msg.Request != "exec" {
			log.Print("Got channel request for: %s instead of 'exec'", msg.Request)
			return false, nil
		}

		var execReq execMsg
		if err := Unmarshal(msg.RequestSpecificData, &execReq); err != nil {
			return false, err
		}
		if execReq.Command != pc.Command {
			log.Printf("Unexpected command: %s, (expecting: %s)", execReq.Command, pc.Command)
			return false, nil
		}
		log.Printf("Succesfully validated channelRequest for: %s", execReq.Command)
		return true, nil
	}
	return true, nil
}
