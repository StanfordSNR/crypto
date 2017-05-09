package ssh

import (
	"crypto/rand"
	"log"
	"net"
	"reflect"

	"github.com/dimakogan/ssh/gossh/common"
)

type ProxyConn interface {
	Run() (done <-chan error)
	GetSessionParams() common.ExecutionApprovedMessage
	BufferedFromServer() int
}

type proxy struct {
	toServer          net.Conn
	toServerTransport *handshakeTransport
	toServerConn      Conn

	toClientTransport *transport

	clientConf *ClientConfig
}

type MessageFilterCallback func(p []byte) (isOK bool, response []byte, err error)

func NewProxyConn(dialAddress string, toServer net.Conn, toClient net.Conn, clientConfig *ClientConfig) (ProxyConn, error) {
	var err error
	log.Printf("NewProxyCOnn")
	// Connect to server
	clientConfig.SetDefaults()

	serverVersion, err := exchangeVersions(toServer, []byte(clientConfig.ClientVersion))
	if err != nil {
		log.Printf("exchangeVersions failed")
		return nil, err
	}
	log.Printf("Got server version: %s", serverVersion)

	toServerTransport := newClientTransport(
		newTransport(toServer, clientConfig.Rand, true /* is client */),
		[]byte(clientConfig.ClientVersion), serverVersion, clientConfig, dialAddress, toServer.RemoteAddr(), nil)

	if err := toServerTransport.waitSession(); err != nil {
		log.Printf("wait session failed: %s", err)
		return nil, err
	}

	toServerSessionID := toServerTransport.getSessionID()

	toServerConn := &connection{
		transport: toServerTransport,
		sshConn: sshConn{
			conn:          toServer,
			serverVersion: serverVersion,
			sessionID:     toServerSessionID,
			clientVersion: []byte(clientConfig.ClientVersion),
		},
	}
	err = toServerConn.clientAuthenticate(clientConfig)
	if err != nil {
		log.Printf("Failed to authenticate with server ")
		return nil, err
	}
	log.Printf("Authenticated with server ")

	doneWithKex := make(chan struct{})
	toServerTransport.stopKexHandling(doneWithKex)
	<-doneWithKex

	toClientTransport := newTransport(toClient, rand.Reader, false)
	p2s, s2p := toServerTransport.getSequenceNumbers()
	toClientTransport.setIncomingSequenceNumber(p2s)
	toClientTransport.setOutgoingSequenceNumber(s2p)

	return &proxy{
		toServer:          toServer,
		toServerTransport: toServerTransport,
		toServerConn:      toServerConn,
		clientConf:        clientConfig,
		toClientTransport: toClientTransport,
	}, nil
}

func (p *proxy) GetSessionParams() common.ExecutionApprovedMessage {
	log.Printf("GetSessionParams begin")
	c2p, p2c := p.toClientTransport.getSequenceNumbers()
	return common.ExecutionApprovedMessage{
		InSeqNum:      p2c,
		OutSeqNum:     c2p,
		ServerVersion: p.toServerConn.ServerVersion(),
		SessionID:     p.toServerTransport.getSessionID(),
	}
}

// don't allow key exchange before channel has been opened -- no more sessions

func (p *proxy) Run() <-chan error {
	forwardingDone := make(chan error, 2)
	var err error

	go func() {
		// From client to server forwarding
		for {
			packet, err := p.toClientTransport.readPacket()
			if err != nil {
				forwardingDone <- err
				return
			}

			msgNum := packet[0]
			msg, err := decode(packet)
			log.Printf("Got message %d from client: %s", msgNum, reflect.TypeOf(msg))

			// Packet allowed message, forwarding it.
			err = p.toServerTransport.writePacket(packet)
			if err != nil {
				break
			}
			// _, in := p.toClient.trans.getSequenceNumbers()
			// out, _ := p.toServer.trans.getSequenceNumbers()
			//log.Printf("Forwarded seqNum: %d from client to server as: %d", in-1, out-1)

			if msgNum == msgNewKeys {
				log.Printf("Got msgNewKeys from client, finishing client->server forwarding")
				break
			}

		}
		forwardingDone <- err
	}()

	go func() {
		for {
			// From server to client forwarding
			packet, err := p.toServerTransport.readPacket()
			if err != nil {
				forwardingDone <- err
				break
			}

			msgNum := packet[0]
			msg, err := decode(packet)
			log.Printf("Got message %d from server: %s", packet[0], reflect.TypeOf(msg))

			err = p.toClientTransport.writePacket(packet)
			if err != nil {
				forwardingDone <- err
				break
			}
			// out, _ := p.toClient.trans.getSequenceNumbers()
			// _, in := p.toServer.trans.getSequenceNumbers()
			// log.Printf("Forwarded seqNum: %d from server to client as: %d", in-1, out-1)
			if msgNum == msgNewKeys {
				log.Printf("Got msgNewKeys from server, finishing server->client forwarding")
				forwardingDone <- nil
				break
			}
		}
	}()
	done := make(chan error)
	go func() {
		if err := <-forwardingDone; err != nil {
			done <- err
			return
		}
		if err := <-forwardingDone; err != nil {
			done <- err
			return
		}
		done <- nil
	}()
	return done
}

func (p *proxy) BufferedFromServer() int {
	return p.toServerTransport.buffered()
}
