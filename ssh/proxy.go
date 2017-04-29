package ssh

import (
	"log"
	"net"
	"reflect"
)

type side struct {
	conn      net.Conn
	trans     *handshakeTransport
	sessionId []byte
}

type ProxyConn interface {
	Run() (done <-chan error)
	UpdateClientSessionParams() error
}

type proxy struct {
	toClient side
	toServer side

	clientConf *ClientConfig
	serverConf ServerConfig
}

func NewProxyConn(toClient net.Conn, toServer net.Conn, clientConfig *ClientConfig) (ProxyConn, error) {
	var err error
	serverVersion, err := readVersion(toServer)
	if err != nil {
		return nil, err
	}
	log.Printf("Read version: \"%s\" from server", serverVersion)

	clientVersion, err := exchangeVersions(toClient, serverVersion)
	if err != nil {
		return nil, err
	}
	log.Printf("Read version: \"%s\" from client", clientVersion)

	// Connect to server
	clientConfig.SetDefaults()
	clientConfig.ClientVersion = string(clientVersion)

	if err = writeVersion(toServer, clientVersion); err != nil {
		return nil, err
	}

	// TODO: replace this with host key verification callback
	dialAddress := "0.0.0.0"

	toServerTransport := newClientTransport(
		newTransport(toServer, clientConfig.Rand, true /* is client */),
		clientVersion, serverVersion, clientConfig, dialAddress, toServer.RemoteAddr())

	if err := toServerTransport.waitSession(); err != nil {
		return nil, err
	}

	toServerSessionID := toServerTransport.getSessionID()

	toServerConn := &connection{transport: toServerTransport}
	toServerConn.clientAuthenticate(clientConfig)

	doneWithKex := make(chan struct{})
	toServerTransport.stopKexHandling(doneWithKex)
	<-doneWithKex

	// Connect to client

	serverConf := ServerConfig{}
	serverConf.SetDefaults()
	serverConf.NoClientAuth = true
	serverConf.ServerVersion = string(serverVersion)
	serverConf.AddHostKey(&NonePrivateKey{})

	toClientTransport := newServerTransport(
		newTransport(toClient, serverConf.Rand, false /* not client */),
		clientVersion, serverVersion, &serverConf)

	if err = toClientTransport.waitSession(); err != nil {
		return nil, err
	}

	toClientSessionID := toClientTransport.getSessionID()
	toClientConn := &connection{transport: toClientTransport}
	_, err = toClientConn.serverAuthenticate(&serverConf)
	if err != nil {
		return nil, err
	}

	doneWithKex = make(chan struct{})
	log.Printf("stopping  Kex")
	toClientTransport.stopKexHandling(doneWithKex)
	<-doneWithKex
	log.Printf("Done with Kex")

	return &proxy{
		toClient:   side{toClient, toClientTransport, toClientSessionID},
		toServer:   side{toServer, toServerTransport, toServerSessionID},
		clientConf: clientConfig,
		serverConf: serverConf,
	}, nil
}

func (p *proxy) UpdateClientSessionParams() error {
	log.Printf("UpdateClientSessionParams begin")
	sessionID := p.toServer.trans.getSessionID()
	p2s, s2p := p.toServer.trans.getSequenceNumbers()

	err := p.toClient.trans.updateSessionParams(sessionID, s2p, p2s)

	if err != nil {
		log.Printf("Failed to send updateClientSessionParams")
		return err
	}

	return nil
}

func (p *proxy) Run() <-chan error {
	done := make(chan error, 1)
	go func() {
		// From client to server forwarding
		for {
			packet, err := p.toClient.trans.readPacket()
			if err != nil {
				done <- err
				return
			}
			msg, err := decode(packet)
			switch packet[0] {
			case msgNewKeys:
				log.Printf("Got msgNewKeys")
			default:
				// TODO: filter packets
			}
			err = p.toServer.trans.writePacket(packet)
			if err != nil {
				done <- err
				return
			}
			_, in := p.toClient.trans.getSequenceNumbers()
			out, _ := p.toServer.trans.getSequenceNumbers()
			log.Printf("Got message from client: %s, seqNum: %d, forwarded as: %d", reflect.TypeOf(msg), in-1, out-1)
		}
	}()

	go func() {
		for {
			// From server to client forwarding
			packet, err := p.toServer.trans.readPacket()
			if err != nil {
				done <- err
				return
			}

			msg, err := decode(packet)
			switch packet[0] {
			case msgNewKeys:
				log.Printf("Got msgNewKeys")
			default:
				// TODO: filter packets
			}
			err = p.toClient.trans.writePacket(packet)
			if err != nil {
				done <- err
				return
			}
			out, _ := p.toClient.trans.getSequenceNumbers()
			_, in := p.toServer.trans.getSequenceNumbers()
			log.Printf("Got message from server: %s, seqNum: %d, forwarded as: %d", reflect.TypeOf(msg), in-1, out-1)
		}
	}()
	return done
}
