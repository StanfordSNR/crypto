package ssh

import (
	"log"
	"net"
)

type side struct {
	conn      net.Conn
	trans     *handshakeTransport
	sessionId []byte
}

type ProxyConn interface {
	Run() (done <-chan error)
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

	return &proxy{
		toClient:   side{toClient, toClientTransport, toClientSessionID},
		toServer:   side{toServer, toServerTransport, toServerSessionID},
		clientConf: clientConfig,
		serverConf: serverConf,
	}, nil
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
			switch packet[0] {
			// TODO: filter packets
			}
			p.toServer.trans.writePacket(packet)
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
			switch packet[0] {
			// TODO: filter packets
			}
			p.toClient.trans.writePacket(packet)
		}
	}()
	return done
}
