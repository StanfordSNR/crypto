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

	conn := &connection{transport: toServerTransport}
	conn.clientAuthenticate(clientConfig)

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

	return &proxy{
		side{toClient, toClientTransport, toClientSessionID},
		side{toServer, toServerTransport, toServerSessionID}}, nil
}

func (p *proxy) Run() <-chan error {
	done := make(chan error, 1)
	go func() {
		for {
			packet, err := p.toClient.trans.readPacket()
			if err != nil {
				done <- err
			}
			p.toServer.trans.writePacket(packet)
		}
	}()

	go func() {
		for {
			packet, err := p.toServer.trans.readPacket()
			if err != nil {
				done <- err
			}
			p.toClient.trans.writePacket(packet)
		}
	}()
	return done
}
