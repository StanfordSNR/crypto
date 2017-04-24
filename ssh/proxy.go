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

type ProxyConn interface{}

type proxy struct {
	toClient side
	toServer side
}

func NewProxyConn(toClient net.Conn, toServer net.Conn) (ProxyConn, error) {
	var err error
	serverVersion, err := readVersion(toServer)
	if err != nil {
		return nil, err
	}
	log.Printf("Read version: \"%s\" from server", serverVersion)

	// Connect to client

	serverConf := ServerConfig{}
	serverConf.SetDefaults()
	serverConf.NoClientAuth = true
	serverConf.ServerVersion = string(serverVersion)
	serverConf.AddHostKey(&NonePrivateKey{})

	clientVersion, err := exchangeVersions(toClient, serverVersion)
	if err != nil {
		return nil, err
	}
	log.Printf("Read version: \"%s\" from client", clientVersion)

	toClientTransport := newServerTransport(
		newTransport(toClient, serverConf.Rand, false /* not client */),
		clientVersion, serverVersion, &serverConf)

	if err = toClientTransport.waitSession(); err != nil {
		return nil, err
	}

	toClientSessionID := toClientTransport.getSessionID()

	// Connect to server

	clientConf := &ClientConfig{}
	clientConf.SetDefaults()
	clientConf.ClientVersion = string(clientVersion)
	clientConf.HostKeyCallback = InsecureIgnoreHostKey()

	if err = writeVersion(toServer, clientVersion); err != nil {
		return nil, err
	}

	// TODO: replace this with host key verification callback
	dialAddress := "0.0.0.0"

	toServerTransport := newClientTransport(
		newTransport(toServer, clientConf.Rand, true /* is client */),
		clientVersion, serverVersion, clientConf, dialAddress, toServer.RemoteAddr())

	if err := toServerTransport.waitSession(); err != nil {
		return nil, err
	}

	toServerSessionID := toServerTransport.getSessionID()

	return &proxy{
		side{toClient, toClientTransport, toClientSessionID},
		side{toServer, toServerTransport, toServerSessionID}}, nil
}
