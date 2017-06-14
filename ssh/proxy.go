package ssh

import (
	"log"
	"net"
	"reflect"
)

const debugProxy = false

type side struct {
	conn      net.Conn
	trans     *handshakeTransport
	sessionId []byte
}

type ProxyConn interface {
	Run() (done <-chan error)
	UpdateClientSessionParams() error
	BufferedFromServer() int
}

type proxy struct {
	toClient side
	toServer side

	clientConf *ClientConfig
	serverConf ServerConfig

	filterClientCB MessageFilterCallback
	filterServerCB MessageFilterCallback
}

type MessageFilterCallback func(p []byte) (isOK bool, response []byte, err error)

func NewProxyConn(dialAddress string, toClient net.Conn, toServer net.Conn, clientConfig *ClientConfig, filterCCB MessageFilterCallback, filterSCB MessageFilterCallback) (ProxyConn, error) {
	var err error

	serverVersion, err := readVersion(toServer)
	if err != nil {
		return nil, err
	}
	if debugProxy {
		log.Printf("Read version: \"%s\" from server", serverVersion)
	}

	clientVersion, err := exchangeVersions(toClient, serverVersion)
	if err != nil {
		return nil, err
	}
	if debugProxy {
		log.Printf("Read version: \"%s\" from client", clientVersion)
	}

	// Connect to server
	clientConfig.SetDefaults()
	clientConfig.ClientVersion = string(clientVersion)

	if err = writeVersion(toServer, clientVersion); err != nil {
		return nil, err
	}

	toServerTransport := newClientTransport(
		newTransport(toServer, clientConfig.Rand, true /* is client */),
		clientVersion, serverVersion, clientConfig, dialAddress, toServer.RemoteAddr())

	// Connect to client
	serverConf := ServerConfig{}
	serverConf.SetDefaults()
	serverConf.ServerVersion = string(serverVersion)
	serverConf.AddHostKey(&NonePrivateKey{})

	toClientTransport := newServerTransport(
		newTransport(toClient, serverConf.Rand, false /* not client */),
		clientVersion, serverVersion, &serverConf)

	// Establish sessions
	if err := toServerTransport.waitSession(); err != nil {
		toClientTransport.writePacket(Marshal(disconnectMsg{Message: err.Error()}))
		return nil, err
	}

	toServerSessionID := toServerTransport.getSessionID()
	if debugProxy {
		log.Printf("Connected to server successfully")
	}
	toServerConn := &connection{transport: toServerTransport}

	if err = toClientTransport.waitSession(); err != nil {
		return nil, err
	}

	toClientSessionID := toClientTransport.getSessionID()
	toClientConn := &connection{transport: toClientTransport}

	// Authentication
	err = toServerConn.clientAuthenticate(clientConfig)
	if err != nil {
		// Simulate authentication failure for client
		serverConf.PublicKeyCallback = func(conn ConnMetadata, key PublicKey) (*Permissions, error) {
			return nil, err
		}

		toClientConn.serverAuthenticate(&serverConf)
		return nil, err
	}

	serverConf.NoClientAuth = true
	_, err = toClientConn.serverAuthenticate(&serverConf)
	if err != nil {
		return nil, err
	}

	doneWithKex := make(chan struct{})
	toServerTransport.stopKexHandling(doneWithKex)
	<-doneWithKex

	doneWithKex = make(chan struct{})
	if debugProxy {
		log.Printf("Stopping Kex")
	}
	toClientTransport.stopKexHandling(doneWithKex)
	<-doneWithKex
	if debugProxy {
		log.Printf("Done with Kex")
	}

	return &proxy{
		toClient:       side{toClient, toClientTransport, toClientSessionID},
		toServer:       side{toServer, toServerTransport, toServerSessionID},
		clientConf:     clientConfig,
		serverConf:     serverConf,
		filterClientCB: filterCCB,
		filterServerCB: filterSCB,
	}, nil
}

func (p *proxy) UpdateClientSessionParams() error {
	if debugProxy {
		log.Printf("UpdateClientSessionParams begin")
	}
	sessionID := p.toServer.trans.getSessionID()
	p2s, s2p := p.toServer.trans.getSequenceNumbers()

	err := p.toClient.trans.updateSessionParams(sessionID, s2p, p2s)

	if err != nil {
		log.Printf("Failed to send updateClientSessionParams")
		return err
	}
	if debugProxy {
		log.Printf("UpdateClientSessionParams Complete")
	}

	return nil
}

// don't allow key exchange before channel has been opened -- no more sessions
func (p *proxy) Run() <-chan error {
	forwardingDone := make(chan error, 2)
	var err error
	go func() {
		// From client to server forwarding
		for {
			packet, err := p.toClient.trans.readPacket()
			if err != nil {
				forwardingDone <- err
				return
			}

			msgNum := packet[0]
			msg, err := decode(packet)
			if debugProxy {
				log.Printf("Got message %d from client: %s", msgNum, reflect.TypeOf(msg))
			}

			allowed, response, err := p.filterClientCB(packet)
			if err != nil {
				log.Printf("Got error from client packet filter: %s", err)
				p.toClient.trans.writePacket(response)
				p.toServer.trans.Close()
				break
			}
			if !allowed {
				log.Printf("Packet from client to server blocked")
				if err = p.toClient.trans.writePacket(response); err != nil {
					break
				}
				// Send a msgIgnore instead to keep sequence numbers aligned
				p.toServer.trans.writePacket([]byte{msgIgnore})
			}
			// Packet allowed message, forwarding it.
			err = p.toServer.trans.writePacket(packet)
			if err != nil {
				break
			}
			_, in := p.toClient.trans.getSequenceNumbers()
			out, _ := p.toServer.trans.getSequenceNumbers()
			if debugProxy {
				log.Printf("Forwarded seqNum: %d from client to server as: %d", in-1, out-1)
			}
			if msgNum == msgNewKeys {
				if debugProxy {
					log.Printf("Got msgNewKeys from client, finishing client->server forwarding")
				}
				break
			}

		}
		forwardingDone <- err
	}()

	go func() {
		for {
			// From server to client forwarding
			packet, err := p.toServer.trans.readPacket()
			if err != nil {
				break
			}

			msgNum := packet[0]
			msg, err := decode(packet)

			if debugProxy {
				log.Printf("Got message %d from server: %s", packet[0], reflect.TypeOf(msg))
			}

			validState, response, err := p.filterServerCB(packet)
			if err != nil {
				log.Printf("Got error from server packet filter: %s", err)
				p.toClient.trans.writePacket(response)
				break
			}
			if !validState {
				log.Printf("Packet from server to client ends connection")
				if err = p.toClient.trans.writePacket(response); err != nil {
					break
				}
				// No need to send a msgIgnore for seq # since server->client msg was blocked
			}

			err = p.toClient.trans.writePacket(packet)
			if err != nil {
				break
			}
			out, _ := p.toClient.trans.getSequenceNumbers()
			_, in := p.toServer.trans.getSequenceNumbers()
			if debugProxy {
				log.Printf("Forwarded seqNum: %d from server to client as: %d", in-1, out-1)
			}
			if msgNum == msgNewKeys {
				if debugProxy {
					log.Printf("Got msgNewKeys from server, finishing server->client forwarding")
				}
				break
			}
		}
		forwardingDone <- err
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
	return p.toServer.trans.buffered()
}
