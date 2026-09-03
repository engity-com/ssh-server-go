package main

import (
	"context"
	"fmt"
	"log"

	"github.com/engity-com/ssh-server-go"
	gossh "golang.org/x/crypto/ssh"
)

const (
	listenAddress   = "127.0.0.1:2222"
	destinationHost = "127.0.0.1"
	destinationPort = 8080
)

func main() {
	server := ssh.Server{
		Addr: listenAddress,
		Handler: func(session ssh.Session) error {
			_, err := fmt.Fprintln(session, "Local forwarding is available")
			return err
		},
		LocalPortForwardingCallback: func(_ ssh.Context, _ gossh.ConnMetadata, host string, port uint32) (bool, error) {
			allowed := host == destinationHost && port == destinationPort
			log.Printf("forward to %s:%d allowed: %t", host, port, allowed)
			return allowed, nil
		},
		ChannelHandlers: map[string]ssh.ChannelHandler{
			"session":      ssh.DefaultSessionHandler,
			"direct-tcpip": ssh.DirectTCPIPHandler,
		},
	}

	log.Println("DEVELOPMENT ONLY: anonymous authentication and an ephemeral host key")
	log.Printf("starting SSH server on %s; connect with ssh -N -L 8081:%s:%d -p 2222 localhost", listenAddress, destinationHost, destinationPort)
	log.Fatal(server.ListenAndServe(context.Background()))
}
