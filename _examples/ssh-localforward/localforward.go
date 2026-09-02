package main

import (
	"io"
	"log"

	"github.com/engity-com/ssh-server-go"
)

const (
	listenAddress   = "127.0.0.1:2222"
	destinationHost = "127.0.0.1"
	destinationPort = 8080
)

func main() {
	server := ssh.Server{
		Addr: listenAddress,
		Handler: func(session ssh.Session) {
			_, _ = io.WriteString(session, "Local forwarding is available\n")
		},
		LocalPortForwardingCallback: func(_ ssh.Context, host string, port uint32) bool {
			allowed := host == destinationHost && port == destinationPort
			log.Printf("forward to %s:%d allowed: %t", host, port, allowed)
			return allowed
		},
		ChannelHandlers: map[string]ssh.ChannelHandler{
			"session":      ssh.DefaultSessionHandler,
			"direct-tcpip": ssh.DirectTCPIPHandler,
		},
	}

	log.Println("DEVELOPMENT ONLY: anonymous authentication and an ephemeral host key")
	log.Printf("starting SSH server on %s; connect with ssh -N -L 8081:%s:%d -p 2222 localhost", listenAddress, destinationHost, destinationPort)
	log.Fatal(server.ListenAndServe())
}
