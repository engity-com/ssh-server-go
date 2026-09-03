package main

import (
	"context"
	"fmt"
	"log"

	"github.com/engity-com/ssh-server-go"
)

const listenAddress = "127.0.0.1:2222"

func main() {
	server := &ssh.Server{
		Addr: listenAddress,
		Handler: func(session ssh.Session) error {
			_, err := fmt.Fprintf(session, "Your address is %s\n", session.RemoteAddr())
			return err
		},
		ProxyProtocol: &ssh.ProxyProtocolConfig{},
	}

	log.Println("DEVELOPMENT ONLY: anonymous authentication, an ephemeral host key and trusts the PROXY protocol from everywhere.")
	log.Printf("starting PROXY-aware SSH server on %s", listenAddress)
	log.Fatal(server.ListenAndServe(context.Background()))
}
