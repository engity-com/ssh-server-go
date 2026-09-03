package main

import (
	"context"
	"fmt"
	"log"

	"github.com/engity-com/ssh-server-go"
	gossh "golang.org/x/crypto/ssh"
)

func main() {
	forwardHandler := &ssh.ForwardedTCPHandler{}

	server := ssh.Server{
		Addr: "127.0.0.1:2222",
		Handler: ssh.Handler(func(s ssh.Session) error {
			_, err := fmt.Fprintln(s, "Remote forwarding available...")
			return err
		}),
		ReversePortForwardingCallback: ssh.ReversePortForwardingCallback(func(ctx ssh.Context, conn gossh.ConnMetadata, host string, port uint32) (bool, error) {
			log.Println("attempt to bind", host, port, "granted")
			return true, nil
		}),
		RequestHandlers: map[string]ssh.RequestHandler{
			"tcpip-forward":        forwardHandler.HandleSSHRequest,
			"cancel-tcpip-forward": forwardHandler.HandleSSHRequest,
		},
	}

	log.Println("DEVELOPMENT ONLY: anonymous authentication and an ephemeral host key")
	log.Println("starting SSH server on 127.0.0.1:2222; connect with ssh -N -R ...")
	log.Fatal(server.ListenAndServe(context.Background()))
}
