package main

import (
	"io"
	"log"

	"github.com/engity-com/ssh-server-go"
)

func main() {
	forwardHandler := &ssh.ForwardedTCPHandler{}

	server := ssh.Server{
		Addr: "127.0.0.1:2222",
		Handler: ssh.Handler(func(s ssh.Session) {
			_, _ = io.WriteString(s, "Remote forwarding available...\n")
		}),
		ReversePortForwardingCallback: ssh.ReversePortForwardingCallback(func(ctx ssh.Context, host string, port uint32) bool {
			log.Println("attempt to bind", host, port, "granted")
			return true
		}),
		RequestHandlers: map[string]ssh.RequestHandler{
			"tcpip-forward":        forwardHandler.HandleSSHRequest,
			"cancel-tcpip-forward": forwardHandler.HandleSSHRequest,
		},
	}

	log.Println("DEVELOPMENT ONLY: anonymous authentication and an ephemeral host key")
	log.Println("starting SSH server on 127.0.0.1:2222; connect with ssh -N -R ...")
	log.Fatal(server.ListenAndServe())
}
