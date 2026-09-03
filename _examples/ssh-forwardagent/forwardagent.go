package main

import (
	"context"
	"fmt"
	"log"
	"os/exec"

	"github.com/engity-com/ssh-server-go"
)

func main() {
	ssh.Handle(func(s ssh.Session) error {
		cmd := exec.Command("ssh-add", "-l")
		if ssh.AgentRequested(s) {
			l, err := ssh.NewAgentListener()
			if err != nil {
				return fmt.Errorf("create agent listener: %w", err)
			}
			defer l.Close()
			go ssh.ForwardAgentConnections(l, nil, s)
			cmd.Env = append(s.Environ(), fmt.Sprintf("%s=%s", "SSH_AUTH_SOCK", l.Addr().String()))
		} else {
			cmd.Env = s.Environ()
		}
		cmd.Stdout = s
		cmd.Stderr = s.Stderr()
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("run ssh-add: %w", err)
		}
		return nil
	})

	server := &ssh.Server{
		Addr: "127.0.0.1:2222",
		AgentForwardingCallback: func(ssh.Context, ssh.Session) (bool, error) {
			return true, nil
		},
	}

	log.Println("DEVELOPMENT ONLY: anonymous authentication, agent forwarding, and an ephemeral host key")
	log.Println("starting ssh server on 127.0.0.1:2222...")
	log.Fatal(server.ListenAndServe(context.Background()))
}
