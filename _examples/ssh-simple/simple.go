package main

import (
	"context"
	"fmt"
	"log"

	"github.com/engity-com/ssh-server-go"
)

func main() {
	ssh.Handle(func(s ssh.Session) error {
		_, err := fmt.Fprintf(s, "Hello %s\n", s.User())
		return err
	})

	log.Println("DEVELOPMENT ONLY: anonymous authentication and an ephemeral host key")
	log.Println("starting ssh server on 127.0.0.1:2222...")
	log.Fatal(ssh.ListenAndServe(context.Background(), "127.0.0.1:2222", nil))
}
