package main

import (
	"context"
	"fmt"
	"io"
	"log"

	"github.com/engity-com/ssh-server-go"
)

func main() {
	ssh.Handle(func(s ssh.Session) {
		io.WriteString(s, fmt.Sprintf("Hello %s\n", s.User()))
	})

	log.Println("DEVELOPMENT ONLY: anonymous authentication and an ephemeral host key")
	log.Println("starting ssh server on 127.0.0.1:2222...")
	log.Fatal(ssh.ListenAndServe(context.Background(), "127.0.0.1:2222", nil))
}
