package main

import (
	"context"
	"fmt"
	"io"
	"log"

	"github.com/engity-com/ssh-server-go"
	gossh "golang.org/x/crypto/ssh"
)

func main() {
	ssh.Handle(func(s ssh.Session) {
		authorizedKey := gossh.MarshalAuthorizedKey(s.PublicKey())
		io.WriteString(s, fmt.Sprintf("public key used by %s:\n", s.User()))
		s.Write(authorizedKey)
	})

	publicKeyOption := ssh.PublicKeyAuth(func(ctx ssh.Context, key ssh.PublicKey) bool {
		return true // allow all keys, or use ssh.KeysEqual() to compare against known keys
	})

	log.Println("DEVELOPMENT ONLY: every public key is accepted and the host key is ephemeral")
	log.Println("starting ssh server on 127.0.0.1:2222...")
	log.Fatal(ssh.ListenAndServe(context.Background(), "127.0.0.1:2222", nil, publicKeyOption))
}
