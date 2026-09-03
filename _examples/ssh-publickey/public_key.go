package main

import (
	"context"
	"fmt"
	"log"

	"github.com/engity-com/ssh-server-go"
	gossh "golang.org/x/crypto/ssh"
)

func main() {
	ssh.Handle(func(s ssh.Session) error {
		authorizedKey := gossh.MarshalAuthorizedKey(s.PublicKey())
		if _, err := fmt.Fprintf(s, "public key used by %s:\n", s.User()); err != nil {
			return err
		}
		_, err := s.Write(authorizedKey)
		return err
	})

	publicKeyOption := ssh.PublicKeyAuth(func(ctx ssh.Context, conn gossh.ConnMetadata, key ssh.PublicKey) (bool, error) {
		return true, nil // allow all keys, or use ssh.KeysEqual() to compare against known keys
	})

	log.Println("DEVELOPMENT ONLY: every public key is accepted and the host key is ephemeral")
	log.Println("starting ssh server on 127.0.0.1:2222...")
	log.Fatal(ssh.ListenAndServe(context.Background(), "127.0.0.1:2222", nil, publicKeyOption))
}
