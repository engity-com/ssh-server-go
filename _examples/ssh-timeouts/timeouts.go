package main

import (
	"context"
	"log"
	"time"

	"github.com/engity-com/ssh-server-go"
)

var (
	DeadlineTimeout = 30 * time.Second
	IdleTimeout     = 10 * time.Second
)

func main() {
	ssh.Handle(func(s ssh.Session) error {
		log.Println("new connection")
		i := 0
		for {
			i += 1
			log.Println("active seconds:", i)
			select {
			case <-time.After(time.Second):
				continue
			case <-s.Context().Done():
				log.Println("connection closed")
				return nil
			}
		}
	})
	server := &ssh.Server{
		Addr:        "127.0.0.1:2222",
		MaxTimeout:  &DeadlineTimeout,
		IdleTimeout: &IdleTimeout,
	}

	log.Println("DEVELOPMENT ONLY: anonymous authentication and an ephemeral host key")
	log.Println("starting ssh server on 127.0.0.1:2222...")
	log.Printf("connections will only last %s and timeout after %s of no activity\n", DeadlineTimeout, IdleTimeout)
	log.Fatal(server.ListenAndServe(context.Background()))
}
