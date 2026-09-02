package main

import (
	"context"
	"errors"
	"io"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/engity-com/ssh-server-go"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	server := &ssh.Server{
		Addr:                    "127.0.0.1:2222",
		GracefulShutdownHandler: ssh.NewGracefulShutdownTimeoutHandler(10 * time.Second),
		Handler: func(session ssh.Session) {
			_, _ = io.WriteString(session, "Press Ctrl+C in the server terminal to stop gracefully.\n")
		},
	}

	log.Println("DEVELOPMENT ONLY: anonymous authentication and an ephemeral host key")
	log.Println("starting SSH server on 127.0.0.1:2222; press Ctrl+C to stop")
	if err := server.ListenAndServe(ctx); err != nil &&
		(!errors.Is(err, context.Canceled) || errors.Is(err, ssh.ErrGracefulShutdownTimeout)) {
		log.Fatal(err)
	} else if err != nil {
		log.Printf("server stopped: %v", err)
	}
}
