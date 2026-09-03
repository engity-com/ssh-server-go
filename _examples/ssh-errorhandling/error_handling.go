package main

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/engity-com/ssh-server-go"
)

var (
	errFatal   = errors.New("fatal example failure")
	errIgnored = errors.New("ignored example failure")
)

func main() {
	server := &ssh.Server{
		Addr: "127.0.0.1:2222",
		Handler: func(session ssh.Session) error {
			switch session.RawCommand() {
			case "fail":
				return errors.New("example command failed")
			case "fatal":
				return errFatal
			case "ignore":
				return errIgnored
			}
			_, err := fmt.Fprintf(session, "Hello %s\n", session.User())
			return err
		},
		ErrorHandler: func(
			ctx context.Context,
			scope ssh.ErrorScope,
			operation ssh.ErrorOperation,
			err error,
			respond ssh.ErrorResponder,
			next ssh.ErrorHandler,
		) (bool, error) {
			if errors.Is(err, errIgnored) {
				log.Printf("ignoring session error: %v", err)
				return true, nil
			}
			if errors.Is(err, errFatal) {
				return false, respond([]byte("The connection must be closed.\n"), true)
			}
			if scope == ssh.ErrorScopeSession && operation == ssh.ErrorOperationHandle {
				log.Printf("session failed: %v", err)
				if responseErr := respond([]byte("The command could not be completed.\n"), false); responseErr != nil {
					return false, fmt.Errorf("report session error: %w", responseErr)
				}
				return false, nil
			}

			return next(ctx, scope, operation, fmt.Errorf("example server: %w", err), respond, next)
		},
	}

	log.Println("DEVELOPMENT ONLY: anonymous authentication and an ephemeral host key")
	log.Println("try: ssh -p 2222 127.0.0.1 fail (or use fatal/ignore)")
	log.Fatal(server.ListenAndServe(context.Background()))
}
