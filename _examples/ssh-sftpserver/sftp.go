package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"

	"github.com/engity-com/ssh-server-go"
	"github.com/pkg/sftp"
)

// SftpHandler handler for SFTP subsystem
func SftpHandler(sess ssh.Session) error {
	debugStream := io.Discard
	serverOptions := []sftp.ServerOption{
		sftp.WithDebug(debugStream),
	}
	server, err := sftp.NewServer(
		sess,
		serverOptions...,
	)
	if err != nil {
		return fmt.Errorf("initialize sftp server: %w", err)
	}
	serveErr := server.Serve()
	closeErr := server.Close()
	if errors.Is(serveErr, io.EOF) {
		serveErr = nil
		fmt.Println("sftp client exited session.")
	}
	return errors.Join(serveErr, closeErr)
}

func main() {
	server := ssh.Server{
		Addr: "127.0.0.1:2222",
		SubsystemHandlers: map[string]ssh.SubsystemHandler{
			"sftp": SftpHandler,
		},
	}
	log.Println("DEVELOPMENT ONLY: anonymous authentication and an ephemeral host key")
	log.Println("starting ssh server on 127.0.0.1:2222...")
	log.Fatal(server.ListenAndServe(context.Background()))
}
