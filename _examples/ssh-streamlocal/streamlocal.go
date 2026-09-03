package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/engity-com/ssh-server-go"
	gossh "golang.org/x/crypto/ssh"
)

const (
	listenAddress     = "127.0.0.1:2222"
	directSocketPath  = "/tmp/ssh-server-go-direct.sock"
	reverseSocketPath = "/tmp/ssh-server-go-reverse.sock"
)

func main() {
	forwardHandler := &ssh.ForwardedUnixHandler{}

	server := ssh.Server{
		Addr: listenAddress,
		Handler: func(session ssh.Session) error {
			_, err := fmt.Fprintln(session, "Unix socket forwarding is available")
			return err
		},
		ChannelHandlers: map[string]ssh.ChannelHandler{
			"session":                        ssh.DefaultSessionHandler,
			"direct-streamlocal@openssh.com": ssh.DirectStreamLocalHandler,
		},
		LocalUnixForwardingCallback: func(ctx ssh.Context, conn gossh.ConnMetadata, socketPath string) (net.Conn, error) {
			if socketPath != directSocketPath {
				return nil, ssh.ErrServerPermissionDenied
			}
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", socketPath)
		},
		ReverseUnixForwardingCallback: func(ctx ssh.Context, conn gossh.ConnMetadata, socketPath string) (net.Listener, error) {
			if socketPath != reverseSocketPath {
				return nil, ssh.ErrServerPermissionDenied
			}
			var listenConfig net.ListenConfig
			listener, err := listenConfig.Listen(ctx, "unix", socketPath)
			if err != nil {
				return nil, err
			}
			unlinker, ok := listener.(interface{ SetUnlinkOnClose(bool) })
			if !ok {
				_ = listener.Close()
				return nil, errors.New("unix listener does not support unlink-on-close")
			}
			unlinker.SetUnlinkOnClose(true)
			if err := os.Chmod(socketPath, 0o600); err != nil {
				_ = listener.Close()
				return nil, err
			}
			return listener, nil
		},
		RequestHandlers: map[string]ssh.RequestHandler{
			"streamlocal-forward@openssh.com":        forwardHandler.HandleSSHRequest,
			"cancel-streamlocal-forward@openssh.com": forwardHandler.HandleSSHRequest,
		},
	}

	log.Println("DEVELOPMENT ONLY: anonymous authentication and an ephemeral host key")
	log.Printf("allowing direct Unix forwarding to %q", directSocketPath)
	log.Printf("allowing reverse Unix forwarding on %q", reverseSocketPath)
	log.Printf("starting SSH server on %s", listenAddress)
	log.Fatal(server.ListenAndServe(context.Background()))
}
