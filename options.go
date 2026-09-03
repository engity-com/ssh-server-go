package ssh

import (
	"context"
	"errors"
	"os"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

// NewGracefulShutdownTimeoutHandler returns a graceful shutdown handler that
// always uses timeout.
func NewGracefulShutdownTimeoutHandler(timeout time.Duration) GracefulShutdownHandler {
	return func(context.Context) (time.Duration, error) {
		return timeout, nil
	}
}

// WithGracefulShutdownHandler returns a functional option that sets the
// graceful shutdown handler on the server.
func WithGracefulShutdownHandler(handler GracefulShutdownHandler) Option {
	return func(srv *Server) error {
		srv.GracefulShutdownHandler = handler
		return nil
	}
}

// WithGracefulShutdownTimeout returns a functional option that configures a
// fixed graceful shutdown timeout on the server.
func WithGracefulShutdownTimeout(timeout time.Duration) Option {
	return WithGracefulShutdownHandler(NewGracefulShutdownTimeoutHandler(timeout))
}

// WithErrorHandler returns a functional option that sets the central handler
// for operational server and handler errors.
func WithErrorHandler(handler ErrorHandler) Option {
	return func(srv *Server) error {
		srv.ErrorHandler = handler
		return nil
	}
}

// PasswordAuth returns a functional option that sets PasswordHandler on the server.
func PasswordAuth(fn PasswordHandler) Option {
	return func(srv *Server) error {
		srv.PasswordHandler = fn
		return nil
	}
}

// PublicKeyAuth returns a functional option that sets PublicKeyHandler on the server.
func PublicKeyAuth(fn PublicKeyHandler) Option {
	return func(srv *Server) error {
		srv.PublicKeyHandler = fn
		return nil
	}
}

// HostKeyFile returns a functional option that adds HostSigners to the server
// from a PEM file at filepath.
func HostKeyFile(filepath string) Option {
	return func(srv *Server) error {
		pemBytes, err := os.ReadFile(filepath) // #nosec G304 -- callers intentionally choose the host-key path
		if err != nil {
			return err
		}

		signer, err := gossh.ParsePrivateKey(pemBytes)
		if err != nil {
			return err
		}

		srv.AddHostKey(signer)

		return nil
	}
}

func KeyboardInteractiveAuth(fn KeyboardInteractiveHandler) Option {
	return func(srv *Server) error {
		srv.KeyboardInteractiveHandler = fn
		return nil
	}
}

// HostKeyPEM returns a functional option that adds HostSigners to the server
// from a PEM file as bytes.
func HostKeyPEM(bytes []byte) Option {
	return func(srv *Server) error {
		signer, err := gossh.ParsePrivateKey(bytes)
		if err != nil {
			return err
		}

		srv.AddHostKey(signer)

		return nil
	}
}

// NoPty returns a functional option that sets PtyCallback to return false,
// denying PTY requests.
func NoPty() Option {
	return func(srv *Server) error {
		srv.PtyCallback = func(Context, Session, Pty) (bool, error) {
			return false, nil
		}
		return nil
	}
}

// WrapConn returns a functional option that sets ConnCallback on the server.
func WrapConn(fn ConnCallback) Option {
	return func(srv *Server) error {
		srv.ConnCallback = fn
		return nil
	}
}

// EnableProxyProtocol returns a functional option that enables PROXY protocol
// processing. With no configuration, every connection must supply a PROXY
// header and the header is trusted from any peer. At most one configuration
// may be supplied.
func EnableProxyProtocol(config ...ProxyProtocolConfig) Option {
	return func(srv *Server) error {
		if len(config) > 1 {
			return errors.New("ssh: enable proxy protocol accepts at most one configuration")
		}
		configured := ProxyProtocolConfig{}
		if len(config) == 1 {
			configured = config[0]
		}
		srv.ProxyProtocol = &configured
		return nil
	}
}
