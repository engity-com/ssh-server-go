package ssh

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/echocat/slf4g"
	"github.com/echocat/slf4g/fields"
	gossh "golang.org/x/crypto/ssh"
)

type serverConn struct {
	net.Conn

	idleTimeout       time.Duration
	handshakeDeadline time.Time
	maxDeadline       time.Time
	closeCanceler     context.CancelFunc
	deadlineMu        sync.Mutex
}

func (c *serverConn) Write(p []byte) (n int, err error) {
	if c.idleTimeout > 0 {
		c.updateDeadline()
	}
	n, err = c.Conn.Write(p)
	if _, ok := errors.AsType[net.Error](err); ok && c.closeCanceler != nil {
		c.closeCanceler()
	}
	return
}

func (c *serverConn) Read(b []byte) (n int, err error) {
	if c.idleTimeout > 0 {
		c.updateDeadline()
	}
	n, err = c.Conn.Read(b)
	if _, ok := errors.AsType[net.Error](err); ok && c.closeCanceler != nil {
		c.closeCanceler()
	}
	return
}

func (c *serverConn) Close() (err error) {
	err = c.Conn.Close()
	if c.closeCanceler != nil {
		c.closeCanceler()
	}
	return
}

func (c *serverConn) updateDeadline() {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.updateDeadlineLocked()
}

func (c *serverConn) clearHandshakeDeadline() {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.handshakeDeadline = time.Time{}
	c.updateDeadlineLocked()
}

func (c *serverConn) updateDeadlineLocked() {
	deadline := c.maxDeadline

	if !c.handshakeDeadline.IsZero() && (deadline.IsZero() || c.handshakeDeadline.Before(deadline)) {
		deadline = c.handshakeDeadline
	}

	if c.idleTimeout > 0 {
		idleDeadline := time.Now().Add(c.idleTimeout)
		if deadline.IsZero() || idleDeadline.Before(deadline) {
			deadline = idleDeadline
		}
	}

	_ = c.Conn.SetDeadline(deadline)
}

func enrichLoggerForServerConnection(in log.Logger, conn *gossh.ServerConn) log.Logger {
	if conn == nil {
		return in
	}
	return in.
		With("ssh.remote", fields.LazyFunc(func() any {
			return conn.RemoteAddr()
		})).
		With("ssh.local", fields.LazyFunc(func() any {
			return conn.LocalAddr()
		})).
		With("ssh.user", fields.LazyFunc(func() any {
			if v := conn.User(); v != "" {
				return v
			}
			return fields.Exclude
		})).
		With("ssh.sessionId", fields.LazyFunc(func() any {
			if v := conn.SessionID(); len(v) > 0 {
				return base64.URLEncoding.EncodeToString(v)
			}
			return fields.Exclude
		}))
}
