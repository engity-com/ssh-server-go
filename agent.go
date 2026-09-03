package ssh

import (
	"errors"
	"net"
	"os"
	"path"
	"sync"
	"sync/atomic"

	"github.com/echocat/slf4g"
	"github.com/echocat/slf4g/names"
	gossh "golang.org/x/crypto/ssh"
)

const (
	agentRequestType = "auth-agent-req@openssh.com"
	agentChannelType = "auth-agent@openssh.com"

	agentTempDir    = "auth-agent"
	agentListenFile = "listener.sock"
)

// contextKeyAgentRequest is an internal context key for storing if the
// client requested agent forwarding
var contextKeyAgentRequest = &contextKey{"auth-agent-req"}

// SetAgentRequested sets up the session context so that AgentRequested
// returns true.
func SetAgentRequested(ctx Context) {
	ctx.SetValue(contextKeyAgentRequest, true)
}

// AgentRequested returns true if the client requested agent forwarding.
func AgentRequested(sess Session) bool {
	return sess.Context().Value(contextKeyAgentRequest) == true
}

// NewAgentListener sets up a temporary Unix socket that can be communicated
// to the session environment and used for forwarding connections.
func NewAgentListener() (net.Listener, error) {
	dir, err := os.MkdirTemp("", agentTempDir)
	if err != nil {
		return nil, err
	}
	l, err := net.Listen("unix", path.Join(dir, agentListenFile))
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	return &agentListener{Listener: l, dir: dir}, nil
}

type agentListener struct {
	net.Listener
	dir string
}

type sessionAgentContext struct {
	Context
	requested atomic.Bool
}

func (ctx *sessionAgentContext) Value(key any) any {
	if key == contextKeyAgentRequest {
		return ctx.requested.Load()
	}
	return ctx.Context.Value(key)
}

func (ctx *sessionAgentContext) SetValue(key, value any) {
	if key == contextKeyAgentRequest {
		ctx.requested.Store(value == true)
		return
	}
	ctx.Context.SetValue(key, value)
}

func (l *agentListener) Close() error {
	return errors.Join(l.Listener.Close(), os.RemoveAll(l.dir))
}

// ForwardAgentConnections takes connections from a listener to proxy into the
// session on the OpenSSH channel for agent connections. It blocks and services
// connections until the listener stop accepting.
func ForwardAgentConnections(ln net.Listener, logger log.Logger, sess Session) {
	if logger == nil {
		logger = defaultForwardAgentConnectionsLoggerGetter()
	}
	if ln == nil || sess == nil {
		logger.Error("cannot forward agent connections without a listener and session")
		return
	}
	ctx := sess.Context()
	if ctx == nil {
		logger.Error("cannot forward agent connections without a session context")
		return
	}
	sshConn, ok := ctx.Value(ContextKeyConn).(gossh.Conn)
	if !ok || sshConn == nil {
		logger.Error("cannot forward agent connections outside a server-managed SSH connection")
		return
	}
	limiter, _ := ctx.Value(contextKeyChannelLimiter).(*connectionChannelLimiter)
	for {
		conn, err := ln.Accept()
		if isClosedError(err) {
			return
		}
		if err != nil {
			logger.WithError(err).
				Warnf("failed to listen for %s channel connections; closing...", agentChannelType)
			return
		}
		if !limiter.reserve() {
			closeQuietly(conn)
			logger.Warnf("too many open SSH channels; rejecting %s connection...", agentChannelType)
			continue
		}
		if !startConnectionWorker(ctx, func() {
			defer closeQuietly(conn)
			defer limiter.release()
			channel, reqs, err := openForwardedChannel(ctx, nil, sshConn, agentChannelType, nil)
			if err != nil {
				logger.WithError(err).
					Warnf("failed to open %s channel; rejecting...", agentChannelType)
				return
			}
			defer closeQuietly(channel)
			go gossh.DiscardRequests(reqs)
			if err := FullDuplexCopy(ctx, conn, channel, &FullDuplexCopyOpts{}); err != nil {
				logger.WithError(err).
					Warnf("failed to handle %s requests; closing...", agentChannelType)
				return
			}
		}) {
			limiter.release()
			closeQuietly(conn)
			return
		}
	}
}

var defaultForwardAgentConnectionsLoggerGetter = sync.OnceValue[log.Logger](func() log.Logger {
	return log.GetLogger(names.CurrentPackageLoggerNameGenerator(0) + ".agent")
})
