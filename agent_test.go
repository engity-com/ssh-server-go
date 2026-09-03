package ssh

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAgentListenerRemovesTemporaryDirectory(t *testing.T) {
	listener, err := NewAgentListener()
	require.NoError(t, err)
	dir := listener.(*agentListener).dir
	require.NoError(t, listener.Close())
	_, err = os.Stat(dir)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestAgentRequestedIsScopedToSession(t *testing.T) {
	requested := make(chan bool, 2)
	first, client, cleanup := newTestSession(t, &Server{
		Handler: func(s Session) error {
			requested <- AgentRequested(s)
			return nil
		},
		AgentForwardingCallback: func(Context, Session) (bool, error) { return true, nil },
	}, nil)
	defer cleanup()

	ok, err := first.SendRequest(agentRequestType, true, nil)
	require.NoError(t, err)
	require.True(t, ok)
	require.NoError(t, first.Run(""))
	require.True(t, <-requested)

	second, err := client.NewSession()
	require.NoError(t, err)
	defer closeQuietly(second)
	require.NoError(t, second.Run(""))
	require.False(t, <-requested)
}

func TestAgentForwardingIsDeniedByDefault(t *testing.T) {
	session, _, cleanup := newTestSession(t, &Server{Handler: func(Session) error { return nil }}, nil)
	defer cleanup()

	ok, err := session.SendRequest(agentRequestType, true, nil)
	require.NoError(t, err)
	require.False(t, ok)
}

func TestForwardAgentConnectionsClosesBlockedSSHConnection(t *testing.T) {
	listener := newLocalListener()
	defer closeQuietly(listener)
	sshConn := &blockingSSHConn{started: make(chan struct{}), closed: make(chan struct{})}
	ctx, cancel := newContext(&Server{})
	defer cancel()
	ctx.SetValue(ContextKeyConn, sshConn)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ForwardAgentConnections(listener, nil, &session{ctx: ctx})
	}()

	localConn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	defer closeQuietly(localConn)
	<-sshConn.started
	select {
	case <-sshConn.closed:
	case <-time.After(2 * forwardedChannelRegistrationTimeout):
		t.Fatal("agent forwarding did not close a connection with a blocked channel open")
	}
	closeQuietly(listener)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("agent forwarding did not stop after listener close")
	}
}
