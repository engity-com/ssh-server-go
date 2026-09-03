package ssh

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	gosshagent "golang.org/x/crypto/ssh/agent"
)

type agentForwardingCallbackEvent struct {
	contextUser      string
	sessionUser      string
	alreadyRequested bool
}

func receiveAgentForwardingCallbackEvent(t *testing.T, events <-chan agentForwardingCallbackEvent) agentForwardingCallbackEvent {
	t.Helper()
	select {
	case event := <-events:
		return event
	case <-time.After(time.Second):
		t.Fatal("agent forwarding callback was not called")
		return agentForwardingCallbackEvent{}
	}
}

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
	callbackCalled := make(chan agentForwardingCallbackEvent, 1)
	first, client, cleanup := newTestSession(t, &Server{
		Handler: func(s Session) error {
			requested <- AgentRequested(s)
			return nil
		},
		AgentForwardingCallback: func(ctx Context, sess Session) (bool, error) {
			callbackCalled <- agentForwardingCallbackEvent{
				contextUser:      ctx.User(),
				sessionUser:      sess.User(),
				alreadyRequested: AgentRequested(sess),
			}
			return true, nil
		},
	}, nil)
	defer cleanup()

	require.NoError(t, gosshagent.RequestAgentForwarding(first))
	event := receiveAgentForwardingCallbackEvent(t, callbackCalled)
	require.Equal(t, "testuser", event.contextUser)
	require.Equal(t, "testuser", event.sessionUser)
	require.False(t, event.alreadyRequested)
	require.NoError(t, first.Run(""))
	require.True(t, <-requested)

	second, err := client.NewSession()
	require.NoError(t, err)
	defer closeQuietly(second)
	require.NoError(t, second.Run(""))
	require.False(t, <-requested)
}

func TestAgentForwardingIsDeniedByCallback(t *testing.T) {
	requested := make(chan bool, 1)
	callbackCalled := make(chan agentForwardingCallbackEvent, 1)
	session, _, cleanup := newTestSession(t, &Server{
		Handler: func(sess Session) error {
			requested <- AgentRequested(sess)
			return nil
		},
		AgentForwardingCallback: func(ctx Context, sess Session) (bool, error) {
			callbackCalled <- agentForwardingCallbackEvent{
				contextUser:      ctx.User(),
				sessionUser:      sess.User(),
				alreadyRequested: AgentRequested(sess),
			}
			return false, nil
		},
	}, nil)
	defer cleanup()

	require.Error(t, gosshagent.RequestAgentForwarding(session))
	event := receiveAgentForwardingCallbackEvent(t, callbackCalled)
	require.Equal(t, "testuser", event.contextUser)
	require.Equal(t, "testuser", event.sessionUser)
	require.False(t, event.alreadyRequested)
	require.NoError(t, session.Run(""))
	require.False(t, <-requested)
}

func TestAgentForwardingIsDeniedByDefault(t *testing.T) {
	requested := make(chan bool, 1)
	session, _, cleanup := newTestSession(t, &Server{Handler: func(sess Session) error {
		requested <- AgentRequested(sess)
		return nil
	}}, nil)
	defer cleanup()

	require.Error(t, gosshagent.RequestAgentForwarding(session))
	require.NoError(t, session.Run(""))
	require.False(t, <-requested)
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
