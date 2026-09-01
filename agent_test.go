package ssh

import (
	"os"
	"testing"

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
		Handler: func(s Session) {
			requested <- AgentRequested(s)
		},
		AgentForwardingCallback: func(Context) bool { return true },
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
	session, _, cleanup := newTestSession(t, &Server{Handler: func(Session) {}}, nil)
	defer cleanup()

	ok, err := session.SendRequest(agentRequestType, true, nil)
	require.NoError(t, err)
	require.False(t, ok)
}
