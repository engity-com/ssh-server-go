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
