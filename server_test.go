package ssh

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
)

func TestAddHostKey(t *testing.T) {
	s := Server{}
	signer, err := generateSigner()
	if err != nil {
		t.Fatal(err)
	}
	s.AddHostKey(signer)
	if len(s.HostSigners) != 1 {
		t.Fatal("Key was not properly added")
	}
	signer, err = generateSigner()
	if err != nil {
		t.Fatal(err)
	}
	s.AddHostKey(signer)
	if len(s.HostSigners) != 1 {
		t.Fatal("Key was not properly replaced")
	}
}

func TestServerConfigUsesAlgorithmDefaults(t *testing.T) {
	ctx, cancel := newContext(nil)
	defer cancel()

	config := (&Server{}).config(ctx)
	require.Equal(t, algorithmNames(DefaultCiphers), config.Ciphers)
	require.Equal(t, algorithmNames(DefaultKeyExchanges), config.KeyExchanges)
	require.Equal(t, algorithmNames(DefaultMessageAuthentications), config.MACs)
}

func TestServerConfigUsesConfiguredAlgorithms(t *testing.T) {
	ctx, cancel := newContext(nil)
	defer cancel()
	srv := &Server{
		Ciphers:                Ciphers{CipherChacha20Poly1305},
		KeyExchanges:           KeyExchanges{KeyExchangeMlkem768x25519xSha256},
		MessageAuthentications: MessageAuthentications{MessageAuthenticationHmacSha2B512Etm},
		ServerConfigCallback: func(Context) *gossh.ServerConfig {
			return &gossh.ServerConfig{
				Config: gossh.Config{
					Ciphers:      []string{CipherAes128Ctr.String()},
					KeyExchanges: []string{KeyExchangeEcdh256.String()},
					MACs:         []string{MessageAuthenticationHmacSha2B256.String()},
				},
			}
		},
	}

	config := srv.config(ctx)
	require.Equal(t, []string{CipherChacha20Poly1305.String()}, config.Ciphers)
	require.Equal(t, []string{KeyExchangeMlkem768x25519xSha256.String()}, config.KeyExchanges)
	require.Equal(t, []string{MessageAuthenticationHmacSha2B512Etm.String()}, config.MACs)
}

func TestServerConfigPreservesCallbackAlgorithms(t *testing.T) {
	ctx, cancel := newContext(nil)
	defer cancel()
	expected := gossh.Config{
		Ciphers:      []string{CipherAes128Ctr.String()},
		KeyExchanges: []string{KeyExchangeEcdh256.String()},
		MACs:         []string{MessageAuthenticationHmacSha2B256.String()},
	}
	srv := &Server{
		ServerConfigCallback: func(Context) *gossh.ServerConfig {
			return &gossh.ServerConfig{Config: expected}
		},
	}

	config := srv.config(ctx)
	require.Equal(t, expected.Ciphers, config.Ciphers)
	require.Equal(t, expected.KeyExchanges, config.KeyExchanges)
	require.Equal(t, expected.MACs, config.MACs)
}

func algorithmNames[T interface{ String() string }](algorithms []T) []string {
	result := make([]string, len(algorithms))
	for i, algorithm := range algorithms {
		result[i] = algorithm.String()
	}
	return result
}

func TestServerShutdown(t *testing.T) {
	l := newLocalListener()
	testBytes := []byte("Hello world\n")
	s := &Server{
		Handler: func(s Session) {
			if _, err := s.Write(testBytes); err != nil {
				t.Error(err)
			}
			time.Sleep(50 * time.Millisecond)
		},
	}
	go func() {
		err := s.Serve(l)
		if err != nil && !errors.Is(err, ErrServerClosed) {
			t.Error(err)
		}
	}()
	sessDone := make(chan struct{})
	sess, _, cleanup := newClientSession(t, l.Addr().String(), nil)
	go func() {
		defer cleanup()
		defer close(sessDone)
		var stdout bytes.Buffer
		sess.Stdout = &stdout
		if err := sess.Run(""); err != nil {
			t.Error(err)
		}
		if !bytes.Equal(stdout.Bytes(), testBytes) {
			t.Errorf("expected = %s; got %s", testBytes, stdout.Bytes())
		}
	}()

	srvDone := make(chan struct{})
	go func() {
		defer close(srvDone)
		err := s.Shutdown(context.Background())
		if err != nil {
			t.Error(err)
		}
	}()

	timeout := time.After(2 * time.Second)
	select {
	case <-timeout:
		t.Fatal("timeout")
		return
	case <-srvDone:
		// TODO: add timeout for sessDone
		<-sessDone
		return
	}
}

func TestServerClose(t *testing.T) {
	l := newLocalListener()
	s := &Server{
		Handler: func(s Session) {
			time.Sleep(5 * time.Second)
		},
	}
	go func() {
		err := s.Serve(l)
		if err != nil && !errors.Is(err, ErrServerClosed) {
			t.Error(err)
		}
	}()

	clientDoneChan := make(chan struct{})
	closeDoneChan := make(chan struct{})

	sess, _, cleanup := newClientSession(t, l.Addr().String(), nil)
	go func() {
		defer cleanup()
		defer close(clientDoneChan)
		<-closeDoneChan
		if err := sess.Run(""); err != nil && err != io.EOF {
			t.Error(err)
		}
	}()

	go func() {
		err := s.Close()
		if err != nil {
			t.Error(err)
		}
		close(closeDoneChan)
	}()

	timeout := time.After(100 * time.Millisecond)
	select {
	case <-timeout:
		t.Error("timeout")
		return
	case <-s.getDoneChan():
		<-clientDoneChan
		return
	}
}

func TestServerHandshakeTimeout(t *testing.T) {
	l := newLocalListener()

	s := &Server{
		HandshakeTimeout: time.Millisecond,
	}
	go func() {
		if err := s.Serve(l); err != nil {
			t.Error(err)
		}
	}()

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer closeQuietly(conn)

	ch := make(chan struct{})
	go func() {
		defer close(ch)
		_, _ = io.Copy(io.Discard, conn)
	}()

	select {
	case <-ch:
		return
	case <-time.After(time.Second):
		t.Fatal("client connection was not force-closed")
		return
	}
}
