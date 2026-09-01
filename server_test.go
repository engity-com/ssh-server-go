package ssh

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
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

func TestRequireHostSigners(t *testing.T) {
	srv := &Server{RequireHostSigners: true}
	require.ErrorIs(t, srv.ensureHostSigner(), ErrServerHostSignerRequired)
	signer, err := generateSigner()
	require.NoError(t, err)
	srv.AddHostKey(signer)
	require.NoError(t, srv.ensureHostSigner())

	generated := &Server{}
	require.NoError(t, generated.ensureHostSigner())
	generated.RequireHostSigners = true
	require.ErrorIs(t, generated.ensureHostSigner(), ErrServerHostSignerRequired)
	generated.AddHostKey(signer)
	require.NoError(t, generated.ensureHostSigner())
}

func TestConnectionSettingsSnapshot(t *testing.T) {
	timeout := time.Second
	oldHandlerCalled := false
	oldChannelHandlerCalled := false
	srv := &Server{
		Handler: func(Session) { oldHandlerCalled = true },
		ChannelHandlers: map[string]ChannelHandler{
			"test": func(*Server, *gossh.ServerConn, gossh.NewChannel, Context) {
				oldChannelHandlerCalled = true
			},
		},
		HandshakeTimeout: &timeout,
	}

	settings := srv.connectionSettings()
	srv.Handle(func(Session) { t.Fatal("snapshot used updated handler") })
	srv.ChannelHandlers["test"] = func(*Server, *gossh.ServerConn, gossh.NewChannel, Context) {
		t.Fatal("snapshot used updated channel handler")
	}
	timeout = 2 * time.Second

	settings.handler(nil)
	settings.channelHandlers["test"](nil, nil, nil, nil)
	require.True(t, oldHandlerCalled)
	require.True(t, oldChannelHandlerCalled)
	require.Equal(t, time.Second, settings.handshakeTimeout)
}

func TestSetOptionRejectsRunningServer(t *testing.T) {
	srv := &Server{activeConns: map[*activeConn]struct{}{{}: {}}}
	called := false
	option := func(*Server) error {
		called = true
		return nil
	}

	require.ErrorIs(t, srv.SetOption(option), ErrServerRunning)
	require.False(t, called)
	srv.activeConns = nil
	require.NoError(t, srv.SetOption(option))
	require.True(t, called)
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
		ServerConfigCallback: func(_ Context, config *gossh.ServerConfig) {
			config.Config = gossh.Config{
				Ciphers:      []string{CipherAes128Ctr.String()},
				KeyExchanges: []string{KeyExchangeEcdh256.String()},
				MACs:         []string{MessageAuthenticationHmacSha2B256.String()},
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
		ServerConfigCallback: func(_ Context, config *gossh.ServerConfig) {
			config.Config = expected
		},
	}

	config := srv.config(ctx)
	require.Equal(t, expected.Ciphers, config.Ciphers)
	require.Equal(t, expected.KeyExchanges, config.KeyExchanges)
	require.Equal(t, expected.MACs, config.MACs)
}

func TestServerConfigCallbackReceivesFreshConfig(t *testing.T) {
	var configs []*gossh.ServerConfig
	srv := &Server{ServerConfigCallback: func(_ Context, config *gossh.ServerConfig) {
		configs = append(configs, config)
	}}
	ctx1, cancel1 := newContext(nil)
	defer cancel1()
	ctx2, cancel2 := newContext(nil)
	defer cancel2()

	first := srv.config(ctx1)
	second := srv.config(ctx2)
	require.Len(t, configs, 2)
	require.Same(t, first, configs[0])
	require.Same(t, second, configs[1])
	require.NotSame(t, first, second)
}

func TestServerConfigCallbackRunsWithoutServerLock(t *testing.T) {
	srv := &Server{}
	srv.ServerConfigCallback = func(Context, *gossh.ServerConfig) {
		srv.Handle(func(Session) {})
	}
	ctx, cancel := newContext(nil)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.config(ctx)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("ServerConfigCallback ran while the server lock was held")
	}
}

func TestServerConfigCallbackDoesNotEnableNoClientAuth(t *testing.T) {
	ctx, cancel := newContext(nil)
	defer cancel()
	srv := &Server{
		ServerConfigCallback: func(_ Context, config *gossh.ServerConfig) {
			config.PasswordCallback = func(gossh.ConnMetadata, []byte) (*gossh.Permissions, error) {
				return nil, nil
			}
		},
	}

	require.False(t, srv.config(ctx).NoClientAuth)
}

func TestServerConfigCallbackPreservesAnonymousZeroValue(t *testing.T) {
	ctx, cancel := newContext(nil)
	defer cancel()
	srv := &Server{ServerConfigCallback: func(_ Context, config *gossh.ServerConfig) {
		config.MaxAuthTries = 3
	}}

	require.True(t, srv.config(ctx).NoClientAuth)
}

func TestCustomAuthenticationCallbackPublishesFinalState(t *testing.T) {
	ctx, cancel := newContext(nil)
	defer cancel()
	srv := &Server{
		ServerConfigCallback: func(_ Context, config *gossh.ServerConfig) {
			config.PasswordCallback = func(gossh.ConnMetadata, []byte) (*gossh.Permissions, error) {
				return &gossh.Permissions{Extensions: map[string]string{"method": "custom"}}, nil
			}
		},
	}
	config := srv.config(ctx)

	permissions, err := config.PasswordCallback(testConnMetadata{user: "custom-user"}, nil)
	require.NoError(t, err)
	require.Equal(t, "custom", permissions.Extensions["method"])
	require.Equal(t, "custom", ctx.Permissions().Extensions["method"])
	require.Equal(t, "custom-user", ctx.User())
}

func TestPartialAuthenticationCallbacksIsolateAttemptState(t *testing.T) {
	ctx, cancel := newContext(nil)
	defer cancel()
	var secondFactorUser string
	var secondFactorPermissions map[string]string
	srv := &Server{
		ServerConfigCallback: func(_ Context, config *gossh.ServerConfig) {
			config.PasswordCallback = func(gossh.ConnMetadata, []byte) (*gossh.Permissions, error) {
				return nil, &gossh.PartialSuccessError{
					Next: gossh.ServerAuthCallbacks{
						PasswordCallback: func(gossh.ConnMetadata, []byte) (*gossh.Permissions, error) {
							secondFactorUser = ctx.User()
							secondFactorPermissions = ctx.Permissions().Extensions
							return &gossh.Permissions{Extensions: map[string]string{"factor": "second"}}, nil
						},
					},
				}
			}
		},
	}
	config := srv.config(ctx)

	_, err := config.PasswordCallback(testConnMetadata{user: "first-user"}, nil)
	partial, ok := errors.AsType[*gossh.PartialSuccessError](err)
	require.True(t, ok)
	permissions, err := partial.Next.PasswordCallback(testConnMetadata{user: "second-user"}, nil)
	require.NoError(t, err)
	require.Equal(t, "second-user", secondFactorUser)
	require.Empty(t, secondFactorPermissions)
	require.Equal(t, "second", permissions.Extensions["factor"])
	require.Equal(t, "second", ctx.Permissions().Extensions["factor"])
}

func TestGSSAPIAuthenticationInitializesContext(t *testing.T) {
	ctx, cancel := newContext(nil)
	defer cancel()
	var callbackUser string
	srv := &Server{
		ServerConfigCallback: func(_ Context, config *gossh.ServerConfig) {
			config.GSSAPIWithMICConfig = &gossh.GSSAPIWithMICConfig{
				AllowLogin: func(gossh.ConnMetadata, string) (*gossh.Permissions, error) {
					callbackUser = ctx.User()
					return nil, nil
				},
			}
		},
	}
	config := srv.config(ctx)

	_, err := config.GSSAPIWithMICConfig.AllowLogin(testConnMetadata{user: "gssapi-user"}, "user@DOMAIN")
	require.NoError(t, err)
	require.Equal(t, "gssapi-user", callbackUser)
}

func TestAuthenticationCallbacksIsolateAttemptState(t *testing.T) {
	ctx, cancel := newContext(nil)
	defer cancel()
	var users []string
	srv := &Server{
		PasswordHandler: func(ctx Context, _ string) bool {
			users = append(users, ctx.User())
			ctx.Permissions().Extensions = map[string]string{"user": ctx.User()}
			return ctx.User() == "admin"
		},
	}
	config := srv.config(ctx)

	_, err := config.PasswordCallback(testConnMetadata{user: "guest"}, nil)
	require.ErrorIs(t, err, ErrServerPermissionDenied)
	permissions, err := config.PasswordCallback(testConnMetadata{user: "admin"}, nil)
	require.NoError(t, err)
	require.Equal(t, []string{"guest", "admin"}, users)
	require.Equal(t, "admin", permissions.Extensions["user"])
	require.Equal(t, "admin", ctx.User())
}

func TestPublicKeyStateIsPublishedOnlyAfterVerification(t *testing.T) {
	ctx, cancel := newContext(nil)
	defer cancel()
	signer, err := generateSigner()
	require.NoError(t, err)
	key := signer.PublicKey()
	srv := &Server{
		PublicKeyHandler: func(ctx Context, _ PublicKey) bool {
			ctx.Permissions().Extensions = map[string]string{"method": "public-key"}
			return true
		},
	}
	config := srv.config(ctx)
	metadata := testConnMetadata{user: "user"}

	permissions, err := config.PublicKeyCallback(metadata, key)
	require.NoError(t, err)
	require.Nil(t, ctx.Value(ContextKeyPublicKey))
	verified, err := config.VerifiedPublicKeyCallback(metadata, key, permissions, key.Type())
	require.NoError(t, err)
	require.Equal(t, key, ctx.Value(ContextKeyPublicKey))
	require.Equal(t, "public-key", verified.Extensions["method"])
}

func TestCustomPublicKeyCallbackPublishesVerifiedKey(t *testing.T) {
	ctx, cancel := newContext(nil)
	defer cancel()
	signer, err := generateSigner()
	require.NoError(t, err)
	key := signer.PublicKey()
	srv := &Server{ServerConfigCallback: func(_ Context, config *gossh.ServerConfig) {
		config.PublicKeyCallback = func(gossh.ConnMetadata, gossh.PublicKey) (*gossh.Permissions, error) {
			return &gossh.Permissions{}, nil
		}
	}}
	config := srv.config(ctx)
	metadata := testConnMetadata{user: "user"}

	permissions, err := config.PublicKeyCallback(metadata, key)
	require.NoError(t, err)
	require.Nil(t, ctx.Value(ContextKeyPublicKey))
	_, err = config.VerifiedPublicKeyCallback(metadata, key, permissions, key.Type())
	require.NoError(t, err)
	require.Equal(t, key, ctx.Value(ContextKeyPublicKey))
}

type testConnMetadata struct {
	user string
}

func (m testConnMetadata) User() string        { return m.user }
func (testConnMetadata) SessionID() []byte     { return []byte("session") }
func (testConnMetadata) ClientVersion() []byte { return []byte("client") }
func (testConnMetadata) ServerVersion() []byte { return []byte("server") }
func (testConnMetadata) RemoteAddr() net.Addr  { return testAddr("remote") }
func (testConnMetadata) LocalAddr() net.Addr   { return testAddr("local") }

type testAddr string

func (a testAddr) Network() string { return "test" }
func (a testAddr) String() string  { return string(a) }

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
	handshakeTimeout := time.Millisecond

	s := &Server{
		HandshakeTimeout: &handshakeTimeout,
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

func TestConfiguredDuration(t *testing.T) {
	require.Equal(t, DefaultHandshakeTimeout, configuredDuration(nil, DefaultHandshakeTimeout))
	configured := 5 * time.Second
	require.Equal(t, configured, configuredDuration(&configured, DefaultHandshakeTimeout))
	disabled := time.Duration(0)
	require.Zero(t, configuredDuration(&disabled, DefaultHandshakeTimeout))
	disabled = -1
	require.Zero(t, configuredDuration(&disabled, DefaultHandshakeTimeout))
}

func TestTimeoutCancelsBlockingConnCallback(t *testing.T) {
	for _, field := range []string{"handshake", "max"} {
		t.Run(field, func(t *testing.T) {
			timeout := 10 * time.Millisecond
			disabled := time.Duration(0)
			srv := &Server{ConnCallback: func(ctx Context, _ net.Conn) net.Conn {
				<-ctx.Done()
				return nil
			}}
			if field == "handshake" {
				srv.HandshakeTimeout = &timeout
				srv.MaxStartups = &MaxStartupsConfig{}
			} else {
				srv.HandshakeTimeout = &disabled
				srv.MaxTimeout = &timeout
			}
			serverConn, clientConn := net.Pipe()
			defer closeQuietly(clientConn)
			done := make(chan struct{})
			go func() {
				defer close(done)
				srv.HandleConn(serverConn)
			}()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("timeout did not cancel the connection callback context")
			}
		})
	}
}

func TestCloseCancelsConnCallbackContext(t *testing.T) {
	disabled := time.Duration(0)
	callbackEntered := make(chan struct{})
	srv := &Server{
		HandshakeTimeout: &disabled,
		ConnCallback: func(ctx Context, _ net.Conn) net.Conn {
			close(callbackEntered)
			<-ctx.Done()
			return nil
		},
	}
	serverConn, clientConn := net.Pipe()
	defer closeQuietly(clientConn)
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.HandleConn(serverConn)
	}()
	<-callbackEntered
	require.NoError(t, srv.Close())
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel ConnCallback context")
	}
}

func TestEarliestDeadline(t *testing.T) {
	now := time.Now()
	earlier := now.Add(time.Second)
	later := now.Add(2 * time.Second)
	require.Equal(t, earlier, earliestDeadline(later, time.Time{}, earlier))
	require.True(t, earliestDeadline().IsZero())
}

func TestConfiguredLimit(t *testing.T) {
	require.Equal(t, DefaultMaxSessionsPerConnection, configuredLimit(nil, DefaultMaxSessionsPerConnection))
	configured := 5
	require.Equal(t, configured, configuredLimit(&configured, DefaultMaxSessionsPerConnection))
	disabled := 0
	require.Zero(t, configuredLimit(&disabled, DefaultMaxSessionsPerConnection))
	disabled = -1
	require.Zero(t, configuredLimit(&disabled, DefaultMaxSessionsPerConnection))
}

func TestMaxStartupsDropRate(t *testing.T) {
	config := MaxStartupsConfig{
		Start: DefaultMaxStartupsStart,
		Rate:  DefaultMaxStartupsRate,
		Full:  DefaultMaxStartupsFull,
	}
	require.Zero(t, maxStartupsDropRate(9, config))
	require.Equal(t, 30, maxStartupsDropRate(10, config))
	require.Equal(t, 65, maxStartupsDropRate(55, config))
	require.Equal(t, 100, maxStartupsDropRate(100, config))
	require.Zero(t, maxStartupsDropRate(100, MaxStartupsConfig{}))
	require.Equal(t, 100, maxStartupsDropRate(5, MaxStartupsConfig{Start: 10, Full: 5}))
}

func TestConnectionChannelLimiter(t *testing.T) {
	limiter := &connectionChannelLimiter{limit: 1}
	require.True(t, limiter.reserve())
	require.False(t, limiter.reserve())
	limiter.release()
	require.True(t, limiter.reserve())
	limiter.release()
}

func TestConnectionChannelLimiterUsesGlobalLimit(t *testing.T) {
	var active atomic.Int64
	global := &resourceLimiter{limit: 1, active: &active}
	first := &connectionChannelLimiter{limit: 10, global: global}
	second := &connectionChannelLimiter{limit: 10, global: global}
	require.True(t, first.reserve())
	require.False(t, second.reserve())
	first.release()
	require.True(t, second.reserve())
	second.release()
}

func TestMaxStartupsRejectsConnectionsAtFullLimit(t *testing.T) {
	l := newLocalListener()
	s := &Server{MaxStartups: &MaxStartupsConfig{Start: 1, Rate: 0, Full: 1}}
	serveDone := make(chan error, 1)
	go func() { serveDone <- s.Serve(l) }()

	first, err := net.Dial("tcp", l.Addr().String())
	require.NoError(t, err)
	defer closeQuietly(first)
	require.Eventually(t, func() bool {
		s.mu.RLock()
		defer s.mu.RUnlock()
		return s.startups == 1
	}, time.Second, time.Millisecond)

	second, err := net.Dial("tcp", l.Addr().String())
	require.NoError(t, err)
	defer closeQuietly(second)
	require.NoError(t, second.SetReadDeadline(time.Now().Add(time.Second)))
	_, err = second.Read(make([]byte, 1))
	require.Error(t, err)
	if netErr, ok := errors.AsType[net.Error](err); ok {
		require.False(t, netErr.Timeout(), "connection was not rejected at the startup limit")
	}

	require.NoError(t, s.Close())
	require.ErrorIs(t, <-serveDone, ErrServerClosed)
}

func TestFailedHandshakeReleasesStartupBeforeCallback(t *testing.T) {
	l := newLocalListener()
	callbackEntered := make(chan struct{})
	releaseCallback := make(chan struct{})
	var callbackOnce sync.Once
	s := &Server{
		MaxStartups: &MaxStartupsConfig{Start: 1, Full: 1},
		ConnectionFailedCallback: func(net.Conn, error) {
			callbackOnce.Do(func() {
				close(callbackEntered)
				<-releaseCallback
			})
		},
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- s.Serve(l) }()

	first, err := net.Dial("tcp", l.Addr().String())
	require.NoError(t, err)
	_, err = io.WriteString(first, "SSH-1.0-invalid\r\n")
	require.NoError(t, err)
	closeQuietly(first)
	select {
	case <-callbackEntered:
	case <-time.After(time.Second):
		t.Fatal("connection failure callback was not called")
	}

	second, err := net.Dial("tcp", l.Addr().String())
	require.NoError(t, err)
	defer closeQuietly(second)
	require.NoError(t, second.SetReadDeadline(time.Now().Add(time.Second)))
	version := make([]byte, 4)
	_, err = io.ReadFull(second, version)
	require.NoError(t, err)
	require.Equal(t, "SSH-", string(version))

	close(releaseCallback)
	require.NoError(t, s.Close())
	require.ErrorIs(t, <-serveDone, ErrServerClosed)
}

func TestServerCloseClosesConnectionDuringHandshake(t *testing.T) {
	l := newLocalListener()
	s := &Server{}
	serveDone := make(chan error, 1)
	go func() { serveDone <- s.Serve(l) }()

	conn, err := net.Dial("tcp", l.Addr().String())
	require.NoError(t, err)
	defer closeQuietly(conn)

	require.Eventually(t, func() bool {
		s.mu.RLock()
		defer s.mu.RUnlock()
		return len(s.activeConns) == 1
	}, time.Second, time.Millisecond)
	require.NoError(t, s.Close())
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(time.Second)))
	_, err = io.ReadAll(conn)
	if netErr, ok := errors.AsType[net.Error](err); ok {
		require.False(t, netErr.Timeout(), "connection was not closed")
	} else {
		require.NoError(t, err)
	}
	require.ErrorIs(t, <-serveDone, ErrServerClosed)
}

func TestServerCloseRejectsConnCallbackReplacement(t *testing.T) {
	original, originalPeer := net.Pipe()
	replacement, replacementPeer := net.Pipe()
	defer closeQuietly(originalPeer)
	defer closeQuietly(replacementPeer)
	callbackEntered := make(chan struct{})
	releaseCallback := make(chan struct{})
	s := &Server{
		ConnCallback: func(Context, net.Conn) net.Conn {
			close(callbackEntered)
			<-releaseCallback
			return replacement
		},
	}
	handleDone := make(chan struct{})
	go func() {
		defer close(handleDone)
		s.HandleConn(original)
	}()
	<-callbackEntered
	require.NoError(t, s.Close())
	close(releaseCallback)
	select {
	case <-handleDone:
	case <-time.After(time.Second):
		t.Fatal("connection callback did not stop after server close")
	}
	_, err := replacementPeer.Read(make([]byte, 1))
	require.Error(t, err)
}

func TestServerReuseWaitsForPreviousGeneration(t *testing.T) {
	firstEntered := make(chan struct{})
	secondEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	setOptionResult := make(chan error, 1)
	var calls atomic.Int32
	var srv *Server
	srv = &Server{ConnCallback: func(Context, net.Conn) net.Conn {
		if calls.Add(1) == 1 {
			close(firstEntered)
			<-releaseFirst
			setOptionResult <- srv.SetOption(NoPty())
		} else {
			close(secondEntered)
		}
		return nil
	}}
	first, firstPeer := net.Pipe()
	defer closeQuietly(firstPeer)
	go srv.HandleConn(first)
	<-firstEntered
	require.NoError(t, srv.Close())

	second, secondPeer := net.Pipe()
	defer closeQuietly(secondPeer)
	secondDone := make(chan struct{})
	go func() {
		defer close(secondDone)
		srv.HandleConn(second)
	}()
	select {
	case <-secondEntered:
		t.Fatal("new generation started before the previous one drained")
	case <-time.After(20 * time.Millisecond):
	}
	close(releaseFirst)
	require.ErrorIs(t, <-setOptionResult, ErrServerRunning)
	select {
	case <-secondEntered:
	case <-time.After(time.Second):
		t.Fatal("new generation did not start after the previous one drained")
	}
	<-secondDone
}

func TestServerConnDeadlineAccessIsSynchronized(t *testing.T) {
	left, right := net.Pipe()
	defer closeQuietly(left)
	defer closeQuietly(right)
	conn := &serverConn{Conn: left, idleTimeout: time.Millisecond, handshakeDeadline: time.Now().Add(time.Second)}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		conn.updateDeadline()
	}()
	go func() {
		defer wg.Done()
		conn.clearHandshakeDeadline()
	}()
	wg.Wait()
}
