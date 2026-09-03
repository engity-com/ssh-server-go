package ssh

import (
	"context"
	"errors"
	"fmt"
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
	require.ErrorIs(t, srv.prepare(context.Background()), ErrServerHostSignerRequired)

	srv = &Server{}
	signer, err := generateSigner()
	require.NoError(t, err)
	srv.AddHostKey(signer)
	require.NoError(t, srv.prepare(context.Background()))
}

func TestHandleConnInitializesHostSigner(t *testing.T) {
	srv := &Server{}
	listener := newLocalListener()
	defer closeQuietly(listener)
	done := make(chan struct{})
	go func() {
		defer close(done)
		serverConn, err := listener.Accept()
		if err != nil {
			t.Error(err)
			return
		}
		_ = srv.HandleConn(context.Background(), serverConn)
	}()

	clientConn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	conn, chans, reqs, err := gossh.NewClientConn(clientConn, listener.Addr().String(), &gossh.ClientConfig{
		User:            "user",
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	})
	require.NoError(t, err)
	client := gossh.NewClient(conn, chans, reqs)
	require.NoError(t, client.Close())
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("HandleConn did not stop after the client closed")
	}
	require.Empty(t, srv.HostSigners)
	require.Len(t, srv.generatedHostSigners, 1)
}

func TestPreparationDoesNotMutatePublicConfiguration(t *testing.T) {
	srv := &Server{}
	require.NoError(t, srv.prepare(context.Background()))
	require.Nil(t, srv.Handler)
	require.Nil(t, srv.HostSigners)
	require.Nil(t, srv.ChannelHandlers)
	require.Nil(t, srv.RequestHandlers)
	require.Nil(t, srv.SubsystemHandlers)
	require.Len(t, srv.generatedHostSigners, 1)
}

func TestDisconnectCallbackWaitsForConnectionWorkers(t *testing.T) {
	type observation struct {
		ctxErr        error
		user          string
		sessionID     string
		serverConn    *gossh.ServerConn
		connectionErr error
	}

	handlerStarted := make(chan struct{})
	handlerCanceled := make(chan struct{})
	releaseHandler := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(releaseHandler) })
	disconnected := make(chan observation, 1)
	var calls atomic.Int32
	srv := &Server{
		Handler: func(session Session) error {
			close(handlerStarted)
			<-session.Context().Done()
			close(handlerCanceled)
			<-releaseHandler
			return nil
		},
		DisconnectCallback: func(ctx Context, conn net.Conn) error {
			calls.Add(1)
			_, connectionErr := conn.Write([]byte("closed"))
			serverConn, _ := ctx.Value(ContextKeyConn).(*gossh.ServerConn)
			disconnected <- observation{
				ctxErr:        ctx.Err(),
				user:          ctx.User(),
				sessionID:     ctx.SessionID(),
				serverConn:    serverConn,
				connectionErr: connectionErr,
			}
			return nil
		},
	}
	session, client, cleanup := newTestSession(t, srv, nil)
	defer cleanup()
	require.NoError(t, session.Start(""))
	<-handlerStarted
	require.NoError(t, session.Close())
	require.Never(t, func() bool { return calls.Load() != 0 }, 20*time.Millisecond, time.Millisecond)

	require.NoError(t, client.Close())
	<-handlerCanceled
	require.Zero(t, calls.Load(), "callback ran before the connection worker stopped")
	releaseOnce.Do(func() { close(releaseHandler) })

	select {
	case got := <-disconnected:
		require.ErrorIs(t, got.ctxErr, context.Canceled)
		require.Equal(t, "testuser", got.user)
		require.NotEmpty(t, got.sessionID)
		require.NotNil(t, got.serverConn)
		require.Error(t, got.connectionErr)
	case <-time.After(time.Second):
		t.Fatal("disconnect callback was not called")
	}
	require.Never(t, func() bool { return calls.Load() > 1 }, 20*time.Millisecond, time.Millisecond)
}

func TestHandleConnReportsRequiredHostSigner(t *testing.T) {
	var callbackCalls atomic.Int32
	srv := &Server{
		RequireHostSigners: true,
		ConnectionFailedCallback: func(Context, net.Conn, error) error {
			callbackCalls.Add(1)
			return nil
		},
	}
	serverConn, clientConn := net.Pipe()
	defer closeQuietly(clientConn)
	err := srv.HandleConn(context.Background(), serverConn)

	require.ErrorIs(t, err, ErrServerHostSignerRequired)
	_ = clientConn.SetReadDeadline(time.Now().Add(time.Second))
	_, err = clientConn.Read(make([]byte, 1))
	require.Error(t, err)
	require.Zero(t, callbackCalls.Load())
}

func TestHandleConnDispatchesHandshakeError(t *testing.T) {
	var errorHandlerCalls atomic.Int32
	srv := &Server{
		ErrorHandler: func(ctx context.Context, scope ErrorScope, operation ErrorOperation, err error, respond ErrorResponder, next ErrorHandler) (bool, error) {
			errorHandlerCalls.Add(1)
			require.Equal(t, ErrorScopeConnection, scope)
			require.Equal(t, ErrorOperationHandshake, operation)
			return next(ctx, scope, operation, err, respond, next)
		},
	}
	serverConn, clientConn := net.Pipe()
	closeQuietly(clientConn)

	err := srv.HandleConn(context.Background(), serverConn)
	require.Error(t, err)
	require.Equal(t, int32(1), errorHandlerCalls.Load())
}

func TestRequireClientAuthReportsMissingAuthentication(t *testing.T) {
	srv := &Server{
		RequireClientAuth: true,
	}
	serverConn, clientConn := net.Pipe()
	defer closeQuietly(clientConn)
	err := srv.HandleConn(context.Background(), serverConn)
	require.ErrorIs(t, err, ErrServerClientAuthRequired)
}

func TestRequireClientAuthRejectsExplicitAnonymousAuthentication(t *testing.T) {
	config := &gossh.ServerConfig{
		NoClientAuth:     true,
		PasswordCallback: func(gossh.ConnMetadata, []byte) (*gossh.Permissions, error) { return nil, nil },
	}
	require.False(t, serverConfigHasClientAuth(config))
}

func TestAuthCallbacksReceiveCurrentMetadata(t *testing.T) {
	ctx, cancel := newContext(nil)
	defer cancel()
	var authUser, bannerUser string
	srv := &Server{ServerConfigCallback: func(ctx Context, _ net.Conn, config *gossh.ServerConfig) error {
		config.AuthLogCallback = func(gossh.ConnMetadata, string, error) { authUser = ctx.User() }
		config.BannerCallback = func(gossh.ConnMetadata) string {
			bannerUser = ctx.User()
			return "banner"
		}
		return nil
	}}
	config := srv.config(ctx)
	metadata := testConnMetadata{user: "current-user"}
	require.Equal(t, "banner", config.BannerCallback(metadata))
	config.AuthLogCallback(metadata, "none", ErrServerPermissionDenied)
	require.Equal(t, "current-user", bannerUser)
	require.Equal(t, "current-user", authUser)
}

func TestPreAuthCallbackReceivesCurrentContextMetadata(t *testing.T) {
	type metadata struct {
		user          string
		sessionID     string
		clientVersion string
		serverVersion string
		localAddr     string
		remoteAddr    string
	}
	observed := make(chan metadata, 1)
	srv := &Server{ServerConfigCallback: func(ctx Context, _ net.Conn, config *gossh.ServerConfig) error {
		config.PreAuthConnCallback = func(gossh.ServerPreAuthConn) {
			observed <- metadata{
				user:          ctx.User(),
				sessionID:     ctx.SessionID(),
				clientVersion: ctx.ClientVersion(),
				serverVersion: ctx.ServerVersion(),
				localAddr:     ctx.LocalAddr().String(),
				remoteAddr:    ctx.RemoteAddr().String(),
			}
		}
		return nil
	}}
	session, _, cleanup := newTestSession(t, srv, nil)
	defer cleanup()
	defer closeQuietly(session)
	result := <-observed
	require.Empty(t, result.user)
	require.NotEmpty(t, result.sessionID)
	require.NotEmpty(t, result.clientVersion)
	require.NotEmpty(t, result.serverVersion)
	require.NotEmpty(t, result.localAddr)
	require.NotEmpty(t, result.remoteAddr)
}

func TestConflictingAuthenticationCallbacksAreRejected(t *testing.T) {
	ctx, cancel := newContext(nil)
	defer cancel()
	signer, err := generateSigner()
	require.NoError(t, err)
	srv := &Server{
		PasswordHandler:            func(Context, gossh.ConnMetadata, string) (bool, error) { return true, nil },
		PublicKeyHandler:           func(Context, gossh.ConnMetadata, PublicKey) (bool, error) { return true, nil },
		KeyboardInteractiveHandler: func(Context, gossh.ConnMetadata, gossh.KeyboardInteractiveChallenge) (bool, error) { return true, nil },
		ServerConfigCallback: func(_ Context, _ net.Conn, config *gossh.ServerConfig) error {
			config.PasswordCallback = func(gossh.ConnMetadata, []byte) (*gossh.Permissions, error) { return nil, nil }
			config.PublicKeyCallback = func(gossh.ConnMetadata, gossh.PublicKey) (*gossh.Permissions, error) { return nil, nil }
			config.KeyboardInteractiveCallback = func(gossh.ConnMetadata, gossh.KeyboardInteractiveChallenge) (*gossh.Permissions, error) {
				return nil, nil
			}
			return nil
		},
	}
	config := srv.config(ctx)
	metadata := testConnMetadata{user: "user"}
	_, err = config.PasswordCallback(metadata, nil)
	require.ErrorIs(t, err, ErrServerAuthCallbackConflict)
	_, err = config.PublicKeyCallback(metadata, signer.PublicKey())
	require.ErrorIs(t, err, ErrServerAuthCallbackConflict)
	_, err = config.KeyboardInteractiveCallback(metadata, nil)
	require.ErrorIs(t, err, ErrServerAuthCallbackConflict)
}

func TestConflictingPartialSuccessCallbacksAreRejected(t *testing.T) {
	ctx, cancel := newContext(nil)
	defer cancel()
	srv := &Server{
		PasswordHandler:            func(Context, gossh.ConnMetadata, string) (bool, error) { return true, nil },
		PublicKeyHandler:           func(Context, gossh.ConnMetadata, PublicKey) (bool, error) { return true, nil },
		KeyboardInteractiveHandler: func(Context, gossh.ConnMetadata, gossh.KeyboardInteractiveChallenge) (bool, error) { return true, nil },
		ServerConfigCallback: func(_ Context, _ net.Conn, config *gossh.ServerConfig) error {
			config.GSSAPIWithMICConfig = &gossh.GSSAPIWithMICConfig{AllowLogin: func(gossh.ConnMetadata, string) (*gossh.Permissions, error) {
				return nil, &gossh.PartialSuccessError{Next: gossh.ServerAuthCallbacks{
					PasswordCallback: func(gossh.ConnMetadata, []byte) (*gossh.Permissions, error) {
						return nil, nil
					},
					PublicKeyCallback: func(gossh.ConnMetadata, gossh.PublicKey) (*gossh.Permissions, error) {
						return nil, nil
					},
					KeyboardInteractiveCallback: func(gossh.ConnMetadata, gossh.KeyboardInteractiveChallenge) (*gossh.Permissions, error) {
						return nil, nil
					},
				}}
			}}
			return nil
		},
	}
	config := srv.config(ctx)
	_, err := config.GSSAPIWithMICConfig.AllowLogin(testConnMetadata{user: "user"}, "user@DOMAIN")
	partial := new(gossh.PartialSuccessError)
	require.ErrorAs(t, err, &partial)
	_, err = partial.Next.PasswordCallback(testConnMetadata{user: "user"}, nil)
	require.ErrorIs(t, err, ErrServerAuthCallbackConflict)
	_, err = partial.Next.PublicKeyCallback(testConnMetadata{user: "user"}, nil)
	require.ErrorIs(t, err, ErrServerAuthCallbackConflict)
	_, err = partial.Next.KeyboardInteractiveCallback(testConnMetadata{user: "user"}, nil)
	require.ErrorIs(t, err, ErrServerAuthCallbackConflict)
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
		ServerConfigCallback: func(_ Context, _ net.Conn, config *gossh.ServerConfig) error {
			config.Config = gossh.Config{
				Ciphers:      []string{CipherAes128Ctr.String()},
				KeyExchanges: []string{KeyExchangeEcdh256.String()},
				MACs:         []string{MessageAuthenticationHmacSha2B256.String()},
			}
			return nil
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
		ServerConfigCallback: func(_ Context, _ net.Conn, config *gossh.ServerConfig) error {
			config.Config = expected
			return nil
		},
	}

	config := srv.config(ctx)
	require.Equal(t, expected.Ciphers, config.Ciphers)
	require.Equal(t, expected.KeyExchanges, config.KeyExchanges)
	require.Equal(t, expected.MACs, config.MACs)
}

func TestServerConfigCallbackReceivesFreshConfig(t *testing.T) {
	var configs []*gossh.ServerConfig
	srv := &Server{ServerConfigCallback: func(_ Context, _ net.Conn, config *gossh.ServerConfig) error {
		configs = append(configs, config)
		return nil
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

func TestServerConfigCallbackDoesNotEnableNoClientAuth(t *testing.T) {
	ctx, cancel := newContext(nil)
	defer cancel()
	srv := &Server{
		ServerConfigCallback: func(_ Context, _ net.Conn, config *gossh.ServerConfig) error {
			config.PasswordCallback = func(gossh.ConnMetadata, []byte) (*gossh.Permissions, error) {
				return nil, nil
			}
			return nil
		},
	}

	require.False(t, srv.config(ctx).NoClientAuth)
}

func TestServerConfigCallbackPreservesAnonymousZeroValue(t *testing.T) {
	ctx, cancel := newContext(nil)
	defer cancel()
	srv := &Server{ServerConfigCallback: func(_ Context, _ net.Conn, config *gossh.ServerConfig) error {
		config.MaxAuthTries = 3
		return nil
	}}

	require.True(t, srv.config(ctx).NoClientAuth)
}

func TestCustomAuthenticationCallbackPublishesFinalState(t *testing.T) {
	ctx, cancel := newContext(nil)
	defer cancel()
	srv := &Server{
		ServerConfigCallback: func(_ Context, _ net.Conn, config *gossh.ServerConfig) error {
			config.PasswordCallback = func(gossh.ConnMetadata, []byte) (*gossh.Permissions, error) {
				return &gossh.Permissions{Extensions: map[string]string{"method": "custom"}}, nil
			}
			return nil
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
		ServerConfigCallback: func(_ Context, _ net.Conn, config *gossh.ServerConfig) error {
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
			return nil
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
		ServerConfigCallback: func(_ Context, _ net.Conn, config *gossh.ServerConfig) error {
			config.GSSAPIWithMICConfig = &gossh.GSSAPIWithMICConfig{
				AllowLogin: func(gossh.ConnMetadata, string) (*gossh.Permissions, error) {
					callbackUser = ctx.User()
					return nil, nil
				},
			}
			return nil
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
		PasswordHandler: func(ctx Context, _ gossh.ConnMetadata, _ string) (bool, error) {
			users = append(users, ctx.User())
			ctx.Permissions().Extensions = map[string]string{"user": ctx.User()}
			return ctx.User() == "admin", nil
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
		PublicKeyHandler: func(ctx Context, _ gossh.ConnMetadata, _ PublicKey) (bool, error) {
			ctx.Permissions().Extensions = map[string]string{"method": "public-key"}
			return true, nil
		},
	}
	config := srv.config(ctx)
	metadata := testConnMetadata{user: "user"}

	permissions, err := config.PublicKeyCallback(metadata, key)
	require.NoError(t, err)
	require.Nil(t, ctx.Value(ContextKeyPublicKey))
	verified, err := config.VerifiedPublicKeyCallback(metadata, key, permissions, key.Type())
	require.NoError(t, err)
	config.AuthLogCallback(metadata, "publickey", nil)
	require.Equal(t, key, ctx.Value(ContextKeyPublicKey))
	require.Equal(t, "public-key", verified.Extensions["method"])
}

func TestCustomPublicKeyCallbackPublishesVerifiedKey(t *testing.T) {
	ctx, cancel := newContext(nil)
	defer cancel()
	signer, err := generateSigner()
	require.NoError(t, err)
	key := signer.PublicKey()
	srv := &Server{ServerConfigCallback: func(_ Context, _ net.Conn, config *gossh.ServerConfig) error {
		config.PublicKeyCallback = func(gossh.ConnMetadata, gossh.PublicKey) (*gossh.Permissions, error) {
			return &gossh.Permissions{}, nil
		}
		return nil
	}}
	config := srv.config(ctx)
	metadata := testConnMetadata{user: "user"}

	permissions, err := config.PublicKeyCallback(metadata, key)
	require.NoError(t, err)
	require.Nil(t, ctx.Value(ContextKeyPublicKey))
	_, err = config.VerifiedPublicKeyCallback(metadata, key, permissions, key.Type())
	require.NoError(t, err)
	config.AuthLogCallback(metadata, "publickey", nil)
	require.Equal(t, key, ctx.Value(ContextKeyPublicKey))
}

func TestCustomVerifiedPublicKeyCallbackPublishesReturnedPermissions(t *testing.T) {
	ctx, cancel := newContext(nil)
	defer cancel()
	signer, err := generateSigner()
	require.NoError(t, err)
	replacement := &gossh.Permissions{
		CriticalOptions: map[string]string{"source-address": "127.0.0.1"},
		Extensions:      map[string]string{"role": "admin"},
		ExtraData:       map[any]any{"audit": "verified"},
	}
	srv := &Server{ServerConfigCallback: func(_ Context, _ net.Conn, config *gossh.ServerConfig) error {
		config.PublicKeyCallback = func(gossh.ConnMetadata, gossh.PublicKey) (*gossh.Permissions, error) {
			return &gossh.Permissions{}, nil
		}
		config.VerifiedPublicKeyCallback = func(gossh.ConnMetadata, gossh.PublicKey, *gossh.Permissions, string) (*gossh.Permissions, error) {
			return replacement, nil
		}
		return nil
	}}
	config := srv.config(ctx)
	metadata := testConnMetadata{user: "user"}
	permissions, err := config.PublicKeyCallback(metadata, signer.PublicKey())
	require.NoError(t, err)
	verified, err := config.VerifiedPublicKeyCallback(metadata, signer.PublicKey(), permissions, signer.PublicKey().Type())
	require.NoError(t, err)
	require.Same(t, replacement, verified)
	require.Same(t, replacement, ctx.Permissions().Permissions)
}

func TestPublicKeyPartialSuccessPreservesVerifiedKey(t *testing.T) {
	ctx, cancel := newContext(nil)
	defer cancel()
	signer, err := generateSigner()
	require.NoError(t, err)
	key := signer.PublicKey()
	srv := &Server{ServerConfigCallback: func(_ Context, _ net.Conn, config *gossh.ServerConfig) error {
		config.PublicKeyCallback = func(gossh.ConnMetadata, gossh.PublicKey) (*gossh.Permissions, error) {
			return &gossh.Permissions{}, nil
		}
		config.VerifiedPublicKeyCallback = func(gossh.ConnMetadata, gossh.PublicKey, *gossh.Permissions, string) (*gossh.Permissions, error) {
			return nil, &gossh.PartialSuccessError{Next: gossh.ServerAuthCallbacks{
				PasswordCallback: func(gossh.ConnMetadata, []byte) (*gossh.Permissions, error) {
					return &gossh.Permissions{}, nil
				},
			}}
		}
		return nil
	}}
	config := srv.config(ctx)
	metadata := testConnMetadata{user: "user"}
	permissions, err := config.PublicKeyCallback(metadata, key)
	require.NoError(t, err)
	_, err = config.VerifiedPublicKeyCallback(metadata, key, permissions, key.Type())
	partial := new(gossh.PartialSuccessError)
	require.ErrorAs(t, err, &partial)
	config.AuthLogCallback(metadata, "publickey", err)
	require.Equal(t, key, ctx.Value(ContextKeyPublicKey))
	_, err = partial.Next.PasswordCallback(metadata, []byte("second-factor"))
	require.NoError(t, err)
	config.AuthLogCallback(metadata, "password", nil)
	require.Equal(t, key, ctx.Value(ContextKeyPublicKey))
}

func TestPublicKeyVerificationFailureDoesNotPublishKey(t *testing.T) {
	ctx, cancel := newContext(nil)
	defer cancel()
	signer, err := generateSigner()
	require.NoError(t, err)
	srv := &Server{ServerConfigCallback: func(_ Context, _ net.Conn, config *gossh.ServerConfig) error {
		config.PublicKeyCallback = func(gossh.ConnMetadata, gossh.PublicKey) (*gossh.Permissions, error) {
			return &gossh.Permissions{}, nil
		}
		config.VerifiedPublicKeyCallback = func(gossh.ConnMetadata, gossh.PublicKey, *gossh.Permissions, string) (*gossh.Permissions, error) {
			return nil, ErrServerPermissionDenied
		}
		return nil
	}}
	config := srv.config(ctx)
	metadata := testConnMetadata{user: "user"}
	permissions, err := config.PublicKeyCallback(metadata, signer.PublicKey())
	require.NoError(t, err)
	_, err = config.VerifiedPublicKeyCallback(metadata, signer.PublicKey(), permissions, signer.PublicKey().Type())
	require.ErrorIs(t, err, ErrServerPermissionDenied)
	config.AuthLogCallback(metadata, "publickey", err)
	require.Nil(t, ctx.Value(ContextKeyPublicKey))
}

func TestVerifiedPublicKeyCallbackPreservesNilPermissions(t *testing.T) {
	for _, withPublicKeyHandler := range []bool{false, true} {
		t.Run(fmt.Sprintf("public-key-handler=%t", withPublicKeyHandler), func(t *testing.T) {
			ctx, cancel := newContext(nil)
			defer cancel()
			signer, err := generateSigner()
			require.NoError(t, err)
			srv := &Server{ServerConfigCallback: func(_ Context, _ net.Conn, config *gossh.ServerConfig) error {
				config.VerifiedPublicKeyCallback = func(gossh.ConnMetadata, gossh.PublicKey, *gossh.Permissions, string) (*gossh.Permissions, error) {
					return nil, nil
				}
				if !withPublicKeyHandler {
					config.PublicKeyCallback = func(gossh.ConnMetadata, gossh.PublicKey) (*gossh.Permissions, error) {
						return &gossh.Permissions{}, nil
					}
				}
				return nil
			}}
			if withPublicKeyHandler {
				srv.PublicKeyHandler = func(Context, gossh.ConnMetadata, PublicKey) (bool, error) { return true, nil }
			}
			config := srv.config(ctx)
			metadata := testConnMetadata{user: "user"}
			permissions, err := config.PublicKeyCallback(metadata, signer.PublicKey())
			require.NoError(t, err)
			verified, err := config.VerifiedPublicKeyCallback(metadata, signer.PublicKey(), permissions, signer.PublicKey().Type())
			require.NoError(t, err)
			require.Nil(t, verified)
			require.NotNil(t, ctx.Permissions().Permissions)
		})
	}
}

func TestRejectedVerifiedKeyDoesNotLeakIntoPasswordAuthentication(t *testing.T) {
	ctx, cancel := newContext(nil)
	defer cancel()
	signer, err := generateSigner()
	require.NoError(t, err)
	srv := &Server{
		PasswordHandler: func(Context, gossh.ConnMetadata, string) (bool, error) { return true, nil },
		ServerConfigCallback: func(_ Context, _ net.Conn, config *gossh.ServerConfig) error {
			config.PublicKeyCallback = func(gossh.ConnMetadata, gossh.PublicKey) (*gossh.Permissions, error) {
				return &gossh.Permissions{}, nil
			}
			return nil
		},
	}
	config := srv.config(ctx)
	metadata := testConnMetadata{user: "user"}
	permissions, err := config.PublicKeyCallback(metadata, signer.PublicKey())
	require.NoError(t, err)
	_, err = config.VerifiedPublicKeyCallback(metadata, signer.PublicKey(), permissions, signer.PublicKey().Type())
	require.NoError(t, err)
	config.AuthLogCallback(metadata, "publickey", errors.New("source-address rejected"))
	require.Nil(t, ctx.Value(ContextKeyPublicKey))

	_, err = config.PasswordCallback(metadata, []byte("fallback"))
	require.NoError(t, err)
	config.AuthLogCallback(metadata, "password", nil)
	require.Nil(t, ctx.Value(ContextKeyPublicKey))
}

func TestRejectedVerifiedKeyDoesNotReachPasswordSession(t *testing.T) {
	signer, err := generateSigner()
	require.NoError(t, err)
	publicKeySeen := make(chan bool, 1)
	srv := &Server{
		Handler:         func(s Session) error { publicKeySeen <- s.PublicKey() != nil; return nil },
		PasswordHandler: func(Context, gossh.ConnMetadata, string) (bool, error) { return true, nil },
		ServerConfigCallback: func(_ Context, _ net.Conn, config *gossh.ServerConfig) error {
			config.PublicKeyCallback = func(gossh.ConnMetadata, gossh.PublicKey) (*gossh.Permissions, error) {
				return &gossh.Permissions{}, nil
			}
			config.VerifiedPublicKeyCallback = func(gossh.ConnMetadata, gossh.PublicKey, *gossh.Permissions, string) (*gossh.Permissions, error) {
				return &gossh.Permissions{CriticalOptions: map[string]string{
					"source-address": "192.0.2.1",
				}}, nil
			}
			return nil
		},
	}
	session, _, cleanup := newTestSession(t, srv, &gossh.ClientConfig{
		User: "user",
		Auth: []gossh.AuthMethod{gossh.PublicKeys(signer), gossh.Password("fallback")},
	})
	defer cleanup()
	require.NoError(t, session.Run(""))
	require.False(t, <-publicKeySeen)
}

func TestPartialSuccessNextPublicKeyReachesSession(t *testing.T) {
	signer, err := generateSigner()
	require.NoError(t, err)
	publicKeySeen := make(chan PublicKey, 1)
	srv := &Server{
		Handler: func(s Session) error { publicKeySeen <- s.PublicKey(); return nil },
		ServerConfigCallback: func(_ Context, _ net.Conn, config *gossh.ServerConfig) error {
			config.PasswordCallback = func(gossh.ConnMetadata, []byte) (*gossh.Permissions, error) {
				return nil, &gossh.PartialSuccessError{Next: gossh.ServerAuthCallbacks{
					PublicKeyCallback: func(gossh.ConnMetadata, gossh.PublicKey) (*gossh.Permissions, error) {
						return &gossh.Permissions{}, nil
					},
				}}
			}
			return nil
		},
	}
	session, _, cleanup := newTestSession(t, srv, &gossh.ClientConfig{
		User: "user",
		Auth: []gossh.AuthMethod{gossh.Password("first-factor"), gossh.PublicKeys(signer)},
	})
	defer cleanup()
	require.NoError(t, session.Run(""))
	require.True(t, KeysEqual(signer.PublicKey(), <-publicKeySeen))
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

func TestServerHandshakeTimeout(t *testing.T) {
	l := newLocalListener()
	handshakeTimeout := time.Millisecond

	s := &Server{
		HandshakeTimeout: &handshakeTimeout,
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- s.Serve(ctx, l) }()
	t.Cleanup(func() {
		cancel()
		require.ErrorIs(t, <-serveDone, context.Canceled)
	})

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
			srv := &Server{ConnCallback: func(ctx Context, _ net.Conn) (net.Conn, error) {
				<-ctx.Done()
				return nil, nil
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
				_ = srv.HandleConn(context.Background(), serverConn)
			}()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("timeout did not cancel the connection callback context")
			}
		})
	}
}

func TestHandleConnContextCancelsConnCallback(t *testing.T) {
	disabled := time.Duration(0)
	callbackEntered := make(chan struct{})
	srv := &Server{
		HandshakeTimeout: &disabled,
		ConnCallback: func(ctx Context, _ net.Conn) (net.Conn, error) {
			close(callbackEntered)
			<-ctx.Done()
			return nil, nil
		},
	}
	serverConn, clientConn := net.Pipe()
	defer closeQuietly(clientConn)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- srv.HandleConn(ctx, serverConn)
	}()
	<-callbackEntered
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("context cancellation did not cancel ConnCallback")
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

func TestResourceLimiterUsesParentLimit(t *testing.T) {
	var globalActive, firstActive, secondActive atomic.Int64
	global := &resourceLimiter{limit: 1, active: &globalActive}
	first := &resourceLimiter{limit: 10, active: &firstActive, parent: global}
	second := &resourceLimiter{limit: 10, active: &secondActive, parent: global}

	require.True(t, first.reserve())
	require.False(t, second.reserve())
	require.Zero(t, secondActive.Load())
	first.release()
	require.True(t, second.reserve())
	second.release()
	require.Zero(t, globalActive.Load())
}

func TestMaxStartupsRejectsConnectionsAtFullLimit(t *testing.T) {
	l := newLocalListener()
	firstEntered := make(chan struct{})
	s := &Server{
		MaxStartups: &MaxStartupsConfig{Start: 1, Rate: 0, Full: 1},
		ConnCallback: func(_ Context, conn net.Conn) (net.Conn, error) {
			close(firstEntered)
			return conn, nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- s.Serve(ctx, l) }()

	first, err := net.Dial("tcp", l.Addr().String())
	require.NoError(t, err)
	defer closeQuietly(first)
	<-firstEntered

	second, err := net.Dial("tcp", l.Addr().String())
	require.NoError(t, err)
	defer closeQuietly(second)
	require.NoError(t, second.SetReadDeadline(time.Now().Add(time.Second)))
	_, err = second.Read(make([]byte, 1))
	require.Error(t, err)
	if netErr, ok := errors.AsType[net.Error](err); ok {
		require.False(t, netErr.Timeout(), "connection was not rejected at the startup limit")
	}

	cancel()
	require.ErrorIs(t, <-serveDone, context.Canceled)
}

func TestDisconnectCallbackRunsForAuthenticatedConnectionLimitRejection(t *testing.T) {
	type observation struct {
		user          string
		hasServerConn bool
	}

	maxConnections := 1
	disconnected := make(chan observation, 2)
	s := &Server{
		MaxConnections: &maxConnections,
		DisconnectCallback: func(ctx Context, _ net.Conn) error {
			disconnected <- observation{
				user:          ctx.User(),
				hasServerConn: ctx.Value(ContextKeyConn) != nil,
			}
			return nil
		},
	}
	l := newLocalListener()
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- s.Serve(ctx, l) }()
	var clients []*gossh.Client
	t.Cleanup(func() {
		for _, client := range clients {
			closeQuietly(client)
		}
		cancel()
		select {
		case err := <-serveDone:
			if !errors.Is(err, context.Canceled) {
				t.Errorf("Serve() error = %v; want %v", err, context.Canceled)
			}
		case <-time.After(time.Second):
			t.Error("server did not stop during test cleanup")
		}
	})
	clientConfig := func(user string) *gossh.ClientConfig {
		return &gossh.ClientConfig{User: user, HostKeyCallback: gossh.InsecureIgnoreHostKey()}
	}

	first, err := gossh.Dial("tcp", l.Addr().String(), clientConfig("first"))
	require.NoError(t, err)
	clients = append(clients, first)

	second, _ := gossh.Dial("tcp", l.Addr().String(), clientConfig("second"))
	if second != nil {
		clients = append(clients, second)
		closeQuietly(second)
	}
	select {
	case got := <-disconnected:
		require.Equal(t, "second", got.user)
		require.True(t, got.hasServerConn)
	case <-time.After(time.Second):
		t.Fatal("connection-limit rejection did not invoke disconnect callback")
	}

	require.NoError(t, first.Close())
	select {
	case got := <-disconnected:
		require.Equal(t, "first", got.user)
		require.True(t, got.hasServerConn)
	case <-time.After(time.Second):
		t.Fatal("accepted connection did not invoke disconnect callback")
	}
}

func TestFailedHandshakeRetainsStartupDuringCallback(t *testing.T) {
	l := newLocalListener()
	callbackEntered := make(chan struct{})
	callbackDone := make(chan struct{})
	releaseCallback := make(chan struct{})
	var callbackOnce sync.Once
	var disconnectCalls atomic.Int32
	s := &Server{
		MaxStartups: &MaxStartupsConfig{Start: 1, Full: 1},
		ConnectionFailedCallback: func(Context, net.Conn, error) error {
			callbackOnce.Do(func() {
				close(callbackEntered)
				<-releaseCallback
				close(callbackDone)
			})
			return nil
		},
		DisconnectCallback: func(Context, net.Conn) error { disconnectCalls.Add(1); return nil },
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- s.Serve(ctx, l) }()

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
	require.Zero(t, disconnectCalls.Load())

	second, err := net.Dial("tcp", l.Addr().String())
	require.NoError(t, err)
	defer closeQuietly(second)
	require.NoError(t, second.SetReadDeadline(time.Now().Add(time.Second)))
	version := make([]byte, 4)
	_, err = io.ReadFull(second, version)
	require.Error(t, err)

	close(releaseCallback)
	<-callbackDone
	third, err := net.Dial("tcp", l.Addr().String())
	require.NoError(t, err)
	defer closeQuietly(third)
	require.NoError(t, third.SetReadDeadline(time.Now().Add(time.Second)))
	_, err = io.ReadFull(third, version)
	require.NoError(t, err)
	require.Equal(t, "SSH-", string(version))

	cancel()
	require.ErrorIs(t, <-serveDone, context.Canceled)
}

func TestServeContextClosesConnectionDuringHandshake(t *testing.T) {
	l := newLocalListener()
	callbackEntered := make(chan struct{})
	s := &Server{ConnCallback: func(_ Context, conn net.Conn) (net.Conn, error) {
		close(callbackEntered)
		return conn, nil
	}}
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- s.Serve(ctx, l) }()

	conn, err := net.Dial("tcp", l.Addr().String())
	require.NoError(t, err)
	defer closeQuietly(conn)

	<-callbackEntered
	cancel()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(time.Second)))
	_, err = io.ReadAll(conn)
	if netErr, ok := errors.AsType[net.Error](err); ok {
		require.False(t, netErr.Timeout(), "connection was not closed")
	} else {
		require.NoError(t, err)
	}
	require.ErrorIs(t, <-serveDone, context.Canceled)
}

func TestHandleConnContextRejectsConnCallbackReplacement(t *testing.T) {
	original, originalPeer := net.Pipe()
	replacement, replacementPeer := net.Pipe()
	defer closeQuietly(originalPeer)
	defer closeQuietly(replacementPeer)
	callbackEntered := make(chan struct{})
	releaseCallback := make(chan struct{})
	s := &Server{
		ConnCallback: func(Context, net.Conn) (net.Conn, error) {
			close(callbackEntered)
			<-releaseCallback
			return replacement, nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	handleDone := make(chan error, 1)
	go func() {
		handleDone <- s.HandleConn(ctx, original)
	}()
	<-callbackEntered
	cancel()
	close(releaseCallback)
	select {
	case err := <-handleDone:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("connection callback did not stop after context cancellation")
	}
	_, err := replacementPeer.Read(make([]byte, 1))
	require.Error(t, err)
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
