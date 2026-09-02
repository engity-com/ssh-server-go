package ssh

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
)

func TestProxyProtocolReportsHeaderAddresses(t *testing.T) {
	for _, version := range []byte{1, 2} {
		t.Run(string(rune('0'+version)), func(t *testing.T) {
			source := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 4242}
			destination := &net.TCPAddr{IP: net.ParseIP("198.51.100.20"), Port: 22}
			policyOptions := make(chan proxyproto.ConnPolicyOptions, 1)
			validated := make(chan *proxyproto.Header, 1)
			type addresses struct {
				remote        string
				local         string
				contextRemote string
				contextLocal  string
			}
			observed := make(chan addresses, 1)
			callbackRemote := make(chan string, 1)
			failures := make(chan error, 1)
			srv := &Server{
				ProxyProtocol: &ProxyProtocolConfig{
					ConnPolicy: func(options proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
						policyOptions <- options
						return proxyproto.REQUIRE, nil
					},
					ValidateHeader: func(header *proxyproto.Header) error {
						validated <- header
						return nil
					},
					ReadHeaderTimeout: time.Second,
					ReadBufferSize:    512,
				},
				ConnCallback: func(_ Context, conn net.Conn) net.Conn {
					callbackRemote <- conn.RemoteAddr().String()
					return conn
				},
				ConnectionFailedCallback: func(_ net.Conn, err error) {
					failures <- err
				},
				Handler: func(session Session) {
					observed <- addresses{
						remote:        session.RemoteAddr().String(),
						local:         session.LocalAddr().String(),
						contextRemote: session.Context().RemoteAddr().String(),
						contextLocal:  session.Context().LocalAddr().String(),
					}
				},
			}
			listener := newLocalListener()
			serveDone := make(chan error, 1)
			go func() { serveDone <- srv.Serve(listener) }()
			t.Cleanup(func() {
				_ = srv.Close()
				if err := <-serveDone; !errors.Is(err, ErrServerClosed) {
					t.Errorf("Serve() error = %v; want %v", err, ErrServerClosed)
				}
			})

			rawConn, err := net.Dial("tcp", listener.Addr().String())
			require.NoError(t, err)
			t.Cleanup(func() { closeQuietly(rawConn) })
			header := &proxyproto.Header{
				Version:           version,
				Command:           proxyproto.PROXY,
				TransportProtocol: proxyproto.TCPv4,
				SourceAddr:        source,
				DestinationAddr:   destination,
			}
			_, err = header.WriteTo(rawConn)
			require.NoError(t, err)

			clientConn, channels, requests, err := gossh.NewClientConn(rawConn, listener.Addr().String(), &gossh.ClientConfig{
				User:            "testuser",
				HostKeyCallback: gossh.InsecureIgnoreHostKey(),
			})
			require.NoError(t, err)
			client := gossh.NewClient(clientConn, channels, requests)
			t.Cleanup(func() { closeQuietly(client) })
			session, err := client.NewSession()
			require.NoError(t, err)
			require.NoError(t, session.Run(""))

			require.Equal(t, source.String(), <-callbackRemote)
			got := <-observed
			require.Equal(t, source.String(), got.remote)
			require.Equal(t, destination.String(), got.local)
			require.Equal(t, source.String(), got.contextRemote)
			require.Equal(t, destination.String(), got.contextLocal)
			policy := <-policyOptions
			require.Equal(t, listener.Addr().String(), policy.Downstream.String())
			require.NotEqual(t, source.String(), policy.Upstream.String())
			require.Equal(t, header.SourceAddr.String(), (<-validated).SourceAddr.String())
			select {
			case failure := <-failures:
				t.Fatalf("unexpected connection failure: %v", failure)
			default:
			}
		})
	}
}

func TestProxyProtocolConnPolicyCanSkipHeaderProcessing(t *testing.T) {
	var policyCalls atomic.Int32
	var validatorCalls atomic.Int32
	session, _, cleanup := newTestSession(t, &Server{
		ProxyProtocol: &ProxyProtocolConfig{
			ConnPolicy: func(proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
				policyCalls.Add(1)
				return proxyproto.SKIP, nil
			},
			ValidateHeader: func(*proxyproto.Header) error {
				validatorCalls.Add(1)
				return nil
			},
		},
		Handler: func(Session) {},
	}, nil)
	defer cleanup()
	require.NoError(t, session.Run(""))
	require.Equal(t, int32(1), policyCalls.Load())
	require.Zero(t, validatorCalls.Load())
}

func TestProxyProtocolConnPolicyRejectsConnection(t *testing.T) {
	expected := errors.New("untrusted proxy")
	failure := make(chan error, 1)
	srv := &Server{
		ProxyProtocol: &ProxyProtocolConfig{ConnPolicy: func(proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
			return proxyproto.REJECT, expected
		}},
		ConnectionFailedCallback: func(_ net.Conn, err error) { failure <- err },
	}
	serverConn, clientConn := net.Pipe()
	defer closeQuietly(clientConn)
	srv.HandleConn(serverConn)
	require.ErrorIs(t, <-failure, expected)
	_ = clientConn.SetReadDeadline(time.Now().Add(time.Second))
	_, err := clientConn.Read(make([]byte, 1))
	require.Error(t, err)
}

func TestProxyProtocolRejectPolicyRejectsHeader(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer closeQuietly(clientConn)
	wrapped, err := wrapProxyProtocolConn(serverConn, ProxyProtocolConfig{ConnPolicy: func(proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
		return proxyproto.REJECT, nil
	}})
	require.NoError(t, err)
	writeDone := make(chan error, 1)
	go func() {
		_, err := (&proxyproto.Header{
			Version:           1,
			Command:           proxyproto.PROXY,
			TransportProtocol: proxyproto.TCPv4,
			SourceAddr:        &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 4242},
			DestinationAddr:   &net.TCPAddr{IP: net.ParseIP("198.51.100.20"), Port: 22},
		}).WriteTo(clientConn)
		writeDone <- err
	}()
	_, err = wrapped.Read(make([]byte, 1))
	require.ErrorIs(t, err, proxyproto.ErrSuperfluousProxyHeader)
	require.NoError(t, <-writeDone)
}

func TestProxyProtocolValidatorRejectsHeader(t *testing.T) {
	expected := errors.New("invalid proxy metadata")
	var callbackCalls atomic.Int32
	failure := make(chan error, 1)
	srv := &Server{
		ProxyProtocol: &ProxyProtocolConfig{ValidateHeader: func(*proxyproto.Header) error {
			return expected
		}},
		ConnCallback: func(_ Context, conn net.Conn) net.Conn {
			callbackCalls.Add(1)
			return conn
		},
		ConnectionFailedCallback: func(_ net.Conn, err error) { failure <- err },
	}
	serverConn, clientConn := net.Pipe()
	defer closeQuietly(clientConn)
	t.Cleanup(func() { _ = srv.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.HandleConn(serverConn)
	}()
	writeDone := make(chan error, 1)
	go func() {
		_, err := (&proxyproto.Header{
			Version:           2,
			Command:           proxyproto.PROXY,
			TransportProtocol: proxyproto.TCPv4,
			SourceAddr:        &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 4242},
			DestinationAddr:   &net.TCPAddr{IP: net.ParseIP("198.51.100.20"), Port: 22},
		}).WriteTo(clientConn)
		writeDone <- err
	}()
	require.ErrorIs(t, <-failure, expected)
	require.NoError(t, <-writeDone)
	<-done
	require.Equal(t, int32(1), callbackCalls.Load())
}

func TestProxyProtocolReadHeaderTimeout(t *testing.T) {
	failure := make(chan error, 1)
	srv := &Server{
		ProxyProtocol:            &ProxyProtocolConfig{ReadHeaderTimeout: 20 * time.Millisecond},
		ConnectionFailedCallback: func(_ net.Conn, err error) { failure <- err },
	}
	serverConn, clientConn := net.Pipe()
	defer closeQuietly(clientConn)
	t.Cleanup(func() { _ = srv.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.HandleConn(serverConn)
	}()
	select {
	case err := <-failure:
		require.ErrorIs(t, err, proxyproto.ErrNoProxyProtocol)
	case <-time.After(time.Second):
		t.Fatal("PROXY header timeout did not reject the connection")
	}
	<-done
}

func TestProxyProtocolHonorsEarlierHandshakeTimeout(t *testing.T) {
	headerTimeout := time.Second
	handshakeTimeout := 20 * time.Millisecond
	failure := make(chan error, 1)
	srv := &Server{
		ProxyProtocol:            &ProxyProtocolConfig{ReadHeaderTimeout: headerTimeout},
		HandshakeTimeout:         &handshakeTimeout,
		ConnectionFailedCallback: func(_ net.Conn, err error) { failure <- err },
	}
	serverConn, clientConn := net.Pipe()
	defer closeQuietly(clientConn)
	started := time.Now()
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.HandleConn(serverConn)
	}()
	select {
	case err := <-failure:
		require.Error(t, err)
		require.Less(t, time.Since(started), headerTimeout)
	case <-time.After(time.Second):
		t.Fatal("SSH handshake timeout did not stop PROXY header processing")
	}
	<-done
}

func TestServerCloseStopsProxyProtocolHeaderRead(t *testing.T) {
	disabledTimeout := time.Duration(0)
	srv := &Server{
		ProxyProtocol:    &ProxyProtocolConfig{ReadHeaderTimeout: -1},
		HandshakeTimeout: &disabledTimeout,
	}
	serverConn, clientConn := net.Pipe()
	defer closeQuietly(clientConn)
	t.Cleanup(func() { _ = srv.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.HandleConn(serverConn)
	}()
	require.Eventually(t, func() bool {
		srv.mu.RLock()
		defer srv.mu.RUnlock()
		return len(srv.activeConns) == 1
	}, time.Second, time.Millisecond)
	writeDone := make(chan error, 1)
	go func() {
		_, err := clientConn.Write([]byte("PROXY "))
		writeDone <- err
	}()
	select {
	case err := <-writeDone:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("PROXY header processing did not start")
	}
	require.NoError(t, srv.Close())
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Server.Close did not stop PROXY header processing")
	}
	srv.mu.RLock()
	require.Empty(t, srv.activeConns)
	srv.mu.RUnlock()
}

func TestProxyProtocolRejectsAlreadyWrappedConnection(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer closeQuietly(clientConn)
	alreadyWrapped := proxyproto.NewConn(serverConn)
	wrapped, err := wrapProxyProtocolConn(alreadyWrapped, ProxyProtocolConfig{})
	require.ErrorIs(t, err, errProxyProtocolAlreadyWrapped)
	require.Nil(t, wrapped)
	closeQuietly(alreadyWrapped)
}

func TestEnableProxyProtocolOption(t *testing.T) {
	srv := &Server{}
	require.NoError(t, srv.SetOption(EnableProxyProtocol()))
	require.Equal(t, &ProxyProtocolConfig{}, srv.ProxyProtocol)

	config := ProxyProtocolConfig{ReadHeaderTimeout: time.Second, ReadBufferSize: 512}
	srv = &Server{}
	require.NoError(t, srv.SetOption(EnableProxyProtocol(config)))
	config.ReadBufferSize = 1024
	require.Equal(t, time.Second, srv.ProxyProtocol.ReadHeaderTimeout)
	require.Equal(t, 512, srv.ProxyProtocol.ReadBufferSize)
	require.NoError(t, srv.SetOption(EnableProxyProtocol()))
	require.Equal(t, &ProxyProtocolConfig{}, srv.ProxyProtocol)

	srv = &Server{}
	err := srv.SetOption(EnableProxyProtocol(ProxyProtocolConfig{}, ProxyProtocolConfig{}))
	require.Error(t, err)
	require.Nil(t, srv.ProxyProtocol)
}

func TestProxyProtocolConfigIsSnapshotted(t *testing.T) {
	srv := &Server{
		ProxyProtocol: &ProxyProtocolConfig{ReadHeaderTimeout: time.Second, ReadBufferSize: 512},
	}
	settings := srv.connectionSettings()
	srv.ProxyProtocol.ReadHeaderTimeout = 2 * time.Second
	srv.ProxyProtocol.ReadBufferSize = 1024
	srv.ProxyProtocol = nil
	require.NotNil(t, settings.proxyProtocol)
	require.Equal(t, time.Second, settings.proxyProtocol.ReadHeaderTimeout)
	require.Equal(t, 512, settings.proxyProtocol.ReadBufferSize)
}
