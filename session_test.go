package ssh

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
)

func (srv *Server) serveOnce(l net.Listener) error {
	srv.ensureHandlers()
	if err := srv.ensureHostSigner(); err != nil {
		return err
	}
	conn, e := l.Accept()
	if e != nil {
		return e
	}
	srv.ChannelHandlers = map[string]ChannelHandler{
		"session":      DefaultSessionHandler,
		"direct-tcpip": DirectTCPIPHandler,
	}
	srv.HandleConn(conn)
	return nil
}

func newLocalListener() net.Listener {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if l, err = net.Listen("tcp6", "[::1]:0"); err != nil {
			panic(fmt.Sprintf("failed to listen on a port: %v", err))
		}
	}
	return l
}

func newClientSession(t *testing.T, addr string, config *gossh.ClientConfig) (*gossh.Session, *gossh.Client, func()) {
	if config == nil {
		config = &gossh.ClientConfig{
			User: "testuser",
			Auth: []gossh.AuthMethod{
				gossh.Password("testpass"),
			},
		}
	}
	if config.HostKeyCallback == nil {
		config.HostKeyCallback = gossh.InsecureIgnoreHostKey()
	}
	client, err := gossh.Dial("tcp", addr, config)
	if err != nil {
		t.Fatal(err)
	}
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	return session, client, func() {
		closeQuietly(session)
		closeQuietly(client)
	}
}

func newTestSession(t *testing.T, srv *Server, cfg *gossh.ClientConfig) (*gossh.Session, *gossh.Client, func()) {
	l := newLocalListener()
	go func() {
		if err := srv.serveOnce(l); err != nil {
			t.Error(err)
		}
	}()
	session, client, cleanup := newClientSession(t, l.Addr().String(), cfg)
	return session, client, func() {
		cleanup()
		closeQuietly(l)
	}
}

func TestStdout(t *testing.T) {
	t.Parallel()
	testBytes := []byte("Hello world\n")
	session, _, cleanup := newTestSession(t, &Server{
		Handler: func(s Session) {
			if _, err := s.Write(testBytes); err != nil {
				t.Error(err)
			}
		},
	}, nil)
	defer cleanup()
	var stdout bytes.Buffer
	session.Stdout = &stdout
	if err := session.Run(""); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stdout.Bytes(), testBytes) {
		t.Fatalf("stdout = %#v; want %#v", stdout.Bytes(), testBytes)
	}
}

func TestStderr(t *testing.T) {
	t.Parallel()
	testBytes := []byte("Hello world\n")
	session, _, cleanup := newTestSession(t, &Server{
		Handler: func(s Session) {
			if _, err := s.Stderr().Write(testBytes); err != nil {
				t.Error(err)
			}
		},
	}, nil)
	defer cleanup()
	var stderr bytes.Buffer
	session.Stderr = &stderr
	if err := session.Run(""); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stderr.Bytes(), testBytes) {
		t.Fatalf("stderr = %#v; want %#v", stderr.Bytes(), testBytes)
	}
}

func TestStdin(t *testing.T) {
	t.Parallel()
	testBytes := []byte("Hello world\n")
	session, _, cleanup := newTestSession(t, &Server{
		Handler: func(s Session) {
			_, _ = io.Copy(s, s) // stdin back into stdout
		},
	}, nil)
	defer cleanup()
	var stdout bytes.Buffer
	session.Stdout = &stdout
	session.Stdin = bytes.NewBuffer(testBytes)
	if err := session.Run(""); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stdout.Bytes(), testBytes) {
		t.Fatalf("stdout = %#v; want %#v given stdin = %#v", stdout.Bytes(), testBytes, testBytes)
	}
}

func TestUser(t *testing.T) {
	t.Parallel()
	testUser := []byte("a_great_user")
	session, _, cleanup := newTestSession(t, &Server{
		Handler: func(s Session) {
			if _, err := io.WriteString(s, s.User()); err != nil {
				t.Error(err)
			}
		},
	}, &gossh.ClientConfig{
		User: string(testUser),
	})
	defer cleanup()
	var stdout bytes.Buffer
	session.Stdout = &stdout
	if err := session.Run(""); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stdout.Bytes(), testUser) {
		t.Fatalf("stdout = %#v; want %#v given user = %#v", stdout.Bytes(), testUser, string(testUser))
	}
}

func TestDefaultExitStatusZero(t *testing.T) {
	t.Parallel()
	session, _, cleanup := newTestSession(t, &Server{
		Handler: func(s Session) {
			// noop
		},
	}, nil)
	defer cleanup()
	err := session.Run("")
	if err != nil {
		t.Fatalf("expected nil but got %v", err)
	}
}

func TestExplicitExitStatusZero(t *testing.T) {
	t.Parallel()
	session, _, cleanup := newTestSession(t, &Server{
		Handler: func(s Session) {
			if err := s.Exit(0); err != nil {
				t.Error(err)
			}
		},
	}, nil)
	defer cleanup()
	err := session.Run("")
	if err != nil {
		t.Fatalf("expected nil but got %v", err)
	}
}

func TestExitStatusNonZero(t *testing.T) {
	t.Parallel()
	session, _, cleanup := newTestSession(t, &Server{
		Handler: func(s Session) {
			if err := s.Exit(1); err != nil {
				t.Error(err)
			}
		},
	}, nil)
	defer cleanup()
	err := session.Run("")
	ee, isEe := errors.AsType[*gossh.ExitError](err)
	if !isEe {
		t.Fatalf("expected ExitError but got %T", err)
	}
	if ee.ExitStatus() != 1 {
		t.Fatalf("exit-status = %#v; want %#v", ee.ExitStatus(), 1)
	}
}

func TestPty(t *testing.T) {
	t.Parallel()
	term := "xterm"
	winWidth := 40
	winHeight := 80
	done := make(chan bool)
	session, _, cleanup := newTestSession(t, &Server{
		Handler: func(s Session) {
			ptyReq, _, isPty := s.Pty()
			if !isPty {
				t.Fatalf("expected pty but none requested")
			}
			if ptyReq.Term != term {
				t.Fatalf("expected term %#v but got %#v", term, ptyReq.Term)
			}
			if ptyReq.Window.Width != winWidth {
				t.Fatalf("expected window width %#v but got %#v", winWidth, ptyReq.Window.Width)
			}
			if ptyReq.Window.Height != winHeight {
				t.Fatalf("expected window height %#v but got %#v", winHeight, ptyReq.Window.Height)
			}
			close(done)
		},
	}, nil)
	defer cleanup()
	if err := session.RequestPty(term, winHeight, winWidth, gossh.TerminalModes{}); err != nil {
		t.Fatalf("expected nil but got %v", err)
	}
	if err := session.Shell(); err != nil {
		t.Fatalf("expected nil but got %v", err)
	}
	<-done
}

func TestPtyResize(t *testing.T) {
	t.Parallel()
	winch0 := Window{40, 80}
	winch1 := Window{80, 160}
	winch2 := Window{20, 40}
	winches := make(chan Window)
	done := make(chan bool)
	session, _, cleanup := newTestSession(t, &Server{
		Handler: func(s Session) {
			ptyReq, winCh, isPty := s.Pty()
			if !isPty {
				t.Fatalf("expected pty but none requested")
			}
			if ptyReq.Window != winch0 {
				t.Fatalf("expected window %#v but got %#v", winch0, ptyReq.Window)
			}
			for win := range winCh {
				winches <- win
			}
			close(done)
		},
	}, nil)
	defer cleanup()
	// winch0
	if err := session.RequestPty("xterm", winch0.Height, winch0.Width, gossh.TerminalModes{}); err != nil {
		t.Fatalf("expected nil but got %v", err)
	}
	if err := session.Shell(); err != nil {
		t.Fatalf("expected nil but got %v", err)
	}
	gotWinch := <-winches
	if gotWinch != winch0 {
		t.Fatalf("expected window %#v but got %#v", winch0, gotWinch)
	}
	// winch1
	winchMsg := struct{ w, h uint32 }{uint32(winch1.Width), uint32(winch1.Height)}
	ok, err := session.SendRequest("window-change", true, gossh.Marshal(&winchMsg))
	if err == nil && !ok {
		t.Fatalf("unexpected error or bad reply on send request")
	}
	gotWinch = <-winches
	if gotWinch != winch1 {
		t.Fatalf("expected window %#v but got %#v", winch1, gotWinch)
	}
	// winch2
	winchMsg = struct{ w, h uint32 }{uint32(winch2.Width), uint32(winch2.Height)}
	ok, err = session.SendRequest("window-change", true, gossh.Marshal(&winchMsg))
	if err == nil && !ok {
		t.Fatalf("unexpected error or bad reply on send request")
	}
	gotWinch = <-winches
	if gotWinch != winch2 {
		t.Fatalf("expected window %#v but got %#v", winch2, gotWinch)
	}
	closeQuietly(session)
	<-done
}

func TestPtyResizeDoesNotBlockWithoutConsumer(t *testing.T) {
	session, _, cleanup := newTestSession(t, &Server{Handler: func(Session) {}}, nil)
	defer cleanup()
	require.NoError(t, session.RequestPty("xterm", 80, 40, gossh.TerminalModes{}))

	result := make(chan error, 1)
	go func() {
		payload := gossh.Marshal(&struct{ Width, Height uint32 }{80, 160})
		ok, err := session.SendRequest("window-change", true, payload)
		if err == nil && !ok {
			err = errors.New("window change rejected")
		}
		result <- err
	}()
	select {
	case err := <-result:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("window change blocked without a consumer")
	}
}

func TestPtyCanBeReadWhileWindowChanges(t *testing.T) {
	started := make(chan struct{})
	session, _, cleanup := newTestSession(t, &Server{Handler: func(s Session) {
		close(started)
		for {
			select {
			case <-s.Context().Done():
				return
			default:
				s.Pty()
			}
		}
	}}, nil)
	defer cleanup()
	require.NoError(t, session.RequestPty("xterm", 80, 40, gossh.TerminalModes{}))
	require.NoError(t, session.Shell())
	<-started
	for i := range 100 {
		payload := gossh.Marshal(&struct{ Width, Height uint32 }{uint32(80 + i), 160})
		ok, err := session.SendRequest("window-change", true, payload)
		require.NoError(t, err)
		require.True(t, ok)
	}
}

func TestSignalsUnregisterStopsBufferedDrain(t *testing.T) {
	ctx, cancel := newContext(nil)
	defer cancel()
	sess := &session{ctx: ctx, sigBuf: []Signal{SIGINT, SIGTERM}}
	blocked := make(chan Signal)
	sess.Signals(blocked)
	sess.Signals(nil)

	signals := make(chan Signal, 2)
	sess.Signals(signals)
	require.Equal(t, SIGINT, <-signals)
	require.Equal(t, SIGTERM, <-signals)
}

func TestBreakUnregisterStopsDelivery(t *testing.T) {
	ctx, cancel := newContext(nil)
	defer cancel()
	sess := &session{ctx: ctx}
	blocked := make(chan bool)
	sess.Break(blocked)
	result := make(chan bool, 1)
	go func() { result <- sess.deliverBreak() }()
	require.Eventually(t, func() bool {
		sess.Lock()
		defer sess.Unlock()
		return sess.breakSends == 1
	}, time.Second, time.Millisecond)
	sess.Break(nil)
	require.False(t, <-result)
	close(blocked)
}

func TestSessionEnvironmentIsLimited(t *testing.T) {
	session, _, cleanup := newTestSession(t, &Server{Handler: func(Session) {}}, nil)
	defer cleanup()
	for i := range maxSessionEnvVariables {
		require.NoError(t, session.Setenv(fmt.Sprintf("KEY_%d", i), "value"))
	}
	require.Error(t, session.Setenv("ONE_TOO_MANY", "value"))
}

func TestRejectedSubsystemDoesNotLeakIntoShell(t *testing.T) {
	session, _, cleanup := newTestSession(t, &Server{
		Handler: func(s Session) {
			_, _ = io.WriteString(s, s.Subsystem())
		},
		SessionRequestCallback: func(_ Session, requestType string) bool { return requestType != "subsystem" },
	}, nil)
	defer cleanup()
	var stdout bytes.Buffer
	session.Stdout = &stdout
	require.Error(t, session.RequestSubsystem("forbidden"))
	require.NoError(t, session.Run(""))
	require.Empty(t, stdout.String())
}

func TestUnknownSubsystemDoesNotLeakIntoShell(t *testing.T) {
	session, _, cleanup := newTestSession(t, &Server{Handler: func(s Session) {
		_, _ = io.WriteString(s, s.Subsystem())
	}}, nil)
	defer cleanup()
	var stdout bytes.Buffer
	session.Stdout = &stdout
	require.Error(t, session.RequestSubsystem("unknown"))
	require.NoError(t, session.Run(""))
	require.Empty(t, stdout.String())
}

func TestDefaultMaxSessionsPerConnection(t *testing.T) {
	first, client, cleanup := newTestSession(t, &Server{Handler: func(Session) {}}, nil)
	defer cleanup()
	sessions := []*gossh.Session{first}
	defer func() {
		for _, session := range sessions {
			closeQuietly(session)
		}
	}()
	for range DefaultMaxSessionsPerConnection - 1 {
		session, err := client.NewSession()
		require.NoError(t, err)
		sessions = append(sessions, session)
	}
	_, err := client.NewSession()
	require.Error(t, err)
}

func TestMaxSessionsCanBeDisabled(t *testing.T) {
	disabled := 0
	first, client, cleanup := newTestSession(t, &Server{
		Handler:                  func(Session) {},
		MaxSessionsPerConnection: &disabled,
	}, nil)
	defer cleanup()
	sessions := []*gossh.Session{first}
	defer func() {
		for _, session := range sessions {
			closeQuietly(session)
		}
	}()
	for range DefaultMaxSessionsPerConnection {
		session, err := client.NewSession()
		require.NoError(t, err)
		sessions = append(sessions, session)
	}
}

func TestMaxChannelsPerConnection(t *testing.T) {
	maxChannels := 1
	disabledSessions := 0
	first, client, cleanup := newTestSession(t, &Server{
		Handler:                  func(Session) {},
		MaxSessionsPerConnection: &disabledSessions,
		MaxChannelsPerConnection: &maxChannels,
	}, nil)
	defer cleanup()
	defer closeQuietly(first)
	_, err := client.NewSession()
	require.Error(t, err)
	require.NoError(t, first.Close())
	var second *gossh.Session
	require.Eventually(t, func() bool {
		var err error
		second, err = client.NewSession()
		return err == nil
	}, time.Second, time.Millisecond)
	closeQuietly(second)
}

func TestSignals(t *testing.T) {
	t.Parallel()

	// errChan lets us get errors back from the session
	errChan := make(chan error, 5)

	// doneChan lets us specify that we should exit.
	doneChan := make(chan interface{})

	session, _, cleanup := newTestSession(t, &Server{
		Handler: func(s Session) {
			// We need to use a buffered channel here, otherwise it's possible for the
			// second call to Signal to get discarded.
			signals := make(chan Signal, 2)
			s.Signals(signals)

			select {
			case sig := <-signals:
				if sig != SIGINT {
					errChan <- fmt.Errorf("expected signal %v but got %v", SIGINT, sig)
					return
				}
			case <-doneChan:
				errChan <- fmt.Errorf("unexpected done")
				return
			}

			select {
			case sig := <-signals:
				if sig != SIGKILL {
					errChan <- fmt.Errorf("expected signal %v but got %v", SIGKILL, sig)
					return
				}
			case <-doneChan:
				errChan <- fmt.Errorf("unexpected done")
				return
			}
		},
	}, nil)
	defer cleanup()

	go func() {
		if err := session.Signal(gossh.SIGINT); err != nil {
			errChan <- err
			return
		}
		if err := session.Signal(gossh.SIGKILL); err != nil {
			errChan <- err
		}
	}()

	go func() {
		errChan <- session.Run("")
	}()

	err := <-errChan
	close(doneChan)

	if err != nil {
		t.Fatalf("expected nil but got %v", err)
	}
}

func TestBreakWithChanRegistered(t *testing.T) {
	t.Parallel()

	// errChan lets us get errors back from the session
	errChan := make(chan error, 5)

	// doneChan lets us specify that we should exit.
	doneChan := make(chan interface{})

	breakChan := make(chan bool)

	readyToReceiveBreak := make(chan bool)

	session, _, cleanup := newTestSession(t, &Server{
		Handler: func(s Session) {
			s.Break(breakChan) // register a break channel with the session
			readyToReceiveBreak <- true

			select {
			case <-breakChan:
				if _, err := io.WriteString(s, "break"); err != nil {
					errChan <- err
					return
				}
			case <-doneChan:
				errChan <- fmt.Errorf("unexpected done")
				return
			}
		},
	}, nil)
	defer cleanup()
	var stdout bytes.Buffer
	session.Stdout = &stdout
	go func() {
		errChan <- session.Run("")
	}()

	<-readyToReceiveBreak
	ok, err := session.SendRequest("break", true, nil)
	if err != nil {
		t.Fatalf("expected nil but got %v", err)
	}
	if ok != true {
		t.Fatalf("expected true but got %v", ok)
	}

	err = <-errChan
	close(doneChan)

	if err != nil {
		t.Fatalf("expected nil but got %v", err)
	}
	if !bytes.Equal(stdout.Bytes(), []byte("break")) {
		t.Fatalf("stdout = %#v, expected 'break'", stdout.Bytes())
	}
}

func TestBreakWithoutChanRegistered(t *testing.T) {
	t.Parallel()

	// errChan lets us get errors back from the session
	errChan := make(chan error, 5)

	// doneChan lets us specify that we should exit.
	doneChan := make(chan interface{})

	waitUntilAfterBreakSent := make(chan bool)

	session, _, cleanup := newTestSession(t, &Server{
		Handler: func(s Session) {
			<-waitUntilAfterBreakSent
		},
	}, nil)
	defer cleanup()
	var stdout bytes.Buffer
	session.Stdout = &stdout
	go func() {
		errChan <- session.Run("")
	}()

	ok, err := session.SendRequest("break", true, nil)
	if err != nil {
		t.Fatalf("expected nil but got %v", err)
	}
	if ok != false {
		t.Fatalf("expected false but got %v", ok)
	}
	waitUntilAfterBreakSent <- true

	err = <-errChan
	close(doneChan)
	if err != nil {
		t.Fatalf("expected nil but got %v", err)
	}
}
