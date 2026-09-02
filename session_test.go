package ssh

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
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
		"session":                        DefaultSessionHandler,
		"direct-tcpip":                   DirectTCPIPHandler,
		"direct-streamlocal@openssh.com": DirectStreamLocalHandler,
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
	wantWindow := Window{Width: 40, Height: 80, WidthPixels: 320, HeightPixels: 640}
	terminalModes := gossh.TerminalModes{
		gossh.ECHO:          1,
		gossh.IUTF8:         1,
		gossh.TTY_OP_OSPEED: 38400,
	}
	type handlerResult struct {
		pty   Pty
		isPty bool
	}
	result := make(chan handlerResult, 1)
	session, _, cleanup := newTestSession(t, &Server{
		PtyCallback: func(_ Context, pty Pty) bool {
			pty.TerminalModes[gossh.ECHO] = 0
			return true
		},
		Handler: func(s Session) {
			ptyReq, _, isPty := s.Pty()
			result <- handlerResult{pty: ptyReq, isPty: isPty}
		},
	}, nil)
	defer cleanup()
	encodedModes := appendTerminalMode(nil, gossh.ECHO, terminalModes[gossh.ECHO])
	encodedModes = appendTerminalMode(encodedModes, gossh.IUTF8, terminalModes[gossh.IUTF8])
	encodedModes = appendTerminalMode(encodedModes, gossh.TTY_OP_OSPEED, terminalModes[gossh.TTY_OP_OSPEED])
	encodedModes = append(encodedModes, 0)
	ok, err := session.SendRequest("pty-req", true, marshalPtyRequest(term, wantWindow, encodedModes))
	require.NoError(t, err)
	require.True(t, ok)
	if err := session.Shell(); err != nil {
		t.Fatalf("expected nil but got %v", err)
	}
	got := <-result
	require.True(t, got.isPty)
	require.Equal(t, term, got.pty.Term)
	require.Equal(t, wantWindow, got.pty.Window)
	require.True(t, maps.Equal(terminalModes, got.pty.TerminalModes))
}

func TestPtyReturnsTerminalModesCopy(t *testing.T) {
	sess := &session{pty: &Pty{TerminalModes: gossh.TerminalModes{gossh.ECHO: 1}}}
	first, _, ok := sess.Pty()
	require.True(t, ok)
	first.TerminalModes[gossh.ECHO] = 0

	second, _, ok := sess.Pty()
	require.True(t, ok)
	require.Equal(t, uint32(1), second.TerminalModes[gossh.ECHO])
}

func TestPtyTerminalModesAreMetadataOnly(t *testing.T) {
	type handlerResult struct {
		pty Pty
		ok  bool
		err error
	}
	run := func(modes gossh.TerminalModes) string {
		result := make(chan handlerResult, 1)
		session, _, cleanup := newTestSession(t, &Server{Handler: func(s Session) {
			pty, _, ok := s.Pty()
			_, err := io.WriteString(s, "line\n")
			result <- handlerResult{pty: pty, ok: ok, err: err}
		}}, nil)
		defer cleanup()

		var stdout bytes.Buffer
		session.Stdout = &stdout
		require.NoError(t, session.RequestPty("xterm", 24, 80, modes))
		require.NoError(t, session.Run(""))
		got := <-result
		require.True(t, got.ok)
		require.True(t, maps.Equal(modes, got.pty.TerminalModes))
		require.NoError(t, got.err)
		return stdout.String()
	}

	baseline := run(nil)
	disabledOutputProcessing := run(gossh.TerminalModes{gossh.OPOST: 0, gossh.ONLCR: 0})
	require.Equal(t, "line\r\n", baseline)
	require.Equal(t, baseline, disabledOutputProcessing)
}

func TestPtyRejectsMalformedTerminalModesBeforeCallback(t *testing.T) {
	callbackCalled := make(chan struct{}, 1)
	session, _, cleanup := newTestSession(t, &Server{
		Handler: func(Session) {},
		PtyCallback: func(Context, Pty) bool {
			callbackCalled <- struct{}{}
			return true
		},
	}, nil)
	defer cleanup()

	ok, err := session.SendRequest("pty-req", true, marshalPtyRequest("xterm", Window{Width: 80, Height: 24}, []byte{gossh.ECHO}))
	require.NoError(t, err)
	require.False(t, ok)
	select {
	case <-callbackCalled:
		t.Fatal("PTY callback was called for malformed terminal modes")
	default:
	}
}

func TestPtyResize(t *testing.T) {
	t.Parallel()
	winch0 := Window{Width: 40, Height: 80, WidthPixels: 320, HeightPixels: 640}
	winch1 := Window{Width: 80, Height: 160, WidthPixels: 640, HeightPixels: 1280}
	winch2 := Window{Width: 20, Height: 40, WidthPixels: 160, HeightPixels: 320}
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
	ok, err := session.SendRequest("pty-req", true, marshalPtyRequest("xterm", winch0, []byte{0}))
	require.NoError(t, err)
	require.True(t, ok)
	if err := session.Shell(); err != nil {
		t.Fatalf("expected nil but got %v", err)
	}
	gotWinch := <-winches
	if gotWinch != winch0 {
		t.Fatalf("expected window %#v but got %#v", winch0, gotWinch)
	}
	// winch1
	ok, err = session.SendRequest("window-change", true, marshalWindow(winch1))
	require.NoError(t, err)
	require.True(t, ok)
	gotWinch = <-winches
	if gotWinch != winch1 {
		t.Fatalf("expected window %#v but got %#v", winch1, gotWinch)
	}
	// winch2
	require.NoError(t, session.WindowChange(winch2.Height, winch2.Width))
	gotWinch = <-winches
	if gotWinch != winch2 {
		t.Fatalf("expected window %#v but got %#v", winch2, gotWinch)
	}
	closeQuietly(session)
	<-done
}

func TestPtyResizeCoalescesWithoutConsumer(t *testing.T) {
	serverSession := make(chan Session, 1)
	windowChanges := make(chan (<-chan Window), 1)
	session, _, cleanup := newTestSession(t, &Server{Handler: func(s Session) {
		_, winch, _ := s.Pty()
		serverSession <- s
		windowChanges <- winch
		<-s.Context().Done()
	}}, nil)
	defer cleanup()
	require.NoError(t, session.RequestPty("xterm", 80, 40, gossh.TerminalModes{}))
	require.NoError(t, session.Shell())
	sess := <-serverSession
	winch := <-windowChanges

	result := make(chan error, 1)
	go func() {
		for _, update := range []Window{
			{Width: 80, Height: 160, WidthPixels: 640, HeightPixels: 1280},
			{Height: 200, HeightPixels: 1440},
		} {
			ok, err := session.SendRequest("window-change", true, marshalWindow(update))
			if err != nil {
				result <- err
				return
			}
			if !ok {
				result <- errors.New("window change rejected")
				return
			}
		}
		result <- nil
	}()
	select {
	case err := <-result:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("window change blocked without a consumer")
	}

	want := Window{Width: 80, Height: 200, WidthPixels: 640, HeightPixels: 1440}
	require.Equal(t, want, <-winch)
	pty, _, ok := sess.Pty()
	require.True(t, ok)
	require.Equal(t, want, pty.Window)
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
		payload := marshalWindow(Window{Width: 80 + i, Height: 160})
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

func TestClosedSignalChannelPreservesBufferedSignals(t *testing.T) {
	ctx, cancel := newContext(nil)
	defer cancel()
	sess := &session{ctx: ctx, sigBuf: []Signal{SIGINT, SIGTERM}}
	closedSignals := make(chan Signal)
	close(closedSignals)
	sess.Signals(closedSignals)
	require.Eventually(t, func() bool {
		sess.Lock()
		defer sess.Unlock()
		return sess.sigDrainDone == nil && len(sess.sigBuf) == 2
	}, time.Second, time.Millisecond)

	signals := make(chan Signal, 2)
	sess.Signals(signals)
	require.Equal(t, SIGINT, <-signals)
	require.Equal(t, SIGTERM, <-signals)
}

func TestSignalRequestsReceiveReplies(t *testing.T) {
	ready := make(chan struct{})
	release := make(chan struct{})
	session, _, cleanup := newTestSession(t, &Server{Handler: func(s Session) {
		s.Signals(make(chan Signal, 1))
		close(ready)
		<-release
	}}, nil)
	defer cleanup()
	runResult := make(chan error, 1)
	go func() { runResult <- session.Run("") }()
	<-ready

	ok, err := session.SendRequest("signal", true, gossh.Marshal(&struct{ Signal string }{string(SIGINT)}))
	require.NoError(t, err)
	require.True(t, ok)
	ok, err = session.SendRequest("signal", true, []byte{0, 0, 0, 5, 'x'})
	require.NoError(t, err)
	require.False(t, ok)
	close(release)
	require.NoError(t, <-runResult)
}

func TestHandlerExitCancelsBlockedSignalDelivery(t *testing.T) {
	ready := make(chan struct{})
	release := make(chan struct{})
	serverSession := make(chan *session, 1)
	session, _, cleanup := newTestSession(t, &Server{Handler: func(s Session) {
		s.Signals(make(chan Signal))
		serverSession <- s.(*session)
		close(ready)
		<-release
	}}, nil)
	defer cleanup()
	runResult := make(chan error, 1)
	go func() { runResult <- session.Run("") }()
	<-ready
	type requestResult struct {
		ok  bool
		err error
	}
	signalResult := make(chan requestResult, 1)
	go func() {
		ok, err := session.SendRequest("signal", true, gossh.Marshal(&struct{ Signal string }{string(SIGTERM)}))
		signalResult <- requestResult{ok: ok, err: err}
	}()
	internal := <-serverSession
	require.Eventually(t, func() bool {
		internal.Lock()
		defer internal.Unlock()
		return internal.sigSends == 1
	}, time.Second, time.Millisecond)
	close(release)
	result := <-signalResult
	require.NoError(t, result.err)
	require.False(t, result.ok)
	require.NoError(t, <-runResult)
}

func TestDeliveredSignalReplyPrecedesHandlerExit(t *testing.T) {
	ready := make(chan struct{})
	session, _, cleanup := newTestSession(t, &Server{Handler: func(s Session) {
		signals := make(chan Signal)
		s.Signals(signals)
		close(ready)
		<-signals
	}}, nil)
	defer cleanup()
	runResult := make(chan error, 1)
	go func() { runResult <- session.Run("") }()
	<-ready
	ok, err := session.SendRequest("signal", true, gossh.Marshal(&struct{ Signal string }{string(SIGTERM)}))
	require.NoError(t, err)
	require.True(t, ok)
	require.NoError(t, <-runResult)
}

func TestSignalsCannotBeRegisteredAfterExitStarts(t *testing.T) {
	ctx, cancel := newContext(nil)
	defer cancel()
	sess := &session{ctx: ctx}
	sess.exiting.Store(true)
	sess.Signals(make(chan Signal))
	sess.Lock()
	defer sess.Unlock()
	require.Nil(t, sess.sigCh)
}

func TestClosedSignalChannelRejectsRequestWithoutPanic(t *testing.T) {
	ready := make(chan struct{})
	release := make(chan struct{})
	session, _, cleanup := newTestSession(t, &Server{Handler: func(s Session) {
		signals := make(chan Signal)
		s.Signals(signals)
		close(signals)
		close(ready)
		<-release
	}}, nil)
	defer cleanup()
	runResult := make(chan error, 1)
	go func() { runResult <- session.Run("") }()
	<-ready
	ok, err := session.SendRequest("signal", true, gossh.Marshal(&struct{ Signal string }{string(SIGTERM)}))
	require.NoError(t, err)
	require.False(t, ok)
	close(release)
	require.NoError(t, <-runResult)
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

func TestClosedBreakChannelRejectsRequestWithoutPanic(t *testing.T) {
	ready := make(chan struct{})
	release := make(chan struct{})
	session, _, cleanup := newTestSession(t, &Server{Handler: func(s Session) {
		breaks := make(chan bool)
		s.Break(breaks)
		close(breaks)
		close(ready)
		<-release
	}}, nil)
	defer cleanup()
	runResult := make(chan error, 1)
	go func() { runResult <- session.Run("") }()
	<-ready
	ok, err := session.SendRequest("break", true, nil)
	require.NoError(t, err)
	require.False(t, ok)
	close(release)
	require.NoError(t, <-runResult)
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

func TestSessionPermissionsReturnsIndependentCopy(t *testing.T) {
	ctx, cancel := newContext(nil)
	defer cancel()
	original := &gossh.Permissions{
		CriticalOptions: map[string]string{"source-address": "127.0.0.1"},
		Extensions:      map[string]string{"role": "admin"},
		ExtraData:       map[any]any{"audit": "original"},
	}
	ctx.SetValue(ContextKeyPermissions, &Permissions{Permissions: original})
	sess := &session{ctx: ctx}

	copy := sess.Permissions()
	require.NotSame(t, original, copy.Permissions)
	copy.CriticalOptions["source-address"] = "192.0.2.1"
	copy.Extensions["role"] = "guest"
	copy.ExtraData["audit"] = "copy"
	require.Equal(t, "127.0.0.1", original.CriticalOptions["source-address"])
	require.Equal(t, "admin", original.Extensions["role"])
	require.Equal(t, "original", original.ExtraData["audit"])

	original.Extensions["role"] = "operator"
	require.Equal(t, "guest", copy.Extensions["role"])

	ctx.SetValue(ContextKeyPermissions, &Permissions{Permissions: &gossh.Permissions{}})
	empty := sess.Permissions()
	require.Nil(t, empty.CriticalOptions)
	require.Nil(t, empty.Extensions)
	require.Nil(t, empty.ExtraData)
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

func TestSessionLimitsRemainReservedUntilHandlerReturns(t *testing.T) {
	for _, tc := range []struct {
		name   string
		server func(handler Handler) *Server
	}{
		{
			name: "sessions per connection",
			server: func(handler Handler) *Server {
				limit := 1
				return &Server{Handler: handler, MaxSessionsPerConnection: &limit}
			},
		},
		{
			name: "channels per connection",
			server: func(handler Handler) *Server {
				limit, unlimited := 1, 0
				return &Server{Handler: handler, MaxSessionsPerConnection: &unlimited, MaxChannelsPerConnection: &limit}
			},
		},
		{
			name: "global channels",
			server: func(handler Handler) *Server {
				limit, unlimited := 1, 0
				return &Server{
					Handler: handler, MaxSessionsPerConnection: &unlimited,
					MaxChannelsPerConnection: &unlimited, MaxChannels: &limit,
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			started := make(chan struct{})
			release := make(chan struct{})
			first, client, cleanup := newTestSession(t, tc.server(func(Session) {
				close(started)
				<-release
			}), nil)
			defer cleanup()
			require.NoError(t, first.Shell())
			<-started
			require.NoError(t, first.Close())

			require.Never(t, func() bool {
				session, err := client.NewSession()
				if err == nil {
					closeQuietly(session)
					return true
				}
				return false
			}, 50*time.Millisecond, time.Millisecond)

			close(release)
			var next *gossh.Session
			require.Eventually(t, func() bool {
				var err error
				next, err = client.NewSession()
				return err == nil
			}, time.Second, time.Millisecond)
			closeQuietly(next)
		})
	}
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

func TestHandlerExitCancelsBlockedBreakDelivery(t *testing.T) {
	ready := make(chan struct{})
	release := make(chan struct{})
	serverSession := make(chan *session, 1)
	session, _, cleanup := newTestSession(t, &Server{Handler: func(s Session) {
		s.Break(make(chan bool))
		serverSession <- s.(*session)
		close(ready)
		<-release
	}}, nil)
	defer cleanup()
	runResult := make(chan error, 1)
	go func() { runResult <- session.Run("") }()
	<-ready
	type requestResult struct {
		ok  bool
		err error
	}
	breakResult := make(chan requestResult, 1)
	go func() {
		ok, err := session.SendRequest("break", true, nil)
		breakResult <- requestResult{ok: ok, err: err}
	}()
	internal := <-serverSession
	require.Eventually(t, func() bool {
		internal.Lock()
		defer internal.Unlock()
		return internal.breakSends == 1
	}, time.Second, time.Millisecond)
	close(release)
	select {
	case result := <-breakResult:
		require.NoError(t, result.err)
		require.False(t, result.ok)
	case <-time.After(time.Second):
		t.Fatal("handler exit did not cancel blocked break delivery")
	}
	select {
	case err := <-runResult:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("session did not exit after blocked break delivery was canceled")
	}
}

func TestBreakCannotBeRegisteredAfterExitStarts(t *testing.T) {
	ctx, cancel := newContext(nil)
	defer cancel()
	sess := &session{ctx: ctx}
	sess.Break(make(chan bool))
	sess.stopBreakDeliveryForExit()
	sess.Break(make(chan bool))
	require.False(t, sess.deliverBreak())
}
