package ssh

import (
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
)

func TestDeferredSubsystemSuccessAndOrderedReplies(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	releaseOnce := sync.OnceFunc(func() { close(release) })
	finish := make(chan struct{})
	responseErr := make(chan error, 1)
	sess, _, cleanup := newTestSession(t, &Server{
		DeferredSubsystemHandlers: map[string]DeferredSubsystemHandler{
			"sftp": func(s Session, reply SubsystemReply) error {
				if s.Subsystem() != "sftp" {
					return fmt.Errorf("subsystem = %q", s.Subsystem())
				}
				close(started)
				<-release
				responseErr <- reply(true)
				<-finish
				return nil
			},
		},
	}, nil)
	defer func() { releaseOnce(); close(finish); cleanup() }()
	first := make(chan error, 1)
	go func() { first <- sess.RequestSubsystem("sftp") }()
	<-started
	second := make(chan struct {
		ok  bool
		err error
	}, 1)
	go func() {
		ok, err := sess.SendRequest("unknown-after-subsystem", true, nil)
		second <- struct {
			ok  bool
			err error
		}{ok, err}
	}()
	select {
	case result := <-second:
		t.Fatalf("later request replied before subsystem: %+v", result)
	case <-time.After(50 * time.Millisecond):
	}
	releaseOnce()
	require.NoError(t, <-first)
	require.NoError(t, <-responseErr)
	result := <-second
	require.NoError(t, result.err)
	require.False(t, result.ok)
}

func newRawSubsystemChannel(t *testing.T, srv *Server) (gossh.Channel, <-chan *gossh.Request, func()) {
	t.Helper()
	unused, client, cleanup := newTestSession(t, srv, nil)
	require.NoError(t, unused.Close())
	ch, reqs, err := client.OpenChannel("session", nil)
	require.NoError(t, err)
	return ch, reqs, func() { closeQuietly(ch); cleanup() }
}

func requireRejectedSubsystemWithoutExit(t *testing.T, ch gossh.Channel, reqs <-chan *gossh.Request) {
	t.Helper()
	ok, err := ch.SendRequest("subsystem", true, gossh.Marshal(&struct{ Value string }{"sftp"}))
	require.NoError(t, err)
	require.False(t, ok)
	closed := make(chan []string, 1)
	go func() {
		var types []string
		for req := range reqs {
			types = append(types, req.Type)
		}
		closed <- types
	}()
	select {
	case types := <-closed:
		require.Empty(t, types, "rejected subsystem received server channel requests")
	case <-time.After(time.Second):
		t.Fatal("rejected subsystem channel remained open")
	}
}

func TestDeferredSubsystemFailureClosesWithoutExitStatus(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler DeferredSubsystemHandler
	}{
		{"explicit failure", func(_ Session, reply SubsystemReply) error { return reply(false) }},
		{"return without reply", func(Session, SubsystemReply) error { return nil }},
		{"error without reply", func(Session, SubsystemReply) error { return errors.New("upstream rejected") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ch, reqs, cleanup := newRawSubsystemChannel(t, &Server{
				DeferredSubsystemHandlers: map[string]DeferredSubsystemHandler{"sftp": tc.handler},
			})
			defer cleanup()
			requireRejectedSubsystemWithoutExit(t, ch, reqs)
		})
	}
}

func TestDeferredSubsystemReplyExactlyOnce(t *testing.T) {
	called := make(chan error, 2)
	sess, _, cleanup := newTestSession(t, &Server{
		DeferredSubsystemHandlers: map[string]DeferredSubsystemHandler{"sftp": func(_ Session, reply SubsystemReply) error {
			called <- reply(true)
			called <- reply(false)
			return nil
		}},
	}, nil)
	defer cleanup()
	require.NoError(t, sess.RequestSubsystem("sftp"))
	require.NoError(t, <-called)
	require.ErrorIs(t, <-called, ErrSubsystemResponseAlreadySent)
}

func TestDeferredSubsystemAcceptedHandlerErrorUsesExitStatus(t *testing.T) {
	ch, reqs, cleanup := newRawSubsystemChannel(t, &Server{
		DeferredSubsystemHandlers: map[string]DeferredSubsystemHandler{"sftp": func(_ Session, reply SubsystemReply) error {
			if err := reply(true); err != nil {
				return err
			}
			return errors.New("handler failed after acceptance")
		}},
	})
	defer cleanup()
	ok, err := ch.SendRequest("subsystem", true, gossh.Marshal(&struct{ Value string }{"sftp"}))
	require.NoError(t, err)
	require.True(t, ok)
	select {
	case req := <-reqs:
		require.NotNil(t, req)
		require.Equal(t, "exit-status", req.Type)
		var status struct{ Status uint32 }
		require.NoError(t, gossh.Unmarshal(req.Payload, &status))
		require.Equal(t, uint32(1), status.Status)
	case <-time.After(time.Second):
		t.Fatal("accepted handler did not send exit status")
	}
}

func TestDeferredSubsystemLateReplyAfterReturn(t *testing.T) {
	replyReady := make(chan SubsystemReply, 1)
	ch, reqs, cleanup := newRawSubsystemChannel(t, &Server{
		DeferredSubsystemHandlers: map[string]DeferredSubsystemHandler{"sftp": func(_ Session, reply SubsystemReply) error {
			replyReady <- reply
			return nil
		}},
	})
	defer cleanup()
	requireRejectedSubsystemWithoutExit(t, ch, reqs)
	require.ErrorIs(t, (<-replyReady)(true), ErrSubsystemResponseAlreadySent)
}

func TestDeferredSubsystemFailureCannotBeOvertaken(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	releaseOnce := sync.OnceFunc(func() { close(release) })
	sess, _, cleanup := newTestSession(t, &Server{
		DeferredSubsystemHandlers: map[string]DeferredSubsystemHandler{"sftp": func(_ Session, reply SubsystemReply) error {
			close(started)
			<-release
			return reply(false)
		}},
	}, nil)
	defer func() { releaseOnce(); cleanup() }()
	first := make(chan error, 1)
	go func() { first <- sess.RequestSubsystem("sftp") }()
	<-started
	second := make(chan struct {
		ok  bool
		err error
	}, 1)
	go func() {
		ok, err := sess.SendRequest("env", true, gossh.Marshal(&struct{ Key, Value string }{"FOO", "BAR"}))
		second <- struct {
			ok  bool
			err error
		}{ok, err}
	}()
	select {
	case result := <-second:
		t.Fatalf("later request replied before subsystem failure: %+v", result)
	case <-time.After(50 * time.Millisecond):
	}
	releaseOnce()
	require.Error(t, <-first)
	select {
	case result := <-second:
		require.False(t, result.ok, "later success was mistaken for subsystem reply")
	case <-time.After(time.Second):
		t.Fatal("later request did not finish after subsystem rejection")
	}
}

func TestDeferredSubsystemTimeoutAndLateReply(t *testing.T) {
	timeout := 50 * time.Millisecond
	started := make(chan struct{})
	late := make(chan error, 1)
	ch, reqs, cleanup := newRawSubsystemChannel(t, &Server{
		SubsystemReplyTimeout: &timeout,
		DeferredSubsystemHandlers: map[string]DeferredSubsystemHandler{"sftp": func(s Session, reply SubsystemReply) error {
			close(started)
			<-s.Context().Done()
			late <- reply(true)
			return nil
		}},
	})
	defer cleanup()
	result := make(chan error, 1)
	go func() {
		ok, err := ch.SendRequest("subsystem", true, gossh.Marshal(&struct{ Value string }{"sftp"}))
		if err == nil && ok {
			err = errors.New("unexpected subsystem success")
		}
		result <- err
	}()
	<-started
	select {
	case err := <-result:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("deferred subsystem decision did not time out")
	}
	require.ErrorIs(t, <-late, ErrSubsystemResponseAlreadySent)
	select {
	case _, ok := <-reqs:
		require.False(t, ok, "server sent a channel request after rejection")
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for channel closure")
	}
}

func TestDeferredSubsystemTimeoutKeepsSlotUntilHandlerReturns(t *testing.T) {
	timeout := 30 * time.Millisecond
	limit := 1
	release := make(chan struct{})
	releaseOnce := sync.OnceFunc(func() { close(release) })
	sess, client, cleanup := newTestSession(t, &Server{
		MaxSessionsPerConnection: &limit,
		SubsystemReplyTimeout:    &timeout,
		DeferredSubsystemHandlers: map[string]DeferredSubsystemHandler{"sftp": func(Session, SubsystemReply) error {
			<-release // deliberately ignores cancellation
			return nil
		}},
	}, nil)
	defer func() { releaseOnce(); cleanup() }()
	require.Error(t, sess.RequestSubsystem("sftp"))
	_, err := client.NewSession()
	require.Error(t, err, "timed-out handler released the session slot while still running")
	releaseOnce()
	var next *gossh.Session
	require.Eventually(t, func() bool {
		var openErr error
		next, openErr = client.NewSession()
		return openErr == nil
	}, time.Second, time.Millisecond)
	closeQuietly(next)
}

func TestDeferredSubsystemConnectionAbort(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan error, 1)
	sess, client, cleanup := newTestSession(t, &Server{
		DeferredSubsystemHandlers: map[string]DeferredSubsystemHandler{"sftp": func(s Session, reply SubsystemReply) error {
			close(started)
			<-s.Context().Done()
			canceled <- reply(true)
			return nil
		}},
	}, nil)
	defer cleanup()
	result := make(chan error, 1)
	go func() { result <- sess.RequestSubsystem("sftp") }()
	<-started
	require.NoError(t, client.Close())
	select {
	case err := <-result:
		require.Error(t, err)
	case <-time.After(time.Second):
		t.Fatal("client remained blocked on connection close")
	}
	select {
	case err := <-canceled:
		require.Error(t, err) // an in-flight write may fail before cancellation is observed
	case <-time.After(time.Second):
		t.Fatal("handler context was not canceled")
	}
}

func TestDeferredSubsystemDefaultAndPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name string
		want string
	}{
		{"explicit deferred", "deferred"},
		{"named ordinary over deferred default", "ordinary"},
		{"deferred default over ordinary default", "deferred-default"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := make(chan string, 1)
			srv := &Server{
				SubsystemHandlers: map[string]SubsystemHandler{
					"deferred": func(Session) error { called <- "wrong ordinary"; return nil },
					"ordinary": func(Session) error { called <- "ordinary"; return nil },
					"default":  func(Session) error { called <- "ordinary-default"; return nil },
				},
				DeferredSubsystemHandlers: map[string]DeferredSubsystemHandler{
					"deferred": func(_ Session, reply SubsystemReply) error {
						called <- "deferred"
						return reply(true)
					},
					"default": func(s Session, reply SubsystemReply) error {
						if s.Subsystem() != "unlisted" {
							return fmt.Errorf("unexpected subsystem %q", s.Subsystem())
						}
						called <- "deferred-default"
						return reply(true)
					},
				},
			}
			sess, _, cleanup := newTestSession(t, srv, nil)
			defer cleanup()
			name := map[string]string{"explicit deferred": "deferred", "named ordinary over deferred default": "ordinary", "deferred default over ordinary default": "unlisted"}[tc.name]
			require.NoError(t, sess.RequestSubsystem(name))
			require.Equal(t, tc.want, <-called)
		})
	}
}

func TestDeferredSubsystemValidationsRunFirst(t *testing.T) {
	var mu sync.Mutex
	var calls []string
	sess, _, cleanup := newTestSession(t, &Server{
		SessionRequestCallback: func(s Session, kind string) (bool, error) {
			mu.Lock()
			calls = append(calls, kind+":"+s.Subsystem())
			mu.Unlock()
			return s.Subsystem() != "blocked", nil
		},
		DeferredSubsystemHandlers: map[string]DeferredSubsystemHandler{"default": func(_ Session, reply SubsystemReply) error {
			mu.Lock()
			calls = append(calls, "handler")
			mu.Unlock()
			return reply(true)
		}},
	}, nil)
	defer cleanup()
	ok, err := sess.SendRequest("subsystem", true, []byte{0, 0, 0, 10, 'a'})
	require.NoError(t, err)
	require.False(t, ok)
	require.Error(t, sess.RequestSubsystem("blocked"))
	require.NoError(t, sess.RequestSubsystem("allowed"))
	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, []string{"subsystem:blocked", "subsystem:allowed", "handler"}, calls)
}

func TestOrdinarySubsystemShellExecUnchanged(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(*gossh.Session) error
	}{
		{"subsystem", func(s *gossh.Session) error { return s.RequestSubsystem("ordinary") }},
		{"shell", func(s *gossh.Session) error { return s.Shell() }},
		{"exec", func(s *gossh.Session) error { return s.Start("printf hi") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seen := make(chan string, 1)
			ordinary := func(s Session) error {
				seen <- s.Subsystem() + ":" + s.RawCommand()
				_, err := io.WriteString(s, "ok")
				return err
			}
			sess, _, cleanup := newTestSession(t, &Server{
				Handler:           ordinary,
				SubsystemHandlers: map[string]SubsystemHandler{"ordinary": ordinary},
				DeferredSubsystemHandlers: map[string]DeferredSubsystemHandler{"deferred": func(Session, SubsystemReply) error {
					t.Error("unrelated deferred handler called")
					return nil
				}},
			}, nil)
			defer cleanup()
			require.NoError(t, tc.run(sess))
			require.Equal(t, map[string]string{"subsystem": "ordinary:", "shell": ":", "exec": ":printf hi"}[tc.name], <-seen)
			if tc.name != "subsystem" {
				require.NoError(t, sess.Wait())
			}
		})
	}
}

func TestDeferredSubsystemRejectsExitUntilAccepted(t *testing.T) {
	ch, reqs, cleanup := newRawSubsystemChannel(t, &Server{
		DeferredSubsystemHandlers: map[string]DeferredSubsystemHandler{"sftp": func(s Session, reply SubsystemReply) error {
			if err := s.Exit(0); !errors.Is(err, ErrSubsystemResponsePending) {
				return fmt.Errorf("Exit before reply: %v", err)
			}
			if err := s.Close(); !errors.Is(err, ErrSubsystemResponsePending) {
				return fmt.Errorf("Close before reply: %v", err)
			}
			if err := reply(false); err != nil {
				return err
			}
			if err := s.Exit(0); !errors.Is(err, ErrSubsystemResponsePending) {
				return fmt.Errorf("Exit after rejection: %v", err)
			}
			return nil
		}},
	})
	defer cleanup()
	requireRejectedSubsystemWithoutExit(t, ch, reqs)
}
