package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"github.com/creack/pty"
	"github.com/engity-com/ssh-server-go"
)

func setWinsize(f *os.File, w, h int) {
	const maxUint16 = int(^uint16(0))
	if w <= 0 || h <= 0 || w > maxUint16 || h > maxUint16 {
		return
	}
	_, _, _ = syscall.Syscall(
		syscall.SYS_IOCTL,
		f.Fd(),
		uintptr(syscall.TIOCSWINSZ),
		uintptr(unsafe.Pointer(&struct{ h, w, x, y uint16 }{uint16(h), uint16(w), 0, 0})),
	)
}

func main() {
	ssh.Handle(func(s ssh.Session) error {
		cmd := exec.Command("top")
		ptyReq, winCh, isPty := s.Pty()
		if !isPty {
			return ssh.NewSessionExitError(1, "No PTY requested.\n")
		}
		cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
		// Applications can inspect ptyReq.TerminalModes and decide how to
		// configure their PTY; the SSH server does not apply them.
		f, err := pty.Start(cmd)
		if err != nil {
			return fmt.Errorf("start top in PTY: %w", err)
		}
		go func() {
			for win := range winCh {
				setWinsize(f, win.Width, win.Height)
			}
		}()
		go func() {
			_, _ = io.Copy(f, s) // Ends when the PTY or session closes.
		}()
		_, copyErr := io.Copy(s, f)
		closeErr := f.Close()
		waitErr := cmd.Wait()
		if errors.Is(copyErr, syscall.EIO) {
			copyErr = nil // Linux reports PTY EOF as EIO.
		}
		return errors.Join(copyErr, closeErr, waitErr)
	})

	log.Println("DEVELOPMENT ONLY: anonymous authentication and an ephemeral host key")
	log.Println("starting ssh server on 127.0.0.1:2222...")
	log.Fatal(ssh.ListenAndServe(context.Background(), "127.0.0.1:2222", nil))
}
