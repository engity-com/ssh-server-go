package ssh_test

import (
	"context"
	"io"
	"log"
	"os"

	"github.com/engity-com/ssh-server-go"
	gossh "golang.org/x/crypto/ssh"
)

func ExampleListenAndServe() {
	log.Fatal(ssh.ListenAndServe(context.Background(), ":2222", func(s ssh.Session) error {
		_, err := io.WriteString(s, "Hello world\n")
		return err
	}))
}

func ExamplePasswordAuth() {
	log.Fatal(ssh.ListenAndServe(context.Background(), ":2222", nil,
		ssh.PasswordAuth(func(ctx ssh.Context, conn gossh.ConnMetadata, pass string) (bool, error) {
			return pass == "secret", nil
		}),
	))
}

func ExampleNoPty() {
	log.Fatal(ssh.ListenAndServe(context.Background(), ":2222", nil, ssh.NoPty()))
}

func ExamplePublicKeyAuth() {
	log.Fatal(ssh.ListenAndServe(context.Background(), ":2222", nil,
		ssh.PublicKeyAuth(func(ctx ssh.Context, conn gossh.ConnMetadata, key ssh.PublicKey) (bool, error) {
			data, _ := os.ReadFile("/path/to/allowed/key.pub")
			allowed, _, _, _, _ := ssh.ParseAuthorizedKey(data)
			return ssh.KeysEqual(key, allowed), nil
		}),
	))
}

func ExampleHostKeyFile() {
	log.Fatal(ssh.ListenAndServe(context.Background(), ":2222", nil, ssh.HostKeyFile("/path/to/host/key")))
}
