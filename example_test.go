package ssh_test

import (
	"context"
	"io"
	"log"
	"os"

	"github.com/engity-com/ssh-server-go"
)

func ExampleListenAndServe() {
	log.Fatal(ssh.ListenAndServe(context.Background(), ":2222", func(s ssh.Session) {
		_, _ = io.WriteString(s, "Hello world\n")
	}))
}

func ExamplePasswordAuth() {
	log.Fatal(ssh.ListenAndServe(context.Background(), ":2222", nil,
		ssh.PasswordAuth(func(ctx ssh.Context, pass string) bool {
			return pass == "secret"
		}),
	))
}

func ExampleNoPty() {
	log.Fatal(ssh.ListenAndServe(context.Background(), ":2222", nil, ssh.NoPty()))
}

func ExamplePublicKeyAuth() {
	log.Fatal(ssh.ListenAndServe(context.Background(), ":2222", nil,
		ssh.PublicKeyAuth(func(ctx ssh.Context, key ssh.PublicKey) bool {
			data, _ := os.ReadFile("/path/to/allowed/key.pub")
			allowed, _, _, _, _ := ssh.ParseAuthorizedKey(data)
			return ssh.KeysEqual(key, allowed)
		}),
	))
}

func ExampleHostKeyFile() {
	log.Fatal(ssh.ListenAndServe(context.Background(), ":2222", nil, ssh.HostKeyFile("/path/to/host/key")))
}
