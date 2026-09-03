/*
Package ssh wraps the crypto/ssh package with a higher-level API for building
SSH servers. The goal of the API was to make it as simple as using net/http, so
the API is very similar.

You should be able to build any SSH server using only this package, which wraps
relevant types and some functions from crypto/ssh. However, you still need to
use crypto/ssh for building SSH clients.

ListenAndServe starts an SSH server with a given address, handler, and options. The
handler is usually nil, which means to use DefaultHandler. Handle sets DefaultHandler:

	ctx := context.Background()

	ssh.Handle(func(s ssh.Session) error {
	    _, err := io.WriteString(s, "Hello world\n")
	    return err
	})

	log.Fatal(ssh.ListenAndServe(ctx, ":2222", nil))

If you don't specify a host key, the Server generates one on first use and reuses
it for its lifetime. This development convenience does not provide a stable
identity across processes. Production servers should configure a persistent
signer and set Server.RequireHostSigners. It's a better idea to generate or point
to an existing key on your system:

	log.Fatal(ssh.ListenAndServe(ctx, ":2222", nil, ssh.HostKeyFile("/Users/progrium/.ssh/id_rsa")))

Although all options have functional option helpers, another way to control the
server's behavior is by creating a custom Server:

	s := &ssh.Server{
	    Addr:             ":2222",
	    Handler:          sessionHandler,
	    PublicKeyHandler: authHandler,
	}
	s.AddHostKey(hostKeySigner)

	log.Fatal(s.ListenAndServe(ctx))

See [Server] for lifecycle rules, [ErrorHandler] for operational errors, and
[SessionExitError] for controlled session failures.

This package handles basic SSH requests such as environment variables, PTYs,
window changes, signals, and breaks. Relevant state and delivery hooks are
exposed through Session.

The module requires the Go version declared in go.mod. The core package supports
the operating systems supported by its dependencies; examples that launch Unix
programs or use Unix sockets have additional platform requirements.
*/
package ssh
