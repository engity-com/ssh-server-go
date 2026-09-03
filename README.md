# SSH Server SDK for Go

This Go package wraps the [crypto/ssh package](https://pkg.go.dev/golang.org/x/crypto/ssh) with a higher-level API for building SSH servers. The goal of the API was to make it as simple as using [net/http](https://golang.org/pkg/net/http/), so the API is very similar:

```go
 package main

 import (
     "context"
     "io"
     "log"

     "github.com/engity-com/ssh-server-go"
 )

 func main() {
     ssh.Handle(func(s ssh.Session) error {
         _, err := io.WriteString(s, "Hello world\n")
         return err
     })

     log.Fatal(ssh.ListenAndServe(context.Background(), "127.0.0.1:2222", nil))
 }

```

> [!NOTE]
> The minimal example uses anonymous authentication and an automatically generated,
> process-local host key. These defaults are intended for local development only.
> Production servers should configure `PasswordHandler`, `PublicKeyHandler`, or a
> custom authentication policy, add a persistent host key, set
> `RequireHostSigners: true` and `RequireClientAuth: true`, and expose only
> explicitly intended interfaces and forwarding destinations. Agent forwarding
> is denied unless `AgentForwardingCallback` explicitly allows it.

The module requires Go 1.27 or newer. The core package is portable across the
platforms supported by Go and its dependencies; some examples require Unix
facilities or programs.

## Server lifecycle

`Server` is a reusable configuration value. After its first `Serve` or
`HandleConn` call, its public fields and referenced maps, slices, pointers, and
callback state must not be modified. Concurrent and later calls may reuse the
same server when that configuration remains immutable. Configure the server and
call `Handle`, `AddHostKey`, and `SetOption` before first use.

Each `Serve` and `HandleConn` call owns an independent runtime context. Connection
tracking, graceful shutdown, `MaxStartups`, `MaxConnections`, `MaxChannels`,
`MaxReverseForwards`, and the callback concurrency bounds are scoped to that
individual call. Limits are not aggregated across multiple concurrent `Serve`
calls using the same server. Accepted session channels must start shell, exec,
or subsystem within `SessionRequestTimeout` (30 seconds by default).

## Error handling

Session, subsystem, request, and channel handlers return errors to the server's
`ErrorHandler`. The error handler can respond with a safe public message, stop or
permit further processing, transform the error before invoking `next`, or defer
to the caller-specific default action. A non-nil error returned by the error
handler aborts immediately. Otherwise, `canContinue` determines whether the
current scope may proceed; permission does not guarantee that its protocol state
still permits continuation. Handlers can run concurrently and should return
promptly; if too many invocations block at once, excess errors are sent directly
to their caller-specific default action. See the
[error handling example](_examples/ssh-errorhandling) for a complete setup.

Handlers can return `NewSessionExitError(code, message)` for an expected,
client-visible session result. The server writes the public message and exits
with the requested code without invoking `ErrorHandler` unless that protocol
response fails. The exit error may be wrapped, but joining it with an independent
error makes the combined result an operational error handled by `ErrorHandler`.

Synchronous server callbacks return operational errors directly. Boolean policy
callbacks use `false, nil` for an expected denial. Operational errors are routed
through the nearest `ErrorHandler` scope; a `GracefulShutdownHandler` error is
returned directly by `Serve`. Connection setup, banner, and authentication
errors abort the handshake. Callbacks also receive the concrete
`net.Conn`, `ssh.ConnMetadata`, or `Session` that is available at their lifecycle
stage in addition to the connection `Context` where applicable:

```go
BannerHandler: func(ctx ssh.Context, conn gossh.ConnMetadata) (string, error) {
    banner, err := resolveBanner(ctx, conn.User())
    if err != nil {
        return "", fmt.Errorf("resolve banner: %w", err)
    }
    return banner, nil
},
```

Connection-level request handlers receive a `RequestResponseWriter` and a
`Request`. They complete the request explicitly with `Accept` or `Reject` and
return only operational errors:

```go
func handleRequest(response ssh.RequestResponseWriter, request *ssh.Request) error {
	if request.Type != "example@test" {
		return response.Reject(nil)
	}
	return response.Accept([]byte("accepted"))
}
```

This error propagation API is source-incompatible with earlier callback
signatures. `Handler`, `SubsystemHandler`, `ChannelHandler`, and all synchronous
server callbacks now return `error`; boolean policy callbacks return
`(bool, error)`. `RequestHandler` receives a `RequestResponseWriter` and returns
`error`. Connection-aware callbacks additionally receive their concrete
connection metadata. Existing handlers must add the corresponding parameters and
return values and complete requests through `Accept` or `Reject`.

The server lifecycle is also behavior-incompatible with runtime reconfiguration
patterns. Per-connection configuration snapshots were removed; `Server`
configuration is immutable after first use, and limits apply per `Serve` or
`HandleConn` call rather than being aggregated by `Server` identity.

## Getting into this SDK

* [Examples](_examples)
* [Usage](https://pkg.go.dev/github.com/engity-com/ssh-server-go)
* [License](LICENSE)
* [Code of Conduct](CODE_OF_CONDUCT.md)
* [Contributing](CONTRIBUTING.md)
* [Security Policy](SECURITY.md)

## Acknowledgements

This project was originally forked from [gliderlabs/ssh](https://github.com/gliderlabs/ssh). Special thanks to its maintainers and contributors for laying the foundation for this work.
