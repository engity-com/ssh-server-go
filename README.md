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
     ssh.Handle(func(s ssh.Session) {
         io.WriteString(s, "Hello world\n")
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

## Getting into this SDK

* [Examples](_examples)
* [Usage](https://pkg.go.dev/github.com/engity-com/ssh-server-go)
* [License](LICENSE)
* [Code of Conduct](CODE_OF_CONDUCT.md)
* [Contributing](CONTRIBUTING.md)
* [Security Policy](SECURITY.md)

## Acknowledgements

This project was originally forked from [gliderlabs/ssh](https://github.com/gliderlabs/ssh). Special thanks to its maintainers and contributors for laying the foundation for this work.
