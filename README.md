# SSH Server SDK for Go

[![GoDoc](https://godoc.org/github.com/engity-com/ssh-server-go?status.svg)](https://godoc.org/github.com/engity-com/ssh-server-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/engity-com/ssh-server-go)](https://goreportcard.com/report/github.com/engity-com/ssh-server-go)

This Go package wraps the [crypto/ssh package](https://godoc.org/golang.org/x/crypto/ssh) with a higher-level API for building SSH servers. The goal of the API was to make it as simple as using [net/http](https://golang.org/pkg/net/http/), so the API is very similar:

```go
 package main

 import (
     "io"
     "log"

     "github.com/engity-com/ssh-server-go"
 )

 func main() {
     ssh.Handle(func(s ssh.Session) {
         io.WriteString(s, "Hello world\n")
     })

     log.Fatal(ssh.ListenAndServe(":2222", nil))
 }

```

## Getting into this SDK

* [Examples](_examples)
* [Usage]([#features](https://godoc.org/github.com/engity-com/ssh-server-go))
* [License](LICENSE)
* [Code of Conduct](CODE_OF_CONDUCT.md)
* [Contributing](CONTRIBUTING.md)

## Acknowledgements

This project is a fork of [gliderlabs/ssh](https://github.com/gliderlabs/ssh). Special thanks to its maintainers and contributors for laying the foundation for this work.
