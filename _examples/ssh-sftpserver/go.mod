module github.com/engity-com/ssh-server-go/_examples/ssh-sftpserver

go 1.27.0

replace github.com/engity-com/ssh-server-go => ../..

require (
	github.com/engity-com/ssh-server-go v0.0.0
	github.com/pkg/sftp v1.13.11
)

require (
	github.com/anmitsu/go-shlex v0.0.0-20200514113438-38f4b401e2be // indirect
	github.com/echocat/slf4g v1.8.4 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/pires/go-proxyproto v0.15.0 // indirect
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)
