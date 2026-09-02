package ssh

import (
	"crypto/rand"
	"crypto/rsa"

	ssh2 "golang.org/x/crypto/ssh"
)

func generateSigner() (ssh2.Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return ssh2.NewSignerFromKey(key)
}
