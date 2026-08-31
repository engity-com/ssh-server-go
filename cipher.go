package ssh

import (
	"bytes"
	"fmt"
	"slices"
)

type Cipher uint8

const (
	CipherAes128Cbc Cipher = iota
	Cipher3desCbc
	CipherArcfour
	CipherArcfour128
	CipherArcfour256
	CipherChacha20Poly1305
	CipherAes128Ctr
	CipherAes192Ctr
	CipherAes256Ctr
	CipherAes128Gcm
	CipherAes256Gcm
)

var (
	cipher2Name = map[Cipher]string{
		CipherAes128Cbc:        "aes128-cbc",
		Cipher3desCbc:          "3des-cbc",
		CipherArcfour:          "arcfour",
		CipherArcfour128:       "arcfour128",
		CipherArcfour256:       "arcfour256",
		CipherChacha20Poly1305: "chacha20-poly1305@openssh.com",
		CipherAes128Ctr:        "aes128-ctr",
		CipherAes192Ctr:        "aes192-ctr",
		CipherAes256Ctr:        "aes256-ctr",
		CipherAes128Gcm:        "aes128-gcm@openssh.com",
		CipherAes256Gcm:        "aes256-gcm@openssh.com",
	}
	name2Cipher = func(in map[Cipher]string) map[string]Cipher {
		result := make(map[string]Cipher, len(in))
		for k, v := range in {
			result[v] = k
		}
		return result
	}(cipher2Name)

	DefaultCiphers = Ciphers{
		CipherAes256Gcm,
		CipherAes256Ctr,
		CipherAes192Ctr,
	}
)

func (c Cipher) Validate() error {
	_, err := c.MarshalText()
	return err
}

func (c Cipher) MarshalText() (text []byte, err error) {
	if v, ok := cipher2Name[c]; ok {
		return []byte(v), nil
	}
	return nil, fmt.Errorf("illegal ssh cipher: %d", c)
}

func (c Cipher) String() string {
	if v, err := c.MarshalText(); err == nil {
		return string(v)
	}
	return fmt.Sprintf("illegal-ssh-cipher-%d", c)
}

func (c *Cipher) UnmarshalText(text []byte) error {
	if v, ok := name2Cipher[string(text)]; ok {
		*c = v
		return nil
	}
	return fmt.Errorf("illegal ssh cipher: %q", string(text))
}

func (c *Cipher) Set(text string) error {
	return c.UnmarshalText([]byte(text))
}

func (c Cipher) IsZero() bool {
	return false
}

func (c Cipher) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case Cipher:
		return c.isEqualTo(&v)
	case *Cipher:
		return c.isEqualTo(v)
	default:
		return false
	}
}

func (c Cipher) isEqualTo(other *Cipher) bool {
	return other != nil && c == *other
}

type Ciphers []Cipher

func (c Ciphers) IsEmpty() bool {
	return len(c) == 0
}

func (c Ciphers) IsCumulative() bool {
	return true
}

func (c Ciphers) Validate() error {
	_, err := c.MarshalText()
	return err
}

func (c Ciphers) MarshalTexts() (texts [][]byte, err error) {
	texts = make([][]byte, len(c))
	for i, v := range c {
		texts[i], err = v.MarshalText()
		if err != nil {
			return nil, fmt.Errorf("[%d] %w", i, err)
		}
	}
	return texts, nil
}
func (c Ciphers) MarshalText() (text []byte, err error) {
	texts, err := c.MarshalTexts()
	if err != nil {
		return nil, err
	}
	return bytes.Join(texts, []byte(",")), nil
}

func (c Ciphers) String() string {
	v, err := c.MarshalText()
	if err != nil {
		return fmt.Sprintf("illegal-ssh-ciphers: %s", err.Error())
	}
	return string(v)
}

func (c *Ciphers) UnmarshalText(text []byte) error {
	texts := bytes.Split(text, []byte(","))
	for _, v := range texts {
		var buf Cipher
		if err := buf.UnmarshalText(v); err != nil {
			return err
		}
		*c = append(*c, buf)
	}
	return nil
}

func (c *Ciphers) Set(text string) error {
	return c.UnmarshalText([]byte(text))
}

func (c Ciphers) IsZero() bool {
	return false
}

func (c Ciphers) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case Ciphers:
		return c.isEqualTo(&v)
	case *Ciphers:
		return c.isEqualTo(v)
	default:
		return false
	}
}

func (c Ciphers) isEqualTo(other *Ciphers) bool {
	if other == nil || len(c) != len(*other) {
		return false
	}
	for i, tv := range c {
		ov := (*other)[i]
		if !tv.isEqualTo(&ov) {
			return false
		}
	}
	return true
}

func (c Ciphers) Contains(v Cipher) bool {
	return slices.Contains(c, v)
}
