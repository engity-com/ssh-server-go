package ssh

import (
	"bytes"
	"fmt"
	"slices"
)

type KeyExchange uint8

const (
	KeyExchangeDh1Sha1 KeyExchange = iota
	KeyExchangeDh14Sha1
	KeyExchangeDh14Sha256
	KeyExchangeDh16Sha512
	KeyExchangeEcdh256
	KeyExchangeEcdh384
	KeyExchangeEcdh521
	KeyExchangeCurve25519Sha256LibSsh
	KeyExchangeCurve25519Sha256
	KeyExchangeDhgexSha1
	KeyExchangeDhgexSha256
	KeyExchangeMlkem768x25519xSha256
)

var (
	keyExchange2Name = map[KeyExchange]string{
		KeyExchangeDh1Sha1:                "diffie-hellman-group1-sha1",
		KeyExchangeDh14Sha1:               "diffie-hellman-group14-sha1",
		KeyExchangeDh14Sha256:             "diffie-hellman-group14-sha256",
		KeyExchangeDh16Sha512:             "diffie-hellman-group16-sha512",
		KeyExchangeEcdh256:                "ecdh-sha2-nistp256",
		KeyExchangeEcdh384:                "ecdh-sha2-nistp384",
		KeyExchangeEcdh521:                "ecdh-sha2-nistp521",
		KeyExchangeCurve25519Sha256LibSsh: "curve25519-sha256@libssh.org",
		KeyExchangeCurve25519Sha256:       "curve25519-sha256",
		KeyExchangeDhgexSha1:              "diffie-hellman-group-exchange-sha1",
		KeyExchangeDhgexSha256:            "diffie-hellman-group-exchange-sha256",
		KeyExchangeMlkem768x25519xSha256:  "mlkem768x25519-sha256",
	}
	name2KeyExchange = func(in map[KeyExchange]string) map[string]KeyExchange {
		result := make(map[string]KeyExchange, len(in))
		for k, v := range in {
			result[v] = k
		}
		return result
	}(keyExchange2Name)

	DefaultKeyExchanges = KeyExchanges{
		KeyExchangeCurve25519Sha256LibSsh,
		KeyExchangeCurve25519Sha256,
		KeyExchangeDh16Sha512,
		KeyExchangeMlkem768x25519xSha256,
	}
)

func (ke KeyExchange) Validate() error {
	_, err := ke.MarshalText()
	return err
}

func (ke KeyExchange) MarshalText() (text []byte, err error) {
	if v, ok := keyExchange2Name[ke]; ok {
		return []byte(v), nil
	}
	return nil, fmt.Errorf("illegal ssh key exchange: %d", ke)
}

func (ke KeyExchange) String() string {
	if v, err := ke.MarshalText(); err == nil {
		return string(v)
	}
	return fmt.Sprintf("illegal-ssh-key-exchange-%d", ke)
}

func (ke *KeyExchange) UnmarshalText(text []byte) error {
	if v, ok := name2KeyExchange[string(text)]; ok {
		*ke = v
		return nil
	}
	return fmt.Errorf("illegal ssh key exchange: %q", string(text))
}

func (ke *KeyExchange) Set(text string) error {
	return ke.UnmarshalText([]byte(text))
}

func (ke KeyExchange) IsZero() bool {
	return false
}

func (ke KeyExchange) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case KeyExchange:
		return ke.isEqualTo(&v)
	case *KeyExchange:
		return ke.isEqualTo(v)
	default:
		return false
	}
}

func (ke KeyExchange) isEqualTo(other *KeyExchange) bool {
	return other != nil && ke == *other
}

type KeyExchanges []KeyExchange

func (ke KeyExchanges) IsEmpty() bool {
	return len(ke) == 0
}

func (ke KeyExchanges) IsCumulative() bool {
	return true
}

func (ke KeyExchanges) Validate() error {
	_, err := ke.MarshalText()
	return err
}

func (ke KeyExchanges) MarshalTexts() (texts [][]byte, err error) {
	texts = make([][]byte, len(ke))
	for i, v := range ke {
		texts[i], err = v.MarshalText()
		if err != nil {
			return nil, fmt.Errorf("[%d] %w", i, err)
		}
	}
	return texts, nil
}
func (ke KeyExchanges) MarshalText() (text []byte, err error) {
	texts, err := ke.MarshalTexts()
	if err != nil {
		return nil, err
	}
	return bytes.Join(texts, []byte(",")), nil
}

func (ke KeyExchanges) String() string {
	v, err := ke.MarshalText()
	if err != nil {
		return fmt.Sprintf("illegal-ssh-key-exchanges: %s", err.Error())
	}
	return string(v)
}

func (ke *KeyExchanges) UnmarshalText(text []byte) error {
	texts := bytes.Split(text, []byte(","))
	for _, v := range texts {
		var buf KeyExchange
		if err := buf.UnmarshalText(v); err != nil {
			return err
		}
		*ke = append(*ke, buf)
	}
	return nil
}

func (ke *KeyExchanges) Set(text string) error {
	return ke.UnmarshalText([]byte(text))
}

func (ke KeyExchanges) IsZero() bool {
	return false
}

func (ke KeyExchanges) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case KeyExchanges:
		return ke.isEqualTo(&v)
	case *KeyExchanges:
		return ke.isEqualTo(v)
	default:
		return false
	}
}

func (ke KeyExchanges) isEqualTo(other *KeyExchanges) bool {
	if other == nil || len(ke) != len(*other) {
		return false
	}
	for i, tv := range ke {
		ov := (*other)[i]
		if !tv.isEqualTo(&ov) {
			return false
		}
	}
	return true
}

func (ke KeyExchanges) Contains(v KeyExchange) bool {
	return slices.Contains(ke, v)
}
