package ssh

import (
	"bytes"
	"fmt"
	"slices"
)

type MessageAuthentication uint8

const (
	MessageAuthenticationHmacSha1 MessageAuthentication = iota
	MessageAuthenticationHmacSha1B96
	MessageAuthenticationHmacSha2B256
	MessageAuthenticationHmacSha2B512
	MessageAuthenticationHmacSha2B256Etm
	MessageAuthenticationHmacSha2B512Etm
)

var (
	messageAuthentication2Name = map[MessageAuthentication]string{
		MessageAuthenticationHmacSha1:        "hmac-sha1",
		MessageAuthenticationHmacSha1B96:     "hmac-sha1-96",
		MessageAuthenticationHmacSha2B256:    "hmac-sha2-256",
		MessageAuthenticationHmacSha2B512:    "hmac-sha2-512",
		MessageAuthenticationHmacSha2B256Etm: "hmac-sha2-256-etm@openssh.com",
		MessageAuthenticationHmacSha2B512Etm: "hmac-sha2-512-etm@openssh.com",
	}
	name2MessageAuthentication = func(in map[MessageAuthentication]string) map[string]MessageAuthentication {
		result := make(map[string]MessageAuthentication, len(in))
		for k, v := range in {
			result[v] = k
		}
		return result
	}(messageAuthentication2Name)

	DefaultMessageAuthentications = MessageAuthentications{
		MessageAuthenticationHmacSha2B512Etm,
		MessageAuthenticationHmacSha2B256Etm,
	}
)

func (ma MessageAuthentication) Validate() error {
	_, err := ma.MarshalText()
	return err
}

func (ma MessageAuthentication) MarshalText() (text []byte, err error) {
	if v, ok := messageAuthentication2Name[ma]; ok {
		return []byte(v), nil
	}
	return nil, fmt.Errorf("illegal ssh message authentication: %d", ma)
}

func (ma MessageAuthentication) String() string {
	if v, err := ma.MarshalText(); err == nil {
		return string(v)
	}
	return fmt.Sprintf("illegal-ssh-message-authentication-%d", ma)
}

func (ma *MessageAuthentication) UnmarshalText(text []byte) error {
	if v, ok := name2MessageAuthentication[string(text)]; ok {
		*ma = v
		return nil
	}
	return fmt.Errorf("illegal ssh message authentication: %q", string(text))
}

func (ma *MessageAuthentication) Set(text string) error {
	return ma.UnmarshalText([]byte(text))
}

func (ma MessageAuthentication) IsZero() bool {
	return false
}

func (ma MessageAuthentication) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case MessageAuthentication:
		return ma.isEqualTo(&v)
	case *MessageAuthentication:
		return ma.isEqualTo(v)
	default:
		return false
	}
}

func (ma MessageAuthentication) isEqualTo(other *MessageAuthentication) bool {
	return other != nil && ma == *other
}

type MessageAuthentications []MessageAuthentication

func (me MessageAuthentications) IsEmpty() bool {
	return len(me) == 0
}

func (me MessageAuthentications) IsCumulative() bool {
	return true
}

func (me MessageAuthentications) Validate() error {
	_, err := me.MarshalText()
	return err
}

func (me MessageAuthentications) MarshalTexts() (texts [][]byte, err error) {
	texts = make([][]byte, len(me))
	for i, v := range me {
		texts[i], err = v.MarshalText()
		if err != nil {
			return nil, fmt.Errorf("[%d] %w", i, err)
		}
	}
	return texts, nil
}
func (me MessageAuthentications) MarshalText() (text []byte, err error) {
	texts, err := me.MarshalTexts()
	if err != nil {
		return nil, err
	}
	return bytes.Join(texts, []byte(",")), nil
}

func (me MessageAuthentications) String() string {
	v, err := me.MarshalText()
	if err != nil {
		return fmt.Sprintf("illegal-ssh-message-authentications: %s", err.Error())
	}
	return string(v)
}

func (me *MessageAuthentications) UnmarshalText(text []byte) error {
	texts := bytes.Split(text, []byte(","))
	for _, v := range texts {
		var buf MessageAuthentication
		if err := buf.UnmarshalText(v); err != nil {
			return err
		}
		*me = append(*me, buf)
	}
	return nil
}

func (me *MessageAuthentications) Set(text string) error {
	return me.UnmarshalText([]byte(text))
}

func (me MessageAuthentications) IsZero() bool {
	return false
}

func (me MessageAuthentications) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case MessageAuthentications:
		return me.isEqualTo(&v)
	case *MessageAuthentications:
		return me.isEqualTo(v)
	default:
		return false
	}
}

func (me MessageAuthentications) isEqualTo(other *MessageAuthentications) bool {
	if other == nil || len(me) != len(*other) {
		return false
	}
	for i, tv := range me {
		ov := (*other)[i]
		if !tv.isEqualTo(&ov) {
			return false
		}
	}
	return true
}

func (me MessageAuthentications) Contains(v MessageAuthentication) bool {
	return slices.Contains(me, v)
}
