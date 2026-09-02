package ssh

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseString(t *testing.T) {
	in := make([]byte, 4+5+1)
	binary.BigEndian.PutUint32(in, 5)
	copy(in[4:], "hello!")

	out, rest, ok := parseString(in)

	require.True(t, ok)
	require.Equal(t, "hello", out)
	require.Equal(t, []byte("!"), rest)
}

func TestParseStringBoundaries(t *testing.T) {
	tests := []struct {
		name     string
		in       []byte
		wantOut  string
		wantRest []byte
		wantOK   bool
	}{
		{name: "nil"},
		{name: "incomplete length", in: []byte{0, 0, 0}},
		{name: "empty", in: []byte{0, 0, 0, 0}, wantRest: []byte{}, wantOK: true},
		{name: "exact", in: []byte{0, 0, 0, 1, 'a'}, wantOut: "a", wantRest: []byte{}, wantOK: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, rest, ok := parseString(tt.in)

			require.Equal(t, tt.wantOK, ok)
			require.Equal(t, tt.wantOut, out)
			require.Equal(t, tt.wantRest, rest)
		})
	}
}

func TestParseStringRejectsOverflowingLength(t *testing.T) {
	in := []byte{0xff, 0xff, 0xff, 0xff, 0, 0}

	out, rest, ok := parseString(in)

	require.False(t, ok)
	require.Empty(t, out)
	require.Nil(t, rest)
}

func TestParsePtyRequestRejectsOverflowingTermLength(t *testing.T) {
	payload := []byte{0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0}

	_, ok := parsePtyRequest(payload)

	require.False(t, ok)
}
