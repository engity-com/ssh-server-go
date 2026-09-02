package ssh

import (
	"encoding/binary"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
)

func TestParsePtyRequestTerminalModes(t *testing.T) {
	encodedModes := appendTerminalMode(nil, gossh.ECHO, 1)
	encodedModes = appendTerminalMode(encodedModes, 159, 42)
	encodedModes = appendTerminalMode(encodedModes, gossh.ECHO, 0)
	encodedModes = append(encodedModes, 0)

	wantWindow := Window{Width: 80, Height: 24, WidthPixels: 640, HeightPixels: 480}
	pty, ok := parsePtyRequest(marshalPtyRequest("xterm", wantWindow, encodedModes))

	require.True(t, ok)
	require.Equal(t, "xterm", pty.Term)
	require.Equal(t, wantWindow, pty.Window)
	require.Equal(t, gossh.TerminalModes{gossh.ECHO: 0, 159: 42}, pty.TerminalModes)
}

func TestParsePtyRequestRequiresCompletePayload(t *testing.T) {
	valid := marshalPtyRequest("xterm", Window{Width: 80, Height: 24}, []byte{0})
	tests := map[string][]byte{
		"missing mode string":   valid[:len(valid)-5],
		"trailing request data": append(valid, 1),
	}
	for name, payload := range tests {
		t.Run(name, func(t *testing.T) {
			_, ok := parsePtyRequest(payload)
			require.False(t, ok)
		})
	}
}

func TestParsePtyRequestPreservesUnspecifiedDimensions(t *testing.T) {
	pty, ok := parsePtyRequest(marshalPtyRequest("xterm", Window{}, []byte{0}))

	require.True(t, ok)
	require.Equal(t, Window{}, pty.Window)
}

func TestParseTerminalModes(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		modes, ok := parseTerminalModes([]byte{0})
		require.True(t, ok)
		require.NotNil(t, modes)
		require.Empty(t, modes)
	})

	t.Run("defined opcode boundaries", func(t *testing.T) {
		encoded := appendTerminalMode(nil, 1, 10)
		encoded = appendTerminalMode(encoded, 159, 20)
		encoded = append(encoded, 0)
		modes, ok := parseTerminalModes(encoded)
		require.True(t, ok)
		require.Equal(t, gossh.TerminalModes{1: 10, 159: 20}, modes)
	})

	for _, opcode := range []byte{160, 255} {
		t.Run("reserved opcode stops parsing "+strconv.Itoa(int(opcode)), func(t *testing.T) {
			encoded := appendTerminalMode(nil, gossh.ECHO, 1)
			encoded = append(encoded, opcode, 1, 2, 3, 4)
			modes, ok := parseTerminalModes(encoded)
			require.True(t, ok)
			require.Equal(t, gossh.TerminalModes{gossh.ECHO: 1}, modes)
		})
	}

	for name, encoded := range map[string][]byte{
		"missing terminator": appendTerminalMode(nil, gossh.ECHO, 1),
		"truncated value":    {gossh.ECHO, 0, 0, 0},
		"trailing data":      {0, 1},
		"empty stream":       nil,
	} {
		t.Run(name, func(t *testing.T) {
			modes, ok := parseTerminalModes(encoded)
			require.False(t, ok)
			require.Nil(t, modes)
		})
	}
}

func TestUint32ToInt(t *testing.T) {
	value, ok := uint32ToInt(^uint32(0))
	require.Equal(t, strconv.IntSize == 64, ok)
	if ok {
		require.Equal(t, ^uint32(0), uint32(value))
	}
}

func TestParseWinchRequest(t *testing.T) {
	want := Window{Width: 80, Height: 24, WidthPixels: 640, HeightPixels: 480}
	payload := marshalWindow(want)

	got, ok := parseWinchRequest(payload)
	require.True(t, ok)
	require.Equal(t, want, got)

	zero, ok := parseWinchRequest(make([]byte, 16))
	require.True(t, ok)
	require.Equal(t, Window{}, zero)

	for name, malformed := range map[string][]byte{
		"truncated": payload[:len(payload)-1],
		"trailing":  append(payload, 0),
	} {
		t.Run(name, func(t *testing.T) {
			_, ok := parseWinchRequest(malformed)
			require.False(t, ok)
		})
	}
}

func TestParseWindowRejectsDimensionsOutsideIntRange(t *testing.T) {
	values := [4]uint32{80, 24, 640, 480}
	for dimension := range values {
		values := values
		values[dimension] = ^uint32(0)
		_, _, ok := parseWindow(marshalWindowValues(values))
		require.Equal(t, strconv.IntSize == 64, ok)
	}
}

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

func marshalPtyRequest(term string, window Window, modes []byte) []byte {
	return gossh.Marshal(&struct {
		Term                      string
		Width, Height             uint32
		WidthPixels, HeightPixels uint32
		Modes                     string
	}{
		Term:         term,
		Width:        uint32(window.Width),
		Height:       uint32(window.Height),
		WidthPixels:  uint32(window.WidthPixels),
		HeightPixels: uint32(window.HeightPixels),
		Modes:        string(modes),
	})
}

func marshalWindow(window Window) []byte {
	return marshalWindowValues([4]uint32{
		uint32(window.Width),
		uint32(window.Height),
		uint32(window.WidthPixels),
		uint32(window.HeightPixels),
	})
}

func marshalWindowValues(values [4]uint32) []byte {
	return gossh.Marshal(&struct {
		Width, Height             uint32
		WidthPixels, HeightPixels uint32
	}{
		Width:        values[0],
		Height:       values[1],
		WidthPixels:  values[2],
		HeightPixels: values[3],
	})
}

func appendTerminalMode(dst []byte, opcode uint8, value uint32) []byte {
	dst = append(dst, opcode)
	return binary.BigEndian.AppendUint32(dst, value)
}
