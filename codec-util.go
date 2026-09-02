package ssh

import (
	"encoding/binary"

	gossh "golang.org/x/crypto/ssh"
)

func parsePtyRequest(s []byte) (pty Pty, ok bool) {
	term, s, ok := parseString(s)
	if !ok {
		return
	}
	window, s, ok := parseWindow(s)
	if !ok {
		return
	}
	encodedModes, rest, ok := parseString(s)
	if !ok || len(rest) != 0 {
		return Pty{}, false
	}
	terminalModes, ok := parseTerminalModes([]byte(encodedModes))
	if !ok {
		return Pty{}, false
	}
	pty = Pty{
		Term:          term,
		TerminalModes: terminalModes,
		Window:        window,
	}
	return
}

func parseTerminalModes(in []byte) (gossh.TerminalModes, bool) {
	modes := make(gossh.TerminalModes)
	for len(in) > 0 {
		opcode := in[0]
		in = in[1:]
		switch {
		case opcode == 0:
			if len(in) != 0 {
				return nil, false
			}
			return modes, true
		case opcode >= 160:
			return modes, true
		case len(in) < 4:
			return nil, false
		default:
			modes[opcode] = binary.BigEndian.Uint32(in)
			in = in[4:]
		}
	}
	return nil, false
}

func parseWinchRequest(s []byte) (win Window, ok bool) {
	win, rest, ok := parseWindow(s)
	return win, ok && len(rest) == 0
}

func parseWindow(s []byte) (win Window, rest []byte, ok bool) {
	values := [4]int{}
	for i := range values {
		var value uint32
		value, s, ok = parseUint32(s)
		if !ok {
			return Window{}, nil, false
		}
		values[i], ok = uint32ToInt(value)
		if !ok {
			return Window{}, nil, false
		}
	}
	return Window{
		Width:        values[0],
		Height:       values[1],
		WidthPixels:  values[2],
		HeightPixels: values[3],
	}, s, true
}

func parseString(in []byte) (out string, rest []byte, ok bool) {
	if len(in) < 4 {
		return
	}
	length := binary.BigEndian.Uint32(in)
	in = in[4:]
	if uint64(len(in)) < uint64(length) {
		return
	}
	n := int(length)
	out = string(in[:n])
	rest = in[n:]
	ok = true
	return
}

func parseUint32(in []byte) (uint32, []byte, bool) {
	if len(in) < 4 {
		return 0, nil, false
	}
	return binary.BigEndian.Uint32(in), in[4:], true
}

func uint32ToInt(value uint32) (int, bool) {
	result := int(value)
	return result, result >= 0 && uint32(result) == value
}
