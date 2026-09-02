package ssh

import (
	"errors"
	"net"
	"time"

	"github.com/pires/go-proxyproto"
)

var errProxyProtocolAlreadyWrapped = errors.New("ssh: connection is already wrapped for PROXY protocol")

// ProxyProtocolConfig configures PROXY protocol processing for accepted
// connections. A nil ConnPolicy requires a PROXY header but trusts the source
// information supplied by every peer. Listeners reachable by untrusted peers
// should configure a policy such as [proxyproto.TrustProxyHeaderFrom] or
// [proxyproto.TrustProxyHeaderFromRanges]. Connections are wrapped before
// ConnCallback, while the header is processed lazily on first I/O or address
// access. A callback can type-assert the connection to *proxyproto.Conn and use
// Raw to inspect the transport peer instead of the address supplied by the
// header. It must retain or wrap the supplied connection for PROXY processing
// to remain effective.
type ProxyProtocolConfig struct {
	// ConnPolicy decides whether a connection may supply a PROXY header and how
	// that header is handled. It must return promptly.
	ConnPolicy proxyproto.ConnPolicyFunc
	// ValidateHeader performs application-specific validation after parsing. It
	// must return promptly.
	ValidateHeader proxyproto.Validator
	// ReadHeaderTimeout bounds PROXY header processing. Zero uses the
	// go-proxyproto default; a negative value disables its header timeout.
	ReadHeaderTimeout time.Duration
	// ReadBufferSize controls the per-connection header buffer. A nonpositive
	// value uses the go-proxyproto default. Values below 107 bytes break maximum
	// length version 1 headers.
	ReadBufferSize int
}

func wrapProxyProtocolConn(conn net.Conn, config ProxyProtocolConfig) (net.Conn, error) {
	if _, ok := conn.(*proxyproto.Conn); ok {
		return nil, errProxyProtocolAlreadyWrapped
	}

	policy := proxyproto.REQUIRE
	if config.ConnPolicy != nil {
		var err error
		policy, err = config.ConnPolicy(proxyproto.ConnPolicyOptions{
			Upstream:   conn.RemoteAddr(),
			Downstream: conn.LocalAddr(),
		})
		if err != nil {
			return nil, err
		}
		if policy == proxyproto.SKIP {
			return conn, nil
		}
	}

	options := []func(*proxyproto.Conn){proxyproto.WithPolicy(policy)}
	if config.ValidateHeader != nil {
		options = append(options, proxyproto.ValidateHeader(config.ValidateHeader))
	}
	if config.ReadHeaderTimeout < 0 {
		options = append(options, proxyproto.SetReadHeaderTimeout(0))
	} else if config.ReadHeaderTimeout > 0 {
		options = append(options, proxyproto.SetReadHeaderTimeout(config.ReadHeaderTimeout))
	}
	if config.ReadBufferSize > 0 {
		options = append(options, proxyproto.WithBufferSize(config.ReadBufferSize))
	}
	return proxyproto.NewConn(conn, options...), nil
}
