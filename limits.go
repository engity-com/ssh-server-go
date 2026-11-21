package ssh

import "context"

// LimitRejectionReason identifies the protection limit that rejected an
// operation. Global limits apply to one Serve or HandleConn call, not to all
// concurrent calls on the same Server.
type LimitRejectionReason uint8

const (
	// LimitRejectionMaxStartups includes both random early drops and the hard
	// limit on unauthenticated connections.
	LimitRejectionMaxStartups LimitRejectionReason = iota + 1
	// LimitRejectionMaxConnections is the global authenticated connection limit.
	LimitRejectionMaxConnections
	// LimitRejectionMaxChannels is the global active channel limit.
	LimitRejectionMaxChannels
	// LimitRejectionMaxChannelsPerConnection is the connection's channel limit.
	LimitRejectionMaxChannelsPerConnection
	// LimitRejectionMaxSessionsPerConnection is the connection's session limit.
	LimitRejectionMaxSessionsPerConnection
	// LimitRejectionMaxReverseForwards is the global reverse-forward listener limit.
	LimitRejectionMaxReverseForwards
	// LimitRejectionMaxReverseForwardsPerConnection is the connection's
	// reverse-forward listener limit.
	LimitRejectionMaxReverseForwardsPerConnection
)

// String returns a fixed, low-cardinality name suitable for a metrics label.
func (r LimitRejectionReason) String() string {
	switch r {
	case LimitRejectionMaxStartups:
		return "max_startups"
	case LimitRejectionMaxConnections:
		return "max_connections"
	case LimitRejectionMaxChannels:
		return "max_channels"
	case LimitRejectionMaxChannelsPerConnection:
		return "max_channels_per_connection"
	case LimitRejectionMaxSessionsPerConnection:
		return "max_sessions_per_connection"
	case LimitRejectionMaxReverseForwards:
		return "max_reverse_forwards"
	case LimitRejectionMaxReverseForwardsPerConnection:
		return "max_reverse_forwards_per_connection"
	default:
		return "unknown"
	}
}

func (s *serveContext) onLimitRejected(ctx context.Context, reason LimitRejectionReason) {
	if s.LimitRejectedCallback == nil {
		return
	}
	err := s.LimitRejectedCallback(reason)
	if err == nil {
		return
	}

	scope := limitRejectionErrorScope(reason)
	// Locate the callback failure at the rejected resource, even if the callback
	// returns an error with another location. These scopes dispatch synchronously.
	err = locateError(scope, ErrorOperationHandle, err)
	logger := s.logger()
	// Observation errors must not send a reply or close a connection, including
	// when ErrorHandler requests closeAfterResponse. Ignore continuation decisions.
	response := newErrorResponse(func([]byte, bool) error { return ErrErrorResponseUnsupported })
	_, filteredErr := dispatchError(ctx, logger, s.errorHandler, scope, ErrorOperationHandle, err, response, defaultLogAndFailErrorAction)
	if filteredErr != nil {
		logDispatchErrorEscalate(logger, scope, ErrorOperationHandle, filteredErr, err)
	}
}

func limitRejectionErrorScope(reason LimitRejectionReason) ErrorScope {
	switch reason {
	case LimitRejectionMaxChannels, LimitRejectionMaxChannelsPerConnection:
		return ErrorScopeChannel
	case LimitRejectionMaxSessionsPerConnection:
		return ErrorScopeSession
	case LimitRejectionMaxReverseForwards, LimitRejectionMaxReverseForwardsPerConnection:
		return ErrorScopeForwarding
	default:
		return ErrorScopeConnection
	}
}
