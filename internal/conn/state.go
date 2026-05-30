package conn

// State is the protocol-aware state of a connection
type State uint8

const (
	StateUnknown State = iota

	// TCP states (subset of RFC 793)
	StateSynSent
	StateSynRecv
	StateEstablished
	StateFinWait1
	StateFinWait2
	StateTimeWait
	StateCloseWait
	StateLastAck
	StateClosing
	StateClosed

	// UDP states
	StateUDPActive
	StateUDPIdle

	// QUIC states (derived from DPI). The parser doesn't see post-handshake
	// QUIC framing without the post-Initial keys, so transitions past
	// Initial/Handshake are best-effort.
	StateQUICInitial
	StateQUICHandshake
	StateQUICConnected
	StateQUICClosed
)

// String returns the canonical name of the state (matches netstat/ss output)
func (s State) String() string {
	switch s {
	case StateSynSent:
		return "SYN_SENT"
	case StateSynRecv:
		return "SYN_RECV"
	case StateEstablished:
		return "ESTABLISHED"
	case StateFinWait1:
		return "FIN_WAIT1"
	case StateFinWait2:
		return "FIN_WAIT2"
	case StateTimeWait:
		return "TIME_WAIT"
	case StateCloseWait:
		return "CLOSE_WAIT"
	case StateLastAck:
		return "LAST_ACK"
	case StateClosing:
		return "CLOSING"
	case StateClosed:
		return "CLOSED"
	case StateUDPActive:
		return "UDP_ACTIVE"
	case StateUDPIdle:
		return "UDP_IDLE"
	case StateQUICInitial:
		return "QUIC_INITIAL"
	case StateQUICHandshake:
		return "QUIC_HANDSHAKE"
	case StateQUICConnected:
		return "QUIC_CONNECTED"
	case StateQUICClosed:
		return "QUIC_CLOSED"
	default:
		return "-"
	}
}

// TCPFlags is a bitset of observed TCP control flags
type TCPFlags uint8

const (
	TCPFin TCPFlags = 1 << iota
	TCPSyn
	TCPRst
	TCPPsh
	TCPAck
	TCPUrg
)

// ApplyTCP returns the next state given observed TCP flags
//
// outgoing=true means the packet was sent by the local endpoint
func (s State) ApplyTCP(flags TCPFlags, outgoing bool) State {
	syn := flags&TCPSyn != 0
	ack := flags&TCPAck != 0
	fin := flags&TCPFin != 0
	rst := flags&TCPRst != 0

	if rst {
		return StateClosed
	}

	switch s {
	case StateUnknown:
		switch {
		case syn && !ack && outgoing:
			return StateSynSent
		case syn && !ack && !outgoing:
			return StateSynRecv
		default:
			// Either SYN-ACK without prior SYN, or a mid-stream packet;
			// assume the handshake completed before capture started.
			return StateEstablished
		}

	case StateSynSent:
		if syn && ack {
			return StateEstablished
		}

	case StateSynRecv:
		if ack && !syn {
			return StateEstablished
		}

	case StateEstablished:
		if fin && outgoing {
			return StateFinWait1
		}
		if fin && !outgoing {
			return StateCloseWait
		}

	case StateFinWait1:
		switch {
		case fin && ack && !outgoing:
			return StateTimeWait
		case fin && !outgoing:
			return StateClosing
		case ack && !fin:
			return StateFinWait2
		}

	case StateFinWait2:
		if fin {
			return StateTimeWait
		}

	case StateCloseWait:
		if fin && outgoing {
			return StateLastAck
		}

	case StateLastAck:
		if ack {
			return StateClosed
		}

	case StateClosing:
		if ack {
			return StateTimeWait
		}
	}

	return s
}
