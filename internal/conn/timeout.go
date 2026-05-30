package conn

import "time"

// protocol-aware timeouts
const (
	timeoutTCPEstablished = 10 * time.Minute
	timeoutTCPHalfOpen    = 60 * time.Second
	timeoutTCPTimeWait    = 30 * time.Second
	timeoutTCPClosed      = 5 * time.Second
	timeoutUDP            = 60 * time.Second
	timeoutQUICConnected  = 3 * time.Minute
	timeoutQUICHandshake  = 60 * time.Second
	timeoutQUICClosed     = 10 * time.Second
)

// timeoutFor returns how long a connection in its current state may remain
// idle before being evicted by Cleanup
func timeoutFor(c *Connection) time.Duration {
	switch c.Key.Proto {
	case ProtoTCP:
		switch c.State {
		case StateClosed:
			return timeoutTCPClosed
		case StateTimeWait:
			return timeoutTCPTimeWait
		case StateSynSent, StateSynRecv,
			StateFinWait1, StateFinWait2,
			StateCloseWait, StateLastAck, StateClosing:
			return timeoutTCPHalfOpen
		}
		return timeoutTCPEstablished
	case ProtoUDP:
		switch c.State {
		case StateQUICClosed:
			return timeoutQUICClosed
		case StateQUICInitial, StateQUICHandshake:
			return timeoutQUICHandshake
		case StateQUICConnected:
			return timeoutQUICConnected
		}
		// HTTP/3 / QUIC sessions also get the QUIC-connected timeout once
		// DPI has identified them, even if the state machine hasn't
		// transitioned yet (parser sees encrypted post-handshake traffic)
		if c.DPI.Protocol == "QUIC" {
			return timeoutQUICConnected
		}
		return timeoutUDP
	}
	return timeoutUDP
}
