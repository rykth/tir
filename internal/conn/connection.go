package conn

import (
	"net/netip"
	"time"
)

type Proto uint8 // L4 protocol of a connection

const (
	ProtoUnknown Proto = iota
	ProtoTCP
	ProtoUDP
	ProtoICMP
	ProtoICMPv6
)

func (p Proto) String() string {
	switch p {
	case ProtoTCP:
		return "TCP"
	case ProtoUDP:
		return "UDP"
	case ProtoICMP:
		return "ICMP"
	case ProtoICMPv6:
		return "ICMPv6"
	default:
		return "?"
	}
}

// ConnKey is the canonical 5-tuple identifying a connection
type ConnKey struct {
	Proto      Proto
	LocalAddr  netip.Addr // value type(no heap allocation)
	LocalPort  uint16
	RemoteAddr netip.Addr // value type(no heap allocation)
	RemotePort uint16
}

// Connection holds the live, mutable state of a flow
type Connection struct {
	Key       ConnKey
	State     State
	FirstSeen time.Time
	LastSeen  time.Time

	BytesSent uint64
	BytesRecv uint64
	PktsSent  uint64
	PktsRecv  uint64

	// exponentially smoothed bytes/sec (updated by Table.RefreshRates)
	RateSent float64
	RateRecv float64

	// process attribution (populated by the process.Resolver if one is wired)
	PID         int32 // PID == 0 means unknown (the kernel reserves 0 for the swapper)
	ProcessName string

	// deep packet inspection result (empty Protocol means no dissector has
	// matched).
	DPI         DPIInfo
	DPIAttempts uint8 // counts how many packets we've inspected (the parser stops dispatching once the budget is exhausted)

	// last byte counts sampled by RefreshRates(used to compute deltas)
	lastSampledSent uint64
	lastSampledRecv uint64
}

// DPIInfo describes a connections application-layer protocol, as detected
// by a dpi.Dissector (the zero value means "unmatched / unknown")
type DPIInfo struct {
	Protocol string // e.g. "HTTP", "HTTPS", "DNS", "SSH"
	Host     string // SNI for HTTPS, Host header for HTTP, query name for DNS
	Version  string // SSH banner, TLS legacy_version, "query" / "response" for DNS
}
