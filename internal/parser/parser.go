package parser

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/rykth/tir/internal/conn"
	"github.com/rykth/tir/internal/dpi"
)

const maxDPIAttempts = 16

// Parser turns gopacket.Packet values into Connection updates
type Parser struct {
	table      *conn.Table
	localAddrs map[netip.Addr]bool
	registry   *dpi.Registry
}

// New returns a Parser writing into table
func New(table *conn.Table, localAddrs map[netip.Addr]bool, registry *dpi.Registry) *Parser {
	if localAddrs == nil {
		localAddrs = map[netip.Addr]bool{}
	}
	return &Parser{table, localAddrs, registry}
}

// Run starts `workers` goroutines that consume packets from `in` until the
// channel closes or ctx is canceled
func (p *Parser) Run(ctx context.Context, in <-chan gopacket.Packet, workers int) error {
	if workers <= 0 {
		workers = 1
	}
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			p.consume(ctx, in)
		}()
	}
	wg.Wait()
	return nil
}

func (p *Parser) consume(ctx context.Context, in <-chan gopacket.Packet) {
	for {
		select {
		case <-ctx.Done():
			return
		case pkt, ok := <-in:
			if !ok {
				return
			}
			p.Handle(pkt)
		}
	}
}

// Handle decodes a single packet and applies its effect to the table
// Exported for testing (the production path is Run)
func (p *Parser) Handle(pkt gopacket.Packet) {
	src, dst, ok := networkAddrs(pkt)
	if !ok {
		return
	}
	proto, sport, dport, flags, ok := transportInfo(pkt)
	if !ok {
		return
	}

	outgoing, key := p.orient(proto, src, dst, sport, dport)

	pktLen := uint64(pkt.Metadata().CaptureInfo.Length)
	if pktLen == 0 {
		pktLen = uint64(len(pkt.Data()))
	}

	ts := pkt.Metadata().Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}

	var payload []byte
	if p.registry != nil {
		if tl := pkt.TransportLayer(); tl != nil {
			payload = tl.LayerPayload()
		}
	}

	p.table.Apply(key, ts, func(c *conn.Connection) {
		if outgoing {
			c.BytesSent += pktLen
			c.PktsSent++
		} else {
			c.BytesRecv += pktLen
			c.PktsRecv++
		}

		switch proto {
		case conn.ProtoTCP:
			c.State = c.State.ApplyTCP(flags, outgoing)
		case conn.ProtoUDP:
			c.State = conn.StateUDPActive
		}

		// DPI dispatch: skip once a match has been recorded or the budget
		// is exhausted
		//
		// we run under the shard lock; dissectors are pure functions on the
		// payload bytes so this is safe
		if p.registry != nil && c.DPI.Protocol == "" && c.DPIAttempts < maxDPIAttempts && len(payload) > 0 {
			ctx := dpi.Context{
				Outgoing:   outgoing,
				LocalPort:  key.LocalPort,
				RemotePort: key.RemotePort,
			}
			if info, ok := p.registry.Inspect(payload, ctx); ok {
				c.DPI = info
				// QUIC: first Initial seen -> mark the state explicitly so
				// timeouts pick up the longer connected interval
				if info.Protocol == "QUIC" {
					c.State = conn.StateQUICInitial
				}
			}
			c.DPIAttempts++
		}
	})
}

func (p *Parser) orient(proto conn.Proto, src, dst netip.Addr, sport, dport uint16) (outgoing bool, key conn.ConnKey) {
	srcLocal := p.localAddrs[src]
	dstLocal := p.localAddrs[dst]

	switch {
	case srcLocal && !dstLocal:
		return true, conn.ConnKey{Proto: proto, LocalAddr: src, LocalPort: sport, RemoteAddr: dst, RemotePort: dport}
	case !srcLocal && dstLocal:
		return false, conn.ConnKey{Proto: proto, LocalAddr: dst, LocalPort: dport, RemoteAddr: src, RemotePort: sport}
	}

	// both local (loopback) or both remote (bridge / span port)
	//
	// pick the smaller (addr, port) as "local" so both directions hash to the
	// same connection (direction is unknown but the choice is deterministic)
	cmp := src.Compare(dst)
	if cmp < 0 || (cmp == 0 && sport < dport) {
		return true, conn.ConnKey{Proto: proto, LocalAddr: src, LocalPort: sport, RemoteAddr: dst, RemotePort: dport}
	}
	return false, conn.ConnKey{Proto: proto, LocalAddr: dst, LocalPort: dport, RemoteAddr: src, RemotePort: sport}
}

func networkAddrs(pkt gopacket.Packet) (src, dst netip.Addr, ok bool) {
	switch nl := pkt.NetworkLayer().(type) {
	case *layers.IPv4:
		s, sok := netip.AddrFromSlice(nl.SrcIP)
		d, dok := netip.AddrFromSlice(nl.DstIP)
		if !sok || !dok {
			return netip.Addr{}, netip.Addr{}, false
		}
		return s.Unmap(), d.Unmap(), true
	case *layers.IPv6:
		s, sok := netip.AddrFromSlice(nl.SrcIP)
		d, dok := netip.AddrFromSlice(nl.DstIP)
		if !sok || !dok {
			return netip.Addr{}, netip.Addr{}, false
		}
		return s, d, true
	default:
		return netip.Addr{}, netip.Addr{}, false
	}
}

func transportInfo(pkt gopacket.Packet) (proto conn.Proto, sport, dport uint16, flags conn.TCPFlags, ok bool) {
	switch tl := pkt.TransportLayer().(type) {
	case *layers.TCP:
		return conn.ProtoTCP, uint16(tl.SrcPort), uint16(tl.DstPort), tcpFlags(tl), true
	case *layers.UDP:
		return conn.ProtoUDP, uint16(tl.SrcPort), uint16(tl.DstPort), 0, true
	default:
		return 0, 0, 0, 0, false
	}
}

func tcpFlags(t *layers.TCP) conn.TCPFlags {
	var f conn.TCPFlags
	if t.FIN {
		f |= conn.TCPFin
	}
	if t.SYN {
		f |= conn.TCPSyn
	}
	if t.RST {
		f |= conn.TCPRst
	}
	if t.PSH {
		f |= conn.TCPPsh
	}
	if t.ACK {
		f |= conn.TCPAck
	}
	if t.URG {
		f |= conn.TCPUrg
	}
	return f
}
