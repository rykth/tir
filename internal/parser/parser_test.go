package parser

import (
	"net/netip"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/rykth/tir/internal/conn"
)

func tcpPacket(t *testing.T, src, dst string, sport, dport uint16, fin, syn, ack bool) gopacket.Packet {
	t.Helper()
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    netip.MustParseAddr(src).AsSlice(),
		DstIP:    netip.MustParseAddr(dst).AsSlice(),
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(sport),
		DstPort: layers.TCPPort(dport),
		FIN:     fin,
		SYN:     syn,
		ACK:     ack,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("set checksum: %v", err)
	}
	return serialize(t, ip, tcp)
}

func udpPacket(t *testing.T, src, dst string, sport, dport uint16, payload []byte) gopacket.Packet {
	t.Helper()
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    netip.MustParseAddr(src).AsSlice(),
		DstIP:    netip.MustParseAddr(dst).AsSlice(),
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(sport),
		DstPort: layers.UDPPort(dport),
	}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("set checksum: %v", err)
	}
	return serialize(t, ip, udp, gopacket.Payload(payload))
}

func serialize(t *testing.T, ls ...gopacket.SerializableLayer) gopacket.Packet {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ls...); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	pkt.Metadata().CaptureInfo.Length = len(buf.Bytes())
	pkt.Metadata().Timestamp = time.Now()
	return pkt
}

func TestParserTCPSyn(t *testing.T) {
	tbl := conn.NewTable()
	local := netip.MustParseAddr("10.0.0.1")
	p := New(tbl, map[netip.Addr]bool{local: true}, nil)

	p.Handle(tcpPacket(t, "10.0.0.1", "10.0.0.2", 12345, 80, false, true, false))

	if got := tbl.Len(); got != 1 {
		t.Fatalf("Len = %d, want 1", got)
	}
	r := tbl.Snapshot(time.Now()).Rows[0]
	if r.Key.LocalAddr != local || r.Key.LocalPort != 12345 {
		t.Errorf("local = %s:%d, want 10.0.0.1:12345", r.Key.LocalAddr, r.Key.LocalPort)
	}
	if r.Key.RemoteAddr.String() != "10.0.0.2" || r.Key.RemotePort != 80 {
		t.Errorf("remote = %s:%d, want 10.0.0.2:80", r.Key.RemoteAddr, r.Key.RemotePort)
	}
	if r.State != conn.StateSynSent {
		t.Errorf("State = %s, want SYN_SENT", r.State)
	}
	if r.PktsSent != 1 || r.PktsRecv != 0 {
		t.Errorf("packets sent/recv = %d/%d, want 1/0", r.PktsSent, r.PktsRecv)
	}
}

func TestParserTCPHandshakeConverges(t *testing.T) {
	tbl := conn.NewTable()
	local := netip.MustParseAddr("10.0.0.1")
	p := New(tbl, map[netip.Addr]bool{local: true}, nil)

	p.Handle(tcpPacket(t, "10.0.0.1", "10.0.0.2", 12345, 80, false, true, false)) // SYN out
	p.Handle(tcpPacket(t, "10.0.0.2", "10.0.0.1", 80, 12345, false, true, true))  // SYN-ACK in
	p.Handle(tcpPacket(t, "10.0.0.1", "10.0.0.2", 12345, 80, false, false, true)) // ACK out

	r := tbl.Snapshot(time.Now()).Rows[0]
	if r.State != conn.StateEstablished {
		t.Fatalf("State = %s, want ESTABLISHED", r.State)
	}
	if r.PktsSent != 2 || r.PktsRecv != 1 {
		t.Errorf("packets sent/recv = %d/%d, want 2/1", r.PktsSent, r.PktsRecv)
	}
}

func TestParserUDPMarkedActive(t *testing.T) {
	tbl := conn.NewTable()
	local := netip.MustParseAddr("10.0.0.1")
	p := New(tbl, map[netip.Addr]bool{local: true}, nil)

	p.Handle(udpPacket(t, "10.0.0.1", "8.8.8.8", 12345, 53, []byte("query")))

	r := tbl.Snapshot(time.Now()).Rows[0]
	if r.Key.Proto != conn.ProtoUDP {
		t.Errorf("Proto = %s, want UDP", r.Key.Proto)
	}
	if r.State != conn.StateUDPActive {
		t.Errorf("State = %s, want UDP_ACTIVE", r.State)
	}
	if r.BytesSent == 0 {
		t.Errorf("BytesSent = 0, want > 0")
	}
}

func TestParserSameConnectionBothDirections(t *testing.T) {
	tbl := conn.NewTable()
	local := netip.MustParseAddr("10.0.0.1")
	p := New(tbl, map[netip.Addr]bool{local: true}, nil)

	p.Handle(tcpPacket(t, "10.0.0.1", "10.0.0.2", 12345, 80, false, true, false))
	p.Handle(tcpPacket(t, "10.0.0.2", "10.0.0.1", 80, 12345, false, true, true))

	if got := tbl.Len(); got != 1 {
		t.Fatalf("Len = %d, want 1 (both directions should share a key)", got)
	}
}

func TestParserSkipsNonIPPackets(t *testing.T) {
	tbl := conn.NewTable()
	p := New(tbl, nil, nil)

	// a packet with no recognizable network layer
	pkt := gopacket.NewPacket([]byte{0xff, 0xff, 0xff, 0xff}, layers.LayerTypeIPv4, gopacket.Default)
	p.Handle(pkt)
	if got := tbl.Len(); got != 0 {
		t.Errorf("Len = %d, want 0", got)
	}
}
