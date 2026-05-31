package ui

import (
	"fmt"
	"net/netip"

	"github.com/rykth/tir/internal/conn"
)

const (
	kib = 1024
	mib = 1024 * kib
	gib = 1024 * mib
)

func humanBytes(n uint64) string {
	switch {
	case n < kib:
		return fmt.Sprintf("%dB", n)
	case n < mib:
		return fmt.Sprintf("%.1fK", float64(n)/kib)
	case n < gib:
		return fmt.Sprintf("%.1fM", float64(n)/mib)
	default:
		return fmt.Sprintf("%.1fG", float64(n)/gib)
	}
}

func humanRate(r float64) string {
	if r < 1 {
		return "—"
	}
	switch {
	case r < kib:
		return fmt.Sprintf("%.0fB/s", r)
	case r < mib:
		return fmt.Sprintf("%.1fK/s", r/kib)
	case r < gib:
		return fmt.Sprintf("%.1fM/s", r/mib)
	default:
		return fmt.Sprintf("%.1fG/s", r/gib)
	}
}

func fmtAddr(a netip.Addr, port uint16) string {
	if a.Is6() && !a.Is4In6() {
		return fmt.Sprintf("[%s]:%d", a, port)
	}
	return fmt.Sprintf("%s:%d", a, port)
}

func (t Theme) protoStyle(p conn.Proto) (style string) {
	switch p {
	case conn.ProtoTCP:
		return t.ProtoTCP.Render(p.String())
	case conn.ProtoUDP:
		return t.ProtoUDP.Render(p.String())
	default:
		return t.TableDim.Render(p.String())
	}
}

func appLabel(d conn.DPIInfo) string {
	switch {
	case d.Protocol == "":
		return "—"
	case d.Protocol == "SSH":
		return d.Version
	case d.Host != "":
		return d.Protocol + ":" + d.Host
	default:
		return d.Protocol
	}
}
