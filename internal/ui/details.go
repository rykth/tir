package ui

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/rykth/tir/internal/conn"
)

func (m Model) detailsView() string {
	if m.detailsKey == nil {
		return m.theme.Title.Render("Details") + "\n\n" +
			m.theme.TableDim.Render("Press Enter on a connection in Overview to view details.")
	}
	row, found := findRow(m.snap, *m.detailsKey)
	if !found {
		return m.theme.Title.Render("Details") + "\n\n" +
			m.theme.TableDim.Render("Connection closed; no longer in the table.")
	}
	return m.renderDetails(row)
}

func findRow(s *conn.Snapshot, key conn.ConnKey) (conn.ConnView, bool) {
	if s == nil {
		return conn.ConnView{}, false
	}
	for _, r := range s.Rows {
		if r.Key == key {
			return r, true
		}
	}
	return conn.ConnView{}, false
}

func (m Model) renderDetails(r conn.ConnView) string {
	var b strings.Builder
	b.WriteString(m.theme.Title.Render("Connection Details"))
	b.WriteString("\n\n")

	section := func(label string) {
		b.WriteString(m.theme.TableHeader.Render(label))
		b.WriteString("\n")
	}
	field := func(label, value string) {
		if value == "" {
			return
		}
		b.WriteString("  ")
		b.WriteString(m.theme.StatusKey.Render(padRight(label, 14)))
		b.WriteString("  ")
		b.WriteString(value)
		b.WriteString("\n")
	}

	section("Connection")
	field("Protocol", r.Key.Proto.String())
	field("Local", fmtAddr(r.Key.LocalAddr, r.Key.LocalPort))
	field("Remote", fmtAddr(r.Key.RemoteAddr, r.Key.RemotePort))
	if m.cfg.Resolver != nil {
		if host := m.cfg.Resolver.Lookup(r.Key.RemoteAddr); host != "" {
			field("Remote host", host)
		}
	}
	if m.cfg.GeoIP != nil {
		field("Country", m.cfg.GeoIP.CountryCode(r.Key.RemoteAddr))
	}
	field("State", r.State.String())
	if !r.FirstSeen.IsZero() {
		field("First seen", fmt.Sprintf("%s (%s ago)",
			r.FirstSeen.Format("15:04:05"),
			truncDuration(time.Since(r.FirstSeen))))
	}
	if !r.LastSeen.IsZero() {
		field("Last seen", r.LastSeen.Format("15:04:05"))
	}
	b.WriteString("\n")

	section("Traffic")
	field("Sent", fmt.Sprintf("%s — %d pkts", humanBytes(r.BytesSent), r.PktsSent))
	field("Received", fmt.Sprintf("%s — %d pkts", humanBytes(r.BytesRecv), r.PktsRecv))
	field("Rate", fmt.Sprintf("%s ↓ / %s ↑", humanRate(r.RateRecv), humanRate(r.RateSent)))
	b.WriteString("\n")

	if r.ProcessName != "" || r.PID != 0 {
		section("Process")
		field("Name", r.ProcessName)
		if r.PID != 0 {
			field("PID", strconv.Itoa(int(r.PID)))
		}
		b.WriteString("\n")
	}

	if r.DPI.Protocol != "" {
		section("Application (DPI)")
		field("Protocol", r.DPI.Protocol)
		field("Host", r.DPI.Host)
		field("Version", r.DPI.Version)
	}

	return b.String()
}

func truncDuration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return d.Round(time.Second).String()
	case d < time.Hour:
		return d.Round(time.Second).String()
	default:
		return d.Round(time.Minute).String()
	}
}
