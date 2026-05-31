package ui

import (
	"fmt"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/rykth/tir/internal/interfaces"
)

// InterfaceStatsProvider exposes the latest sysfs counters
type InterfaceStatsProvider interface {
	Latest() *interfaces.Snapshot
}

func (m Model) interfacesView() string {
	if m.cfg.Interfaces == nil {
		return m.theme.Title.Render("Interfaces") + "\n\n" +
			m.theme.TableDim.Render("Interface statistics collector is not running.")
	}
	snap := m.cfg.Interfaces.Latest()
	if snap == nil {
		return m.theme.Title.Render("Interfaces") + "\n\n" +
			m.theme.TableDim.Render("Waiting for first sample…")
	}

	rows := slices.Clone(snap.Interfaces)
	slices.SortFunc(rows, func(a, b interfaces.Stats) int {
		switch {
		case a.Name == m.cfg.Interface && b.Name != m.cfg.Interface:
			return -1
		case b.Name == m.cfg.Interface && a.Name != m.cfg.Interface:
			return 1
		case a.Name == "lo" && b.Name != "lo":
			return 1
		case b.Name == "lo" && a.Name != "lo":
			return -1
		default:
			return strings.Compare(a.Name, b.Name)
		}
	})

	var b strings.Builder
	b.WriteString(m.theme.Title.Render("Interfaces"))
	b.WriteString("\n")
	b.WriteString(m.theme.TableDim.Render(
		fmt.Sprintf("Sampled at %s — %d interface(s)",
			snap.CollectedAt.Format("15:04:05"), len(rows))))
	b.WriteString("\n\n")

	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
		m.theme.TableHeader.Render("Interface"),
		m.theme.TableHeader.Render("Down/Up"),
		m.theme.TableHeader.Render("RX Bytes"),
		m.theme.TableHeader.Render("TX Bytes"),
		m.theme.TableHeader.Render("RX Pkts"),
		m.theme.TableHeader.Render("TX Pkts"),
		m.theme.TableHeader.Render("Errors"),
		m.theme.TableHeader.Render("Drops"),
	)
	for _, s := range rows {
		name := s.Name
		if s.Name == m.cfg.Interface {
			name = m.theme.Title.Render(name + " *")
		}
		fmt.Fprintf(tw, "%s\t%s / %s\t%s\t%s\t%d\t%d\t%d / %d\t%d / %d\n",
			name,
			humanRate(s.RXRate), humanRate(s.TXRate),
			humanBytes(s.RXBytes),
			humanBytes(s.TXBytes),
			s.RXPackets,
			s.TXPackets,
			s.RXErrors, s.TXErrors,
			s.RXDropped, s.TXDropped,
		)
	}
	_ = tw.Flush()
	return b.String()
}
