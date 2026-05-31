package ui

import (
	"fmt"
	"slices"
	"strings"

	"github.com/rykth/tir/internal/conn"
)

var sparkChars = []rune{'▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

const sparkLen = 60

type graphSeries struct {
	down []float64
	up   []float64
}

func (g *graphSeries) push(down, up float64) {
	g.down = appendRing(g.down, down, sparkLen)
	g.up = appendRing(g.up, up, sparkLen)
}

func appendRing(s []float64, v float64, max int) []float64 {
	s = append(s, v)
	if len(s) > max {
		s = s[len(s)-max:]
	}
	return s
}

func (m Model) graphView() string {
	if m.snap == nil {
		return m.theme.Title.Render("Graph") + "\n\n" +
			m.theme.TableDim.Render("Waiting for first snapshot…")
	}

	var b strings.Builder
	b.WriteString(m.theme.Title.Render("Bandwidth"))
	b.WriteString("\n")

	var totalDown, totalUp float64
	for _, r := range m.snap.Rows {
		totalDown += r.RateRecv
		totalUp += r.RateSent
	}

	fmt.Fprintf(&b, "  ↓ %s   %s\n", humanRate(totalDown), sparkline(m.series.down))
	fmt.Fprintf(&b, "  ↑ %s   %s\n", humanRate(totalUp), sparkline(m.series.up))
	b.WriteString("\n")

	b.WriteString(m.theme.Title.Render("Top processes (by bandwidth)"))
	b.WriteString("\n")
	for _, p := range topProcesses(m.snap.Rows, 5) {
		fmt.Fprintf(&b, "  %-20s  %s ↓ / %s ↑\n",
			truncate(orDash(p.name), 20), humanRate(p.down), humanRate(p.up))
	}
	b.WriteString("\n")

	b.WriteString(m.theme.Title.Render("Application protocols"))
	b.WriteString("\n")
	for _, e := range appDistribution(m.snap.Rows) {
		fmt.Fprintf(&b, "  %-12s  %d conn(s)\n", e.proto, e.count)
	}
	return b.String()
}

func sparkline(s []float64) string {
	if len(s) == 0 {
		return ""
	}
	max := 0.0
	for _, v := range s {
		if v > max {
			max = v
		}
	}
	if max <= 0 {
		return strings.Repeat(string(sparkChars[0]), len(s))
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, v := range s {
		idx := int(v / max * float64(len(sparkChars)-1))
		if idx < 0 {
			idx = 0
		}
		if idx >= len(sparkChars) {
			idx = len(sparkChars) - 1
		}
		b.WriteRune(sparkChars[idx])
	}
	return b.String()
}

type processBandwidth struct {
	name        string
	down, up    float64
	connections int
}

func topProcesses(rows []conn.ConnView, n int) []processBandwidth {
	agg := map[string]*processBandwidth{}
	for _, r := range rows {
		name := r.ProcessName
		p, ok := agg[name]
		if !ok {
			p = &processBandwidth{name: name}
			agg[name] = p
		}
		p.down += r.RateRecv
		p.up += r.RateSent
		p.connections++
	}
	list := make([]processBandwidth, 0, len(agg))
	for _, p := range agg {
		list = append(list, *p)
	}
	slices.SortFunc(list, func(a, b processBandwidth) int {
		ta := a.down + a.up
		tb := b.down + b.up
		switch {
		case ta > tb:
			return -1
		case ta < tb:
			return 1
		default:
			return 0
		}
	})
	if len(list) > n {
		list = list[:n]
	}
	return list
}

type appEntry struct {
	proto string
	count int
}

func appDistribution(rows []conn.ConnView) []appEntry {
	counts := map[string]int{}
	for _, r := range rows {
		p := r.DPI.Protocol
		if p == "" {
			p = "—"
		}
		counts[p]++
	}
	out := make([]appEntry, 0, len(counts))
	for proto, c := range counts {
		out = append(out, appEntry{proto: proto, count: c})
	}
	slices.SortFunc(out, func(a, b appEntry) int {
		switch {
		case a.count > b.count:
			return -1
		case a.count < b.count:
			return 1
		default:
			return strings.Compare(a.proto, b.proto)
		}
	})
	return out
}
