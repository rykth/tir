package ui

import (
	"cmp"
	"slices"

	"github.com/rykth/tir/internal/conn"
)

// SortColumn identifies one of the sortable table columns.
type SortColumn int

const (
	SortProto SortColumn = iota
	SortLocal
	SortRemote
	SortState
	SortApp       // DPI-detected protocol + host
	SortBandwidth // combined RateSent + RateRecv
	SortPackets   // combined PktsSent + PktsRecv
	SortProcess

	numSortColumns = int(SortProcess) + 1
)

// Label returns a short header label for the column
func (c SortColumn) Label() string {
	switch c {
	case SortProto:
		return "Pro"
	case SortLocal:
		return "Local Address"
	case SortRemote:
		return "Remote Address"
	case SortState:
		return "State"
	case SortApp:
		return "App"
	case SortBandwidth:
		return "Down/Up"
	case SortPackets:
		return "Pkts"
	case SortProcess:
		return "Process"
	default:
		return "?"
	}
}

// Next returns the next column in cycle order
func (c SortColumn) Next() SortColumn {
	return SortColumn((int(c) + 1) % numSortColumns)
}

// DefaultDescending reports whether the column should start in descending
// order (true for numeric/bandwidth columns, false for textual ones)
func (c SortColumn) DefaultDescending() bool {
	switch c {
	case SortBandwidth, SortPackets:
		return true
	default:
		return false
	}
}

func sortRows(rows []conn.ConnView, col SortColumn, desc bool) {
	base := compareFor(col)
	slices.SortStableFunc(rows, func(a, b conn.ConnView) int {
		if desc {
			return -base(a, b)
		}
		return base(a, b)
	})
}

func compareFor(col SortColumn) func(a, b conn.ConnView) int {
	switch col {
	case SortProto:
		return func(a, b conn.ConnView) int {
			return cmp.Compare(a.Key.Proto, b.Key.Proto)
		}
	case SortLocal:
		return func(a, b conn.ConnView) int {
			if c := a.Key.LocalAddr.Compare(b.Key.LocalAddr); c != 0 {
				return c
			}
			return cmp.Compare(a.Key.LocalPort, b.Key.LocalPort)
		}
	case SortRemote:
		return func(a, b conn.ConnView) int {
			if c := a.Key.RemoteAddr.Compare(b.Key.RemoteAddr); c != 0 {
				return c
			}
			return cmp.Compare(a.Key.RemotePort, b.Key.RemotePort)
		}
	case SortState:
		return func(a, b conn.ConnView) int {
			return cmp.Compare(a.State, b.State)
		}
	case SortApp:
		return func(a, b conn.ConnView) int {
			if c := cmp.Compare(a.DPI.Protocol, b.DPI.Protocol); c != 0 {
				return c
			}
			return cmp.Compare(a.DPI.Host, b.DPI.Host)
		}
	case SortBandwidth:
		return func(a, b conn.ConnView) int {
			return cmp.Compare(a.RateSent+a.RateRecv, b.RateSent+b.RateRecv)
		}
	case SortPackets:
		return func(a, b conn.ConnView) int {
			return cmp.Compare(a.PktsSent+a.PktsRecv, b.PktsSent+b.PktsRecv)
		}
	case SortProcess:
		return func(a, b conn.ConnView) int {
			return cmp.Compare(a.ProcessName, b.ProcessName)
		}
	default:
		return func(conn.ConnView, conn.ConnView) int {
			return 0
		}
	}
}
