package ui

import (
	"net/netip"
	"testing"

	"github.com/rykth/tir/internal/conn"
)

func mkView(proto conn.Proto, la string, lp uint16, ra string, rp uint16, state conn.State, tx, rx uint64, rateTx, rateRx float64) conn.ConnView {
	return conn.ConnView{
		Key: conn.ConnKey{
			Proto:      proto,
			LocalAddr:  netip.MustParseAddr(la),
			LocalPort:  lp,
			RemoteAddr: netip.MustParseAddr(ra),
			RemotePort: rp,
		},
		State:     state,
		BytesSent: tx,
		BytesRecv: rx,
		RateSent:  rateTx,
		RateRecv:  rateRx,
	}
}

func TestSortColumnCycleVisitsEveryColumn(t *testing.T) {
	seen := map[SortColumn]bool{}
	c := SortProto
	for range numSortColumns {
		seen[c] = true
		c = c.Next()
	}
	if c != SortProto {
		t.Errorf("Next did not return to start: ended at %v", c)
	}
	if len(seen) != numSortColumns {
		t.Errorf("visited %d columns, want %d", len(seen), numSortColumns)
	}
}

func TestSortColumnDefaultDescending(t *testing.T) {
	desc := map[SortColumn]bool{SortBandwidth: true, SortPackets: true}
	for i := range numSortColumns {
		c := SortColumn(i)
		if got := c.DefaultDescending(); got != desc[c] {
			t.Errorf("%s DefaultDescending = %v, want %v", c.Label(), got, desc[c])
		}
	}
}

func TestSortRowsByBandwidthDescending(t *testing.T) {
	rows := []conn.ConnView{
		mkView(conn.ProtoTCP, "10.0.0.1", 1, "10.0.0.2", 2, conn.StateEstablished, 0, 0, 100, 100),
		mkView(conn.ProtoTCP, "10.0.0.1", 3, "10.0.0.2", 4, conn.StateEstablished, 0, 0, 1000, 1000),
		mkView(conn.ProtoTCP, "10.0.0.1", 5, "10.0.0.2", 6, conn.StateEstablished, 0, 0, 10, 10),
	}
	sortRows(rows, SortBandwidth, true)
	if rows[0].Key.LocalPort != 3 {
		t.Errorf("first row port = %d, want 3 (highest bandwidth)", rows[0].Key.LocalPort)
	}
	if rows[2].Key.LocalPort != 5 {
		t.Errorf("last row port = %d, want 5 (lowest bandwidth)", rows[2].Key.LocalPort)
	}
}

func TestSortRowsByRemoteAscending(t *testing.T) {
	rows := []conn.ConnView{
		mkView(conn.ProtoTCP, "10.0.0.1", 1, "10.0.0.30", 80, conn.StateEstablished, 0, 0, 0, 0),
		mkView(conn.ProtoTCP, "10.0.0.1", 2, "10.0.0.10", 80, conn.StateEstablished, 0, 0, 0, 0),
		mkView(conn.ProtoTCP, "10.0.0.1", 3, "10.0.0.20", 80, conn.StateEstablished, 0, 0, 0, 0),
	}
	sortRows(rows, SortRemote, false)
	want := []string{"10.0.0.10", "10.0.0.20", "10.0.0.30"}
	for i, w := range want {
		if got := rows[i].Key.RemoteAddr.String(); got != w {
			t.Errorf("rows[%d].Remote = %s, want %s", i, got, w)
		}
	}
}

func TestSortRowsStablePreservesInsertionOrder(t *testing.T) {
	rows := []conn.ConnView{
		mkView(conn.ProtoTCP, "10.0.0.1", 1, "10.0.0.2", 80, conn.StateEstablished, 0, 0, 0, 0),
		mkView(conn.ProtoTCP, "10.0.0.1", 2, "10.0.0.2", 80, conn.StateEstablished, 0, 0, 0, 0),
		mkView(conn.ProtoTCP, "10.0.0.1", 3, "10.0.0.2", 80, conn.StateEstablished, 0, 0, 0, 0),
	}
	sortRows(rows, SortPackets, true)
	for i, p := range []uint16{1, 2, 3} {
		if rows[i].Key.LocalPort != p {
			t.Errorf("stable sort broken: rows[%d].LocalPort = %d, want %d", i, rows[i].Key.LocalPort, p)
		}
	}
}

func TestTruncateRespectsWidth(t *testing.T) {
	cases := []struct {
		in   string
		n    int
		want string
	}{
		{"short", 10, "short"},
		{"exactly10c", 10, "exactly10c"},
		{"longerstring", 6, "longe…"},
		{"x", 1, "x"},
		{"xy", 1, "…"},
		{"", 5, ""},
	}
	for _, tc := range cases {
		if got := truncate(tc.in, tc.n); got != tc.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tc.in, tc.n, got, tc.want)
		}
	}
}

func TestHumanBytesRange(t *testing.T) {
	cases := []struct {
		in   uint64
		want string
	}{
		{0, "0B"},
		{512, "512B"},
		{1024, "1.0K"},
		{1500, "1.5K"},
		{1024 * 1024, "1.0M"},
		{1024 * 1024 * 1024, "1.0G"},
	}
	for _, tc := range cases {
		if got := humanBytes(tc.in); got != tc.want {
			t.Errorf("humanBytes(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
