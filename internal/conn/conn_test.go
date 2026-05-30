package conn

import (
	"net/netip"
	"sync"
	"testing"
	"time"
)

func mkKey(proto Proto, local string, lport uint16, remote string, rport uint16) ConnKey {
	return ConnKey{
		Proto:      proto,
		LocalAddr:  netip.MustParseAddr(local),
		LocalPort:  lport,
		RemoteAddr: netip.MustParseAddr(remote),
		RemotePort: rport,
	}
}

func TestTableUpdateNoGhostRows(t *testing.T) {
	tbl := NewTable()
	key := mkKey(ProtoTCP, "10.0.0.1", 1, "10.0.0.2", 2)

	called := false
	if got := tbl.Update(key, func(*Connection) { called = true }); got {
		t.Errorf("Update on missing key = true, want false")
	}
	if called {
		t.Errorf("fn ran for missing key")
	}
	if got := tbl.Len(); got != 0 {
		t.Errorf("Len after missing Update = %d, want 0", got)
	}

	tbl.Apply(key, time.Now(), func(*Connection) {})
	if got := tbl.Update(key, func(c *Connection) { c.PID = 1234; c.ProcessName = "curl" }); !got {
		t.Errorf("Update on existing key = false, want true")
	}
	r := tbl.Snapshot(time.Now()).Rows[0]
	if r.PID != 1234 || r.ProcessName != "curl" {
		t.Errorf("after Update = pid=%d name=%q, want pid=1234 name=\"curl\"", r.PID, r.ProcessName)
	}
}

func TestTableApplyCreatesAndUpdates(t *testing.T) {
	tbl := NewTable()
	key := mkKey(ProtoTCP, "10.0.0.1", 1234, "10.0.0.2", 5678)
	now := time.Now()

	tbl.Apply(key, now, func(c *Connection) { c.BytesSent = 100 })
	if got := tbl.Len(); got != 1 {
		t.Fatalf("Len after first Apply = %d, want 1", got)
	}

	tbl.Apply(key, now.Add(time.Second), func(c *Connection) { c.BytesSent += 50 })
	if got := tbl.Len(); got != 1 {
		t.Fatalf("Len after second Apply = %d, want 1", got)
	}

	snap := tbl.Snapshot(now.Add(2 * time.Second))
	if len(snap.Rows) != 1 {
		t.Fatalf("Rows = %d, want 1", len(snap.Rows))
	}
	if got := snap.Rows[0].BytesSent; got != 150 {
		t.Errorf("BytesSent = %d, want 150", got)
	}
}

func TestTableShardDistribution(t *testing.T) {
	tbl := NewTable()
	const n = 4096
	counts := make([]int, numShards)
	for i := range n {
		k := mkKey(ProtoTCP, "10.0.0.1", uint16(i%65535), "10.0.0.2", uint16((i*131)%65535))
		counts[tbl.shardIdx(k)]++
	}
	// every shard should get a non-trivial share and a perfectly uniform hash
	// would give n/numShards = 256; allow a wide margin
	min := n / numShards / 4
	for i, c := range counts {
		if c < min {
			t.Errorf("shard %d got %d keys, want >= %d", i, c, min)
		}
	}
}

func TestTableApplyConcurrent(t *testing.T) {
	tbl := NewTable()
	const goroutines = 8
	const perG = 1000
	var wg sync.WaitGroup
	wg.Add(goroutines)
	now := time.Now()
	for g := range goroutines {
		go func() {
			defer wg.Done()
			for i := range perG {
				k := mkKey(ProtoUDP, "10.0.0.1", uint16(g*1000+i), "10.0.0.2", 53)
				tbl.Apply(k, now, func(c *Connection) { c.PktsSent++ })
			}
		}()
	}
	wg.Wait()
	if got, want := tbl.Len(), goroutines*perG; got != want {
		t.Fatalf("Len = %d, want %d", got, want)
	}
}

func TestStateApplyTCPHandshake(t *testing.T) {
	s := StateUnknown
	s = s.ApplyTCP(TCPSyn, true) // outgoing SYN
	if s != StateSynSent {
		t.Fatalf("after SYN out: %s", s)
	}

	s = s.ApplyTCP(TCPSyn|TCPAck, false) // incoming SYN-ACK
	if s != StateEstablished {
		t.Fatalf("after SYN-ACK in: %s", s)
	}

	s = s.ApplyTCP(TCPFin, true) // outgoing FIN
	if s != StateFinWait1 {
		t.Fatalf("after FIN out: %s", s)
	}

	s = s.ApplyTCP(TCPFin|TCPAck, false) // incoming FIN-ACK
	if s != StateTimeWait {
		t.Fatalf("after FIN-ACK in: %s", s)
	}
}

func TestStateApplyTCPPassiveOpen(t *testing.T) {
	s := StateUnknown
	s = s.ApplyTCP(TCPSyn, false) // incoming SYN (we're the server)
	if s != StateSynRecv {
		t.Fatalf("after SYN in: %s", s)
	}

	s = s.ApplyTCP(TCPSyn|TCPAck, true) // outgoing SYN-ACK
	if s != StateSynRecv {
		t.Fatalf("after SYN-ACK out: %s (state should hold)", s)
	}

	s = s.ApplyTCP(TCPAck, false) // incoming ACK
	if s != StateEstablished {
		t.Fatalf("after ACK in: %s", s)
	}
}

func TestStateApplyTCPRST(t *testing.T) {
	for _, start := range []State{StateUnknown, StateEstablished, StateFinWait1} {
		got := start.ApplyTCP(TCPRst, true)
		if got != StateClosed {
			t.Errorf("RST from %s = %s, want CLOSED", start, got)
		}
	}
}

func TestCleanupEvictsStale(t *testing.T) {
	tbl := NewTable()
	key := mkKey(ProtoUDP, "10.0.0.1", 1, "10.0.0.2", 2)
	start := time.Now()
	tbl.Apply(key, start, func(*Connection) {})

	if got := tbl.Cleanup(start.Add(timeoutUDP / 2)); got != 0 {
		t.Errorf("evicted within timeout: %d", got)
	}
	if got := tbl.Cleanup(start.Add(timeoutUDP + time.Second)); got != 1 {
		t.Errorf("evicted past timeout: %d", got)
	}
	if got := tbl.Len(); got != 0 {
		t.Errorf("Len after cleanup = %d, want 0", got)
	}
}

func TestRefreshRatesSmoothing(t *testing.T) {
	tbl := NewTable()
	key := mkKey(ProtoTCP, "10.0.0.1", 1, "10.0.0.2", 2)
	now := time.Now()

	tbl.Apply(key, now, func(c *Connection) { c.BytesSent = 1000 })
	tbl.RefreshRates(time.Second)
	if got := tbl.Snapshot(now).Rows[0].RateSent; got <= 0 {
		t.Fatalf("RateSent after first refresh = %v, want > 0", got)
	}

	// no new bytes (second tick should drive the smoothed rate down)
	tbl.RefreshRates(time.Second)
	r2 := tbl.Snapshot(now).Rows[0].RateSent
	tbl.RefreshRates(time.Second)
	r3 := tbl.Snapshot(now).Rows[0].RateSent
	if !(r3 < r2) {
		t.Errorf("rate did not decay: r2=%v r3=%v", r2, r3)
	}
}

func TestPublisherAtomic(t *testing.T) {
	var p Publisher
	if got := p.Latest(); got != nil {
		t.Errorf("Latest before Publish = %v, want nil", got)
	}

	s1 := &Snapshot{GeneratedAt: time.Now()}
	p.Publish(s1)
	if got := p.Latest(); got != s1 {
		t.Errorf("Latest = %p, want %p", got, s1)
	}

	s2 := &Snapshot{GeneratedAt: time.Now()}
	p.Publish(s2)
	if got := p.Latest(); got != s2 {
		t.Errorf("Latest after re-publish = %p, want %p", got, s2)
	}
}

func TestTimeoutForTCPStates(t *testing.T) {
	cases := []struct {
		state State
		want  time.Duration
	}{
		{StateEstablished, timeoutTCPEstablished},
		{StateTimeWait, timeoutTCPTimeWait},
		{StateClosed, timeoutTCPClosed},
		{StateSynSent, timeoutTCPHalfOpen},
	}
	for _, tc := range cases {
		c := &Connection{Key: ConnKey{Proto: ProtoTCP}, State: tc.state}
		if got := timeoutFor(c); got != tc.want {
			t.Errorf("timeoutFor(%s) = %s, want %s", tc.state, got, tc.want)
		}
	}
}
