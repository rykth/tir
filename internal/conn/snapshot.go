package conn

import (
	"sync/atomic"
	"time"
)

// Snapshot is a point-in-time, immutable view of the connection table
type Snapshot struct {
	GeneratedAt time.Time
	Rows        []ConnView
}

// ConnView is an immutable copy of a Connection
type ConnView struct {
	Key         ConnKey
	State       State
	FirstSeen   time.Time
	LastSeen    time.Time
	BytesSent   uint64
	BytesRecv   uint64
	PktsSent    uint64
	PktsRecv    uint64
	RateSent    float64
	RateRecv    float64
	PID         int32
	ProcessName string
	DPI         DPIInfo
}

// Snapshot returns the current Table contents as a Snapshot
func (t *Table) Snapshot(now time.Time) *Snapshot {
	rows := make([]ConnView, 0, t.Len())
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.RLock()
		for _, c := range s.items {
			rows = append(rows, connToView(c))
		}
		s.mu.RUnlock()
	}
	return &Snapshot{GeneratedAt: now, Rows: rows}
}

func connToView(c *Connection) ConnView {
	return ConnView{
		Key:         c.Key,
		State:       c.State,
		FirstSeen:   c.FirstSeen,
		LastSeen:    c.LastSeen,
		BytesSent:   c.BytesSent,
		BytesRecv:   c.BytesRecv,
		PktsSent:    c.PktsSent,
		PktsRecv:    c.PktsRecv,
		RateSent:    c.RateSent,
		RateRecv:    c.RateRecv,
		PID:         c.PID,
		ProcessName: c.ProcessName,
		DPI:         c.DPI,
	}
}

// Publisher is a single-slot atomic holder for the latest Snapshot
type Publisher struct {
	cur atomic.Pointer[Snapshot]
}

// Publish atomically stores s as the most recent snapshot
func (p *Publisher) Publish(s *Snapshot) {
	p.cur.Store(s)
}

// Latest returns the most recently published snapshot (or nil)
func (p *Publisher) Latest() *Snapshot {
	return p.cur.Load()
}
