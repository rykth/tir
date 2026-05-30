package conn

import (
	"encoding/binary"
	"hash/maphash"
	"sync"
	"time"
)

// numShards is the number of parallel shards in the connection table
const numShards = 16

// Table is a sharded, concurrent connection table
type Table struct {
	// each shard has its own RWMutex - updates only contend with other updates
	// that hash to the same shard, and snapshots can read shards in parallel
	shards [numShards]shard
	seed   maphash.Seed

	OnNew    func(ConnView)
	OnClosed func(ConnView)
}

type shard struct {
	mu    sync.RWMutex
	items map[ConnKey]*Connection
}

// NewTable returns an empty Table
func NewTable() *Table {
	t := &Table{seed: maphash.MakeSeed()}
	for i := range t.shards {
		t.shards[i].items = make(map[ConnKey]*Connection)
	}
	return t
}

// Len returns the total number of tracked connections
func (t *Table) Len() int {
	var n int
	for i := range t.shards {
		t.shards[i].mu.RLock()
		n += len(t.shards[i].items)
		t.shards[i].mu.RUnlock()
	}
	return n
}

// Apply upserts the connection identified by key and runs fn against it under
// the shard's write lock
func (t *Table) Apply(key ConnKey, now time.Time, fn func(*Connection)) {
	s := &t.shards[t.shardIdx(key)]
	s.mu.Lock()

	c, ok := s.items[key]
	var isNew bool
	if !ok {
		c = &Connection{Key: key, FirstSeen: now}
		s.items[key] = c
		isNew = true
	}
	c.LastSeen = now
	fn(c) // do the mutation

	var view ConnView
	if isNew && t.OnNew != nil {
		view = connToView(c)
	}
	s.mu.Unlock()

	if isNew && t.OnNew != nil {
		t.OnNew(view)
	}
}

// Update runs fn against an existing connection
func (t *Table) Update(key ConnKey, fn func(*Connection)) bool {
	s := &t.shards[t.shardIdx(key)]
	s.mu.Lock()
	defer s.mu.Unlock()

	c, ok := s.items[key]
	if !ok {
		return false
	}
	fn(c)
	return true
}

func (t *Table) shardIdx(key ConnKey) uint64 {
	// Fixed-size stack buffer: Proto(1) + LocalAddr(16) + LocalPort(2) +
	// RemoteAddr(16) + RemotePort(2) = 37 bytes. As16 normalizes v4 and v6
	// addresses to a 16-byte representation.
	var buf [37]byte
	buf[0] = byte(key.Proto)
	la := key.LocalAddr.As16()
	copy(buf[1:17], la[:])
	binary.BigEndian.PutUint16(buf[17:19], key.LocalPort)
	ra := key.RemoteAddr.As16()
	copy(buf[19:35], ra[:])
	binary.BigEndian.PutUint16(buf[35:37], key.RemotePort)
	return maphash.Bytes(t.seed, buf[:]) % numShards
}
