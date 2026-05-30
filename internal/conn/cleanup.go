package conn

import "time"

// Cleanup evicts connections whose LastSeen exceeds their protocol-aware
// timeout(Returns the number of connections removed. If OnClosed is set, it is
// invoked once per evicted connection after the shard lock is released)
func (t *Table) Cleanup(now time.Time) int {
	var closed []ConnView
	var removed int
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.Lock()
		for k, c := range s.items {
			if now.Sub(c.LastSeen) > timeoutFor(c) {
				if t.OnClosed != nil {
					closed = append(closed, connToView(c))
				}
				delete(s.items, k)
				removed++
			}
		}
		s.mu.Unlock()
	}
	if t.OnClosed != nil {
		for _, v := range closed {
			t.OnClosed(v)
		}
	}
	return removed
}
