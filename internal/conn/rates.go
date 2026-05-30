package conn

import "time"

// rateAlpha is the EMA smoothing factor. Higher = more responsive to bursts,
// lower = smoother long-term trend. 0.5 gives a reasonable middle ground.
const rateAlpha = 0.5

// RefreshRates samples byte counters across the table, computes a per-second
// delta since the previous sample, and folds it into a smoothed RateSent /
// RateRecv
func (t *Table) RefreshRates(interval time.Duration) {
	dt := interval.Seconds()
	if dt <= 0 {
		return
	}
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.Lock()
		for _, c := range s.items {
			dSent := float64(c.BytesSent-c.lastSampledSent) / dt
			dRecv := float64(c.BytesRecv-c.lastSampledRecv) / dt
			c.RateSent = c.RateSent*(1-rateAlpha) + dSent*rateAlpha
			c.RateRecv = c.RateRecv*(1-rateAlpha) + dRecv*rateAlpha
			c.lastSampledSent = c.BytesSent
			c.lastSampledRecv = c.BytesRecv
		}
		s.mu.Unlock()
	}
}
