package api

import "sync"

const (
	// healthWindow is how many recent delivery outcomes are kept per key.
	healthWindow = 50
	// healthMinSample is how many outcomes are needed before a key can be judged.
	healthMinSample = 20
)

// health tracks, per key, how many of its recent sends were to dead tokens. A server that
// mostly sends to tokens Apple has already retired is guessing at them, and every such
// request counts against the relay's standing with APNs.
type health struct {
	mu   sync.Mutex
	keys map[int64]*outcomes
}

type outcomes struct {
	dead [healthWindow]bool
	n    int
	next int
}

func newHealth() *health { return &health{keys: make(map[int64]*outcomes)} }

// record adds one outcome and reports whether the key has now earned a revocation.
func (h *health) record(keyID int64, dead bool) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	o := h.keys[keyID]
	if o == nil {
		o = &outcomes{}
		h.keys[keyID] = o
	}
	o.dead[o.next] = dead
	o.next = (o.next + 1) % healthWindow
	if o.n < healthWindow {
		o.n++
	}
	if o.n < healthMinSample {
		return false
	}
	count := 0
	for i := 0; i < o.n; i++ {
		if o.dead[i] {
			count++
		}
	}
	return count*2 > o.n
}

func (h *health) forget(keyID int64) {
	h.mu.Lock()
	delete(h.keys, keyID)
	h.mu.Unlock()
}
