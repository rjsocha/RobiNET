package wrak

import (
	"sync"
	"time"
)

// NonceStore remembers which nonces have been spent, so a captured request
// cannot be replayed inside the time window.
type NonceStore interface {
	// Use records a nonce and reports whether it was fresh.
	Use(identity, nonce string, ttl time.Duration) bool
}

// MemoryNonces keeps nonces in memory for as long as the window lasts. Losing
// them on restart is acceptable: a replay would still have to land inside the
// window, and the window is shorter than a restart is interesting.
type MemoryNonces struct {
	mu    sync.Mutex
	seen  map[string]time.Time
	swept time.Time
}

// NewMemoryNonces returns an empty store.
func NewMemoryNonces() *MemoryNonces {
	return &MemoryNonces{seen: map[string]time.Time{}}
}

func (m *MemoryNonces) Use(identity, nonce string, ttl time.Duration) bool {
	key := identity + "\x00" + nonce
	now := time.Now()

	m.mu.Lock()
	defer m.mu.Unlock()

	if now.Sub(m.swept) > ttl {
		for k, expiry := range m.seen {
			if now.After(expiry) {
				delete(m.seen, k)
			}
		}
		m.swept = now
	}

	if expiry, used := m.seen[key]; used && now.Before(expiry) {
		return false
	}

	m.seen[key] = now.Add(ttl)
	return true
}
