package harness

import (
	"encoding/json"
	"sort"
	"sync"

	"github.com/gvinsot/SwiftProof/app/internal/model"
)

// memoryCache is an in-memory ExecutionCache for tests. It stores deep copies,
// so a test can only change an entry through its helpers. Feature tests use it
// to reach the "replayed base, then live re-run" branches before the real
// store exists: run the baseline live (twice, or once and then promote), and
// the next eligible run is a replay.
type memoryCache struct {
	mu        sync.Mutex
	entries   map[string]CacheEntry
	gets      int
	puts      int
	deletes   int
	putErr    error // when set, every Put fails with it
	deleteErr error // when set, every Delete fails with it
	stats     model.ExecutionCache
}

func newMemoryCache() *memoryCache { return &memoryCache{entries: map[string]CacheEntry{}} }

// useMemoryCache installs a new memory cache on h, as Options.Cache would.
func useMemoryCache(h *Harness) *memoryCache {
	m := newMemoryCache()
	h.exec.cache = m
	return m
}

func copyEntry(e CacheEntry) CacheEntry {
	e.Preimage = append(json.RawMessage(nil), e.Preimage...)
	e.Payload = append([]byte(nil), e.Payload...)
	return e
}

func (m *memoryCache) Get(key string) (CacheEntry, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gets++
	e, ok := m.entries[key]
	if !ok {
		return CacheEntry{}, false
	}
	return copyEntry(e), true
}

func (m *memoryCache) Put(e CacheEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.puts++
	if m.putErr != nil {
		return m.putErr
	}
	m.entries[e.Key] = copyEntry(e)
	return nil
}

func (m *memoryCache) Delete(key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deletes++
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.entries, key)
	return nil
}

func (m *memoryCache) Stats() model.ExecutionCache {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stats
}

// entry returns a copy of the stored entry for key.
func (m *memoryCache) entry(key string) (CacheEntry, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[key]
	return copyEntry(e), ok
}

// keys lists the stored keys in order.
func (m *memoryCache) keys() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	keys := make([]string, 0, len(m.entries))
	for k := range m.entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// seed stores e as is (a pre-existing entry, possibly tampered).
func (m *memoryCache) seed(e CacheEntry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[e.Key] = copyEntry(e)
}

// promote sets LiveRuns on every stored entry, so an entry recorded by one live
// run becomes servable (liveRuns >= 2) without a second run.
func (m *memoryCache) promote(liveRuns int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, e := range m.entries {
		e.LiveRuns = liveRuns
		m.entries[k] = e
	}
}

// update applies fn to the stored entry for key.
func (m *memoryCache) update(key string, fn func(*CacheEntry)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.entries[key]; ok {
		fn(&e)
		m.entries[key] = e
	}
}
