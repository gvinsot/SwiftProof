// Package events pushes live analysis updates to the browsers of one user.
//
// A dashboard must show a new report as soon as a push has been analyzed,
// without polling every repository. Subscribers are per user, so an event can
// never reach an account that does not own the repository.
package events

import (
	"encoding/json"
	"sync"
)

// bufferSize keeps a slow browser from blocking a worker; when it overflows,
// the event is dropped and the UI recovers on its next refresh.
const bufferSize = 32

// Broker fans events out to the open streams of each user.
type Broker struct {
	mu   sync.Mutex
	subs map[string]map[chan []byte]struct{}
}

// New creates an empty broker.
func New() *Broker { return &Broker{subs: map[string]map[chan []byte]struct{}{}} }

// Subscribe opens a stream for a user and returns it with its cancel function.
func (b *Broker) Subscribe(userKey string) (<-chan []byte, func()) {
	ch := make(chan []byte, bufferSize)
	b.mu.Lock()
	if b.subs[userKey] == nil {
		b.subs[userKey] = map[chan []byte]struct{}{}
	}
	b.subs[userKey][ch] = struct{}{}
	b.mu.Unlock()
	return ch, func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if set, ok := b.subs[userKey]; ok {
			if _, open := set[ch]; open {
				delete(set, ch)
				close(ch)
			}
			if len(set) == 0 {
				delete(b.subs, userKey)
			}
		}
	}
}

// Publish delivers an event to every stream of one user. It never blocks.
func (b *Broker) Publish(userKey string, payload any) {
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs[userKey] {
		select {
		case ch <- data:
		default:
		}
	}
}

// Subscribers reports how many streams are open, for the health endpoint.
func (b *Broker) Subscribers() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for _, set := range b.subs {
		n += len(set)
	}
	return n
}
