// Package events is a tiny in-process pub/sub for live UI updates.
package events

import (
	"encoding/json"
	"sync"
)

// Event is the wire shape sent to websocket subscribers.
type Event struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data,omitempty"`
}

// Broker delivers events to all active subscribers. Slow subscribers drop
// messages — this is a UI feed, not a queue.
type Broker struct {
	mu   sync.RWMutex
	subs map[chan Event]struct{}
}

// New returns an empty broker ready to accept subscribers.
func New() *Broker { return &Broker{subs: make(map[chan Event]struct{})} }

// Subscribe returns a receive-only channel and a cancel func that
// unsubscribes and closes the channel.
func (b *Broker) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 64)
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	b.mu.Unlock()
	cancel := func() {
		b.mu.Lock()
		if _, ok := b.subs[ch]; ok {
			delete(b.subs, ch)
			close(ch)
		}
		b.mu.Unlock()
	}
	return ch, cancel
}

// Publish marshals data to JSON once and fans out to every subscriber.
// If a subscriber's buffer is full the event is dropped for that sub.
func (b *Broker) Publish(typ string, data any) {
	raw, err := json.Marshal(data)
	if err != nil {
		return
	}
	e := Event{Type: typ, Data: raw}
	b.mu.RLock()
	for ch := range b.subs {
		select {
		case ch <- e:
		default:
		}
	}
	b.mu.RUnlock()
}
