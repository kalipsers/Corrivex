// Package hub tracks the set of agents that currently have a live WebSocket
// connection to the server. It is consulted when the dashboard creates a new
// task so we can push it to the host immediately instead of waiting for the
// next poll.
package hub

import (
	"sync"
)

// Conn is a live agent connection. The writer goroutine reads from Send; every
// caller that wants to push a message to the agent sends to Send (non-blocking
// on a full buffer — slow agents just miss the message, and we close them).
type Conn struct {
	Hostname string
	Send     chan []byte
	// Close is invoked when the hub evicts this connection (new session for
	// same hostname, explicit unregister, etc.). Implementations close the
	// underlying WebSocket inside Close.
	Close func()
}

// Hub maps hostname → current connection.
type Hub struct {
	mu    sync.RWMutex
	conns map[string]*Conn
}

func New() *Hub { return &Hub{conns: make(map[string]*Conn)} }

// Register swaps in a new connection for hostname. Any pre-existing session is
// closed so only one agent-per-hostname is routed to at a time.
func (h *Hub) Register(c *Conn) {
	h.mu.Lock()
	old := h.conns[c.Hostname]
	h.conns[c.Hostname] = c
	h.mu.Unlock()
	if old != nil && old.Close != nil {
		old.Close()
	}
}

// Unregister removes the connection only if it is the one still in the map
// (avoids evicting a fresh session when the previous one finishes its teardown).
func (h *Hub) Unregister(c *Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if cur, ok := h.conns[c.Hostname]; ok && cur == c {
		delete(h.conns, c.Hostname)
	}
}

// IsOnline reports whether the named host has a live connection.
func (h *Hub) IsOnline(hostname string) bool {
	h.mu.RLock()
	_, ok := h.conns[hostname]
	h.mu.RUnlock()
	return ok
}

// Send delivers a raw JSON frame to the connected agent. Returns false if the
// host has no active connection or its send buffer is full.
func (h *Hub) Send(hostname string, frame []byte) bool {
	h.mu.RLock()
	c, ok := h.conns[hostname]
	h.mu.RUnlock()
	if !ok {
		return false
	}
	select {
	case c.Send <- frame:
		return true
	default:
		return false
	}
}

// OnlineHosts returns the set of hostnames currently connected.
func (h *Hub) OnlineHosts() map[string]bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make(map[string]bool, len(h.conns))
	for k := range h.conns {
		out[k] = true
	}
	return out
}
