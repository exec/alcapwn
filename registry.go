package main

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// SessionState represents the lifecycle state of a session.
type SessionState int

const (
	SessionStateActive      SessionState = iota // backgrounded, ready for 'use'
	SessionStateInteractive                     // currently attached to operator
	SessionStateTerminated                      // connection closed / killed
)

// Session represents a single connected reverse shell.
type Session struct {
	ID           int
	Conn         net.Conn     // original plain connection
	ActiveConn   net.Conn     // may be TLS-upgraded; set after PTY upgrade
	Upgrader     *PTYUpgrader // set after PTY upgrade completes
	RemoteAddr   string
	ListenerAddr string // address of the listener this session came through
	Label        string // optional human-readable name set with 'rename'
	Findings        *Findings
	Matches         []MatchResult
	HarvestedCreds  *string // set by 'creds' command; shown in 'info'
	IsRoot          bool    // current privilege state — updated live, distinct from Findings.UID snapshot
	RootLevel       string  // "uid", "euid", or "both"; empty when not root
	StartTime       time.Time
	State        SessionState
	TLS          bool
	mu           sync.Mutex
	// drain goroutine control — guarded by mu.
	// Non-nil only while a drain goroutine is running (session backgrounded).
	drainStop chan struct{} // close to stop the drain goroutine
	drainDone chan struct{} // closed when drain goroutine exits
	drainConn net.Conn    // connection the drain goroutine is reading from
}

// Registry is a thread-safe store of active sessions, numbered 1–1024.
type Registry struct {
	mu       sync.Mutex
	sessions map[int]*Session
	nextID   int
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{
		sessions: make(map[int]*Session),
		nextID:   1,
	}
}

// Allocate assigns the next available ID (1–1024) and registers a new Session.
// Returns nil if the session limit is reached.
func (r *Registry) Allocate(conn net.Conn, useTLS bool) *Session {
	r.mu.Lock()
	defer r.mu.Unlock()

	id := 0
	// Fast path: try nextID first.
	if r.nextID <= 1024 {
		if _, taken := r.sessions[r.nextID]; !taken {
			id = r.nextID
			r.nextID++
		}
	}
	// Slow path: scan from 1 for the first free slot.
	if id == 0 {
		for i := 1; i <= 1024; i++ {
			if _, taken := r.sessions[i]; !taken {
				id = i
				break
			}
		}
	}
	if id == 0 {
		fmt.Println("[!] Session limit reached (1024)")
		return nil
	}

	sess := &Session{
		ID:         id,
		Conn:       conn,
		RemoteAddr: conn.RemoteAddr().String(),
		StartTime:  time.Now(),
		State:      SessionStateActive,
		TLS:        useTLS,
	}
	r.sessions[id] = sess
	return sess
}

// Get returns a session by ID, or nil if not found.
func (r *Registry) Get(id int) *Session {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sessions[id]
}

// Remove marks a session terminated and removes it from the registry.
func (r *Registry) Remove(id int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if sess, ok := r.sessions[id]; ok {
		sess.mu.Lock()
		sess.State = SessionStateTerminated
		sess.mu.Unlock()
		delete(r.sessions, id)
	}
}

// All returns all sessions sorted ascending by ID.
func (r *Registry) All() []*Session {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([]*Session, 0, len(r.sessions))
	for _, s := range r.sessions {
		result = append(result, s)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].ID < result[j].ID
	})
	return result
}

// Count returns the number of registered sessions.
func (r *Registry) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sessions)
}
