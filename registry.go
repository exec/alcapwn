package main

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"alcapwn/proto"
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
	// Agent session fields — populated only when IsAgent is true.
	// For PTY sessions these are always nil/false.
	IsAgent     bool
	AgentMeta   *proto.Hello      // set after agent handshake; guarded by mu
	agentTaskCh chan agentTaskReq  // operator → handleAgentSession task channel
	// HTTP beacon fields — set only for HTTP transport agents (HTTPToken != "").
	// TCP agents leave these nil/empty.
	HTTPToken     string               // URL token for /beacon/{token}; also key in registry.httpTokens
	httpCS        *proto.CryptoSession // per-session AES-256-GCM state for HTTP transport
	httpInFlight   map[string]*agentTaskReq // in-flight tasks keyed by task ID
	httpInflightMu sync.Mutex              // guards httpInFlight
	// drain goroutine control — guarded by mu.
	// Non-nil only while a drain goroutine is running (session backgrounded).
	drainStop chan struct{} // close to stop the drain goroutine
	drainDone chan struct{} // closed when drain goroutine exits
	drainConn net.Conn    // connection the drain goroutine is reading from
	// Pivot state — SOCKS5 proxies and TCP forwards active on this session.
	pivotState *pivotState
}

// Registry is a thread-safe store of active sessions, numbered 1–1024.
type Registry struct {
	mu         sync.Mutex
	sessions   map[int]*Session
	httpTokens sync.Map // token string → *Session (for HTTP beacon lookup)
	nextID   int
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{
		sessions: make(map[int]*Session),
		nextID:   1,
	}
}

// nextIDLocked finds the next available session ID (1–1024).
// Caller must hold r.mu. Returns 0 if no slot is free.
func (r *Registry) nextIDLocked() int {
	// Fast path: try nextID first.
	if r.nextID <= 1024 {
		if _, taken := r.sessions[r.nextID]; !taken {
			id := r.nextID
			r.nextID++
			return id
		}
	}
	// Slow path: scan from 1 for the first free slot.
	for i := 1; i <= 1024; i++ {
		if _, taken := r.sessions[i]; !taken {
			return i
		}
	}
	return 0
}

// Allocate assigns the next available ID (1–1024) and registers a new Session.
// Returns nil if the session limit is reached.
func (r *Registry) Allocate(conn net.Conn, useTLS bool) *Session {
	r.mu.Lock()
	defer r.mu.Unlock()

	id := r.nextIDLocked()
	if id == 0 {
		fmt.Println("[!] Session limit reached (1024)")
		return nil
	}

	sess := &Session{
		ID:           id,
		Conn:         conn,
		RemoteAddr:   conn.RemoteAddr().String(),
		StartTime:    time.Now(),
		State:        SessionStateActive,
		TLS:          useTLS,
		httpInFlight: make(map[string]*agentTaskReq),
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
// For HTTP sessions it also deletes the token from httpTokens.
func (r *Registry) Remove(id int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if sess, ok := r.sessions[id]; ok {
		sess.mu.Lock()
		sess.State = SessionStateTerminated
		tok := sess.HTTPToken
		sess.mu.Unlock()
		if tok != "" {
			r.httpTokens.Delete(tok)
		}
		delete(r.sessions, id)
		// Allow the freed ID to be reused by the fast path.
		if id < r.nextID {
			r.nextID = id
		}
	}
}

// AllocateHTTP creates an HTTP-transport agent session with the given beacon
// token.  remoteAddr is the agent's IP:port string from the HTTP request.
// Returns nil if the session limit (1024) is reached.
func (r *Registry) AllocateHTTP(token, remoteAddr string) *Session {
	r.mu.Lock()
	defer r.mu.Unlock()

	id := r.nextIDLocked()
	if id == 0 {
		fmt.Println("[!] Session limit reached (1024)")
		return nil
	}

	sess := &Session{
		ID:           id,
		HTTPToken:    token,
		RemoteAddr:   remoteAddr,
		StartTime:    time.Now(),
		State:        SessionStateActive,
		httpInFlight: make(map[string]*agentTaskReq),
	}
	r.sessions[id] = sess
	r.httpTokens.Store(token, sess)
	return sess
}

// LookupHTTPToken returns the session associated with an HTTP beacon token,
// or nil if no such session exists.
func (r *Registry) LookupHTTPToken(token string) *Session {
	if v, ok := r.httpTokens.Load(token); ok {
		return v.(*Session)
	}
	return nil
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

// remoteHost returns the host part of the session's remote address.
// Works for both TCP sessions (Conn.RemoteAddr) and HTTP sessions (RemoteAddr string).
func (s *Session) remoteHost() string {
	if s.Conn != nil {
		return hostFromAddr(s.Conn.RemoteAddr())
	}
	host, _, _ := net.SplitHostPort(s.RemoteAddr)
	if host == "" {
		return s.RemoteAddr
	}
	return host
}

// Count returns the number of registered sessions.
func (r *Registry) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sessions)
}
