package main

import "alcapwn/proto"

// Transport abstracts the C2 communication channel between the agent and server.
// Two implementations exist: TCPTransport (persistent encrypted TCP) and
// HTTPTransport (HTTP beacon polling).
//
// Usage per reconnect cycle:
//
//	t := buildTransport(ivSec, jitPct)
//	if err := t.Connect(hello); err != nil { ... }
//	for { task, _ := t.PollTask(); t.SendResult(executeTask(*task)) }
//	t.Close()
type Transport interface {
	// Connect establishes the session: dials the server, performs the X25519
	// handshake, sends Hello, and receives Welcome.  Must be called once before
	// PollTask or SendResult.
	Connect(hello proto.Hello) error

	// PollTask blocks until the next Task is available and returns it.
	// For TCP this reads from the persistent connection, handling Pings
	// internally.  For HTTP this repeatedly GETs /beacon/{token}, sleeping
	// interval±jitter between 204 No Content responses.
	PollTask() (*proto.Task, error)

	// SendResult delivers the completed result for the most recently polled
	// task back to the server.
	SendResult(result proto.Result) error

	// Close terminates the transport and releases any resources.
	// Safe to call more than once.
	Close()
}
