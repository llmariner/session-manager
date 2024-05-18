package proxy

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const testProto = "my-custom-protocol"

func TestUpgradeProxy_AddRemove(t *testing.T) {
	id := "foo"
	conn := &net.TCPConn{}

	p := NewUpgradeProxy()

	// Add a single connection to the pool.
	err := p.Add(id, conn)
	assert.NoError(t, err)

	// A single connection for the map key.
	trs, ok := p.transports[id]
	assert.True(t, ok)
	assert.Len(t, trs, 1)

	// Add a second connection to the map key.
	err = p.Add(id, conn)
	assert.NoError(t, err)

	// The map key now has two transports.
	trs, ok = p.transports[id]
	assert.True(t, ok)
	assert.Len(t, trs, 2)

	// Remove both connections.
	size := len(trs)
	for i := 0; i < size; i++ {
		tr := p.takeTransport(id)
		assert.NotNil(t, tr)
	}

	// The map of transports is now empty.
	assert.Empty(t, p.transports)
}

func TestUpgradeProxy_Proxy(t *testing.T) {
	// NOTE: This test nuanced and warrants some explanation.
	//
	// To test the proxying functionality of the UpgradeProxy, we run a
	// "greeter" that acts like an agent. The greeter listens on a domain
	// socket and acts as an HTTP server. This HTTP server has an endpoint that
	// simulates an HTTP CONNECT-like upgrade similar to what we expect with
	// "kubectl exec". The protocol after the upgrade is a simple text-based
	// protocol that receives a greeting from a client and responds with its
	// own.
	//
	// We add instantiate a connection to the greeter by dialing the domain
	// socket on which it is listening, and add this connection to the proxy.
	//
	// To simulate a client that issues upgrade requests that need to be
	// proxied, we establish two connections to a domain socket. One connection
	// can be used as a test client, and the second is passed to the proxy to
	// use when bridging the connection to the agent.
	//
	// The test checks that the HTTP upgrade succeeds, and that the
	// greeter receives the client's message and that the client receives the
	// greeting back.

	// Create a test greeter that listens on a socket.
	g := newTestGreeter(
		t.TempDir()+"/greeter.sock",
		"Hello, world!",
	)
	go func() { _ = g.run() }()

	// Wait for the greeter to become ready.
	errC := make(chan error)
	go func() {
		c := http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return net.Dial("unix", g.socketPath)
				},
			},
		}
		attempts := 0
		for {
			resp, err := c.Get("http://_/ready")
			if resp != nil && resp.StatusCode == http.StatusOK {
				break
			}
			attempts++
			if attempts == 5 {
				errC <- fmt.Errorf("timed out: %s", err)
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		close(errC)
	}()
	assert.NoError(t, <-errC)

	// Establish a net.Conn to the greeter that we add to the proxy.
	conn, err := net.Dial("unix", g.socketPath)
	assert.NoError(t, err)

	id := "test:80"
	p := NewUpgradeProxy()
	err = p.Add(id, conn)
	assert.NoError(t, err)

	// Create a fake connection that we can use as a "client" to send and
	// receive bytes. We use a domain socket with two net.Conns connected to it:
	// - connL: test client <-> socket
	// - connR: socket <-> proxy
	socketPath := t.TempDir() + "/client.sock"
	l, err := net.Listen("unix", socketPath)
	assert.NoError(t, err)

	connC := make(chan net.Conn)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			panic(err)
		}
		connC <- conn
	}()

	// Create the socket <-> proxy connection.
	connR, err := net.Dial("unix", socketPath)
	assert.NoError(t, err)
	w := &testRecorder{
		ResponseRecorder: *httptest.NewRecorder(),
		conn:             connR,
	}

	// Fetch the test client <-> socket connection.
	connL := <-connC

	// Construct a request and proxy it.
	url := fmt.Sprintf("http://%s/connect", id)
	req, err := http.NewRequest(http.MethodConnect, url, nil)
	assert.NoError(t, err)

	// NOTE: add upgrade headers per RFC 7320, section 6.7.
	req.Header.Add("Connection", "upgrade")
	req.Header.Add("Upgrade", testProto)

	// Proxy the request. This is blocking, so run it in a separate thread.
	doneC := make(chan struct{})
	go func() {
		p.Proxy(w, req)
		close(doneC)
	}()

	// Write a message to the greeter.
	greeting := "Hello from client."
	_, err = connL.Write([]byte(greeting))
	assert.NoError(t, err)

	// Read the response from the greeter.
	var b [100]byte
	n, err := connL.Read(b[:])
	assert.NoError(t, err)

	// Assert that we got the expected message from the greeter.
	assert.Equal(t, g.greeting, string(b[:n]))

	// Assert that the greeter got our message.
	assert.Equal(t, greeting, g.captured)

	// Close the connection to the proxy.
	_ = connR.Close()
	<-doneC

	// Afterwards, make sure that the response header has the access-control-allow-origin header.
	assert.Equal(t, "*", w.Result().Header.Get(allowOriginHeaderName))
}

// testRecorder is an http.ResponseWriter backed by a httptest.ResponseRecorder
// that also implements http.Hijacker, allowing a net.Conn to be fetched and
// used to transfer bytes as if the request was a HTTP upgrade tunnel.
type testRecorder struct {
	httptest.ResponseRecorder
	conn net.Conn
}

// Hijack implements http.Hijacker by returning the stored net.Conn.
func (r *testRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return r.conn, nil, nil
}

// testGreeter is an HTTP server that exposes two endpoints:
//   - /ready: a readiness endpoint
//   - /connect: responds to a HTTP CONNECT-style upgrade, after which point the
//     underlying connection can be used for a simple plaintext protocol.
type testGreeter struct {
	socketPath string
	greeting   string

	srv      *http.Server
	m        sync.Mutex
	captured string
}

// newTestGreeter returns a new *testGreeter.
func newTestGreeter(socketPath, greeting string) *testGreeter {
	s := &testGreeter{
		socketPath: socketPath,
		greeting:   greeting,
		srv:        &http.Server{},
	}

	m := http.NewServeMux()
	m.HandleFunc("/ready", s.handleReady)
	m.HandleFunc("/connect", s.handleUpgrade)
	s.srv = &http.Server{Handler: m}

	return s
}

// run starts the testGreeter. This is a blocking function.
func (g *testGreeter) run() error {
	l, err := net.Listen("unix", g.socketPath)
	if err != nil {
		return err
	}
	return g.srv.Serve(l)
}

// handleReady responds with a "ready" string.
func (g *testGreeter) handleReady(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte("ready"))
}

// handleUpgrade responds to an HTTP CONNECT-style request before dropping down
// to a plaintext protocol.
func (g *testGreeter) handleUpgrade(w http.ResponseWriter, _ *http.Request) {
	g.m.Lock()
	defer g.m.Unlock()

	// Respond with the expected upgrade headers (see RFC 7320, section 6.7).
	w.Header().Add("connection", "upgrade")
	w.Header().Add("upgrade", testProto)
	w.WriteHeader(http.StatusSwitchingProtocols)

	// Hijack the connection and drop down to a simple plaintext protocol.
	hijacker := w.(http.Hijacker)
	conn, _, err := hijacker.Hijack()
	if err != nil {
		panic(fmt.Errorf("hijack: %s", err))
	}

	// Read from the connection and store.
	var b [100]byte
	n, err := conn.Read(b[:])
	if err != nil {
		panic(fmt.Errorf("read: %s", err))
	}
	g.captured = string(b[:n])

	// Respond with the greeting.
	_, err = conn.Write([]byte(g.greeting))
	if err != nil {
		panic(fmt.Errorf("write: %s", err))
	}
}
