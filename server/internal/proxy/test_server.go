package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// testSeverOpts are options for a test server.
type testServerOpts struct {
	hostname   string
	socketPath string
	greeting   string
	// returnPath is true if the server should return the request path in the response.
	returnPath bool
}

// testServer is a plaintext HTTP/2 server that returns a greeting.
type testServer struct {
	socketPath string
	greeting   string
	returnPath bool

	srv *http.Server
}

// newTestServer returns a new testServer that will listen on the given socket
// path and return the given greeting.
func newTestServer(socketPath, greeting string, returnPath bool) *testServer {
	s := &testServer{
		socketPath: socketPath,
		greeting:   greeting,
		returnPath: returnPath,
	}
	s.srv = &http.Server{
		// Explicitly enable H2C support on the server. Without this, the server
		// will reject inbound cleartext requests and close the connection.
		Handler: h2c.NewHandler(http.HandlerFunc(s.handle), &http2.Server{}),
	}
	return s
}

// run is starts the server. This is a blocking function.
func (s *testServer) run() error {
	l, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return err
	}
	return s.srv.Serve(l)
}

// handle is the HTTP handler that returns the greeting.
func (s *testServer) handle(w http.ResponseWriter, r *http.Request) {
	if s.returnPath {
		_, _ = w.Write([]byte(r.URL.Path))
		return
	}

	_, _ = w.Write([]byte(s.greeting))
}

// setupServers starts the testServers with the given testServerOpts.
func setupServers(opts []testServerOpts) {
	var wg sync.WaitGroup
	for _, o := range opts {
		s1 := newTestServer(o.socketPath, o.greeting, o.returnPath)

		// Start the server.
		wg.Add(1)
		go func() {
			if err := s1.run(); err != nil && err != http.ErrServerClosed {
				panic(fmt.Errorf("server: run: %s", err))
			}
		}()

		// Wait for the server to start responding.
		go func(socketPath string) {
			attempts := 0
			c := &http.Client{Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return net.Dial("unix", socketPath)
				},
			}}
			for {
				resp, err := c.Get("http://_")
				if resp != nil && resp.StatusCode == 200 {
					break
				}
				attempts++
				if attempts == 5 {
					panic(fmt.Errorf("timed out waiting for server: %s", err))
				}
				time.Sleep(time.Second)
			}
			wg.Done()
		}(o.socketPath)
	}

	// Wait for all servers to start.
	wg.Wait()
}
