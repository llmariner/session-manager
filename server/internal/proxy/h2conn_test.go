package proxy

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/net/http2"
)

func TestH2ConnPool(t *testing.T) {
	// Start two backend servers.
	s1Opts := testServerOpts{
		hostname:   "server1",
		socketPath: fmt.Sprintf("%s/server1.sock", t.TempDir()),
		greeting:   "Hello from Server 1.",
	}
	s2Opts := testServerOpts{
		hostname:   "server2",
		socketPath: fmt.Sprintf("%s/server2.sock", t.TempDir()),
		greeting:   "Hello from Server 2.",
	}
	opts := []testServerOpts{s1Opts, s2Opts}
	setupServers(opts)

	// Construct a client that can make use of the http2.Transport, whose
	// backing connection pool is populated by our custom h2ConnPool.
	tr := &http2.Transport{AllowHTTP: true}
	client := &http.Client{Transport: tr}

	// Create the connection pool.
	cp := newH2ConnPool(tr)

	// Add the connections to the pool, ID'd by a hostname that will be used
	// on the outbound request to identify the connection.
	keyFunc := func(hostname string) string {
		return fmt.Sprintf("%s:80", hostname)
	}
	for _, opt := range opts {
		conn, err := net.Dial("unix", opt.socketPath)
		assert.NoError(t, err)

		err = cp.AddConn(conn, keyFunc(opt.hostname))
		assert.NoError(t, err)
	}

	// Use the client, backed by the pool, to issue a request to each backend.
	for _, opt := range opts {
		ok := cp.hasConn(keyFunc(opt.hostname))
		assert.True(t, ok)

		url := fmt.Sprintf("http://%s", keyFunc(opt.hostname))
		r, err := http.NewRequest(http.MethodGet, url, nil)
		assert.NoError(t, err)

		resp, err := client.Do(r)
		assert.NoError(t, err)

		b, err := ioutil.ReadAll(resp.Body)
		assert.NoError(t, err)

		assert.Equal(t, opt.greeting, string(b))
	}
}
