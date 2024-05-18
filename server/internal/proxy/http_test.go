package proxy

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHTTPProxy(t *testing.T) {
	opt := testServerOpts{
		socketPath: t.TempDir() + "/server.sock",
		greeting:   "Hello, world!",
	}
	setupServers([]testServerOpts{opt})

	tunnel := NewHTTPProxy()

	// Add a connection for a single ID to the pool.
	key := "cluster-1:80"
	conn, err := net.Dial("unix", opt.socketPath)
	assert.NoError(t, err)

	err = tunnel.pool.AddConn(conn, key)
	assert.NoError(t, err)

	// The tunnel has a connection for the ID we added.
	assert.True(t, tunnel.pool.hasConn(key))

	// The tunnel has no connection.
	assert.False(t, tunnel.pool.hasConn("some-other-key:80"))

	// Proxy a request through the tunnel.
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s", key), nil)
	origin := "https://app.staging.cloudnatix.com"
	req.Header.Set(originHeaderName, origin)
	assert.NoError(t, err)

	w := httptest.NewRecorder()
	_ = tunnel.Proxy(w, req)

	resp := w.Result()
	b, err := ioutil.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, opt.greeting, string(b))

	// Should always have the access-control-allow-origin header.
	assert.Equal(t, origin, resp.Header.Get(allowOriginHeaderName))

	// Proxying a response for an ID that has no connection results in an error.
	req, err = http.NewRequest(http.MethodGet, "http://some-other-key:80", nil)
	assert.NoError(t, err)

	w = httptest.NewRecorder()
	_ = tunnel.Proxy(w, req)

	resp = w.Result()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}
