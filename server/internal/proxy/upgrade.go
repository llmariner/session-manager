package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/llm-operator/session-manager/server/internal/flushwriter"
	"k8s.io/klog/v2"
)

const (
	dummyHostname    = "_unused"
	proxyTypeUpgrade = "connect"
)

var hostPort = fmt.Sprintf("%s:443", dummyHostname)

// UpgradeProxy proxies requests on connections that need to be "upgraded"
// before non-HTTP traffic can be sent on the connection (e.g. SPDY for kubectl
// exec, etc.), possibly in either direction.
type UpgradeProxy struct {
	m          sync.RWMutex
	transports map[string][]*http.Transport

	// numTakenTransports is the number of transports keyed by cluster ID.
	numTakenTransports map[string]int

	baseURL string
}

// NewUpgradeProxy returns a new ConnectProxy.
func NewUpgradeProxy(baseURL string) *UpgradeProxy {
	return &UpgradeProxy{
		transports:         make(map[string][]*http.Transport),
		numTakenTransports: make(map[string]int),

		baseURL: baseURL,
	}
}

// Add adds the connection to the connection pool.
func (t *UpgradeProxy) Add(id string, c net.Conn) error {
	klog.Infof("Adding connection (ID: %q, proto=CONNECT)", id)

	tr := &http.Transport{
		DialTLSContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return c, nil
		},
	}

	// Add this client to the map for this cluster.
	t.putTransport(id, tr)

	return nil
}

// Proxy proxies a HTTP requests that need to be "upgraded" (i.e. for kubectl
// exec, port-forward, etc.).
//
// Following the upgrade between the proxy and the agent, the connection between
// the client and the proxy is "hijacked". The two sides of the connection
// (client -> proxy, and proxy -> agent) can then be bridged to allow
// bidirectional traffic flow.
func (t *UpgradeProxy) Proxy(w http.ResponseWriter, r *http.Request) {
	tr := t.takeTransport(r.Host)
	if tr == nil {
		t.m.Lock()
		n := t.numTakenTransports[r.Host]
		t.m.Unlock()

		msg := fmt.Sprintf("transport not found for host: %q (%d transport(s) in-use)", r.Host, n)
		klog.Info(msg)
		http.Error(w, fmt.Sprintf("Server Error: %s", msg), http.StatusInternalServerError)
		return
	}

	t.m.Lock()
	t.numTakenTransports[r.Host]++
	t.m.Unlock()

	defer func() {
		t.m.Lock()
		defer t.m.Unlock()
		t.numTakenTransports[r.Host]--
		if t.numTakenTransports[r.Host] == 0 {
			delete(t.numTakenTransports, r.Host)
		}
	}()

	// Set the scheme and host.
	r.URL.Scheme = "https"
	// NOTE: we rewrite the host:port pair to a well-known, static value to
	// avoid the http.Transport creating a new pooled connection making use of
	// the same TCP connection, which will result in an error when data is
	// written to the connection.
	r.URL.Host = hostPort

	r.URL.Path = strings.TrimPrefix(r.URL.Path, t.baseURL)

	// NOTE: Request.RequestURI can't be set in client requests.
	// http://golang.org/src/pkg/net/http/client.go
	r.RequestURI = ""

	klog.V(2).Infof("Proxying request.")

	resp, err := tr.RoundTrip(r)
	if err != nil {
		msg := fmt.Sprintf("failed to proxy request: %s", err)
		klog.Infof(msg)
		http.Error(w, fmt.Sprintf("Server Error: %s", msg), http.StatusInternalServerError)
		return
	}
	defer func() {
		if err = resp.Body.Close(); err != nil {
			klog.Errorf("Failed to close response body: %s", err)
		}
	}()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		b, _ := io.ReadAll(resp.Body)
		msg := fmt.Sprintf("could not switch protocols; statusCode=%d; status=%s; body=%s", resp.StatusCode, resp.Status, string(b))
		klog.Warningf(msg)
		http.Error(w, string(b), resp.StatusCode)
		return
	}

	// Copy headers to complete upgrade.
	for k, vs := range resp.Header {
		// We want to inject the Access-Control-Allow-Origin CORS header by
		// ourselves.
		if strings.ToLower(k) == allowOriginHeaderName {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.Header().Add(allowOriginHeaderName, "*")
	w.WriteHeader(resp.StatusCode)

	// The response body from an Upgrade request with a 101 - Switching
	// Protocols status can be used to send / receive data to / from the agent,
	// when cast as an io.ReadWriteCloser.
	agentConn, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		msg := fmt.Sprintf("body (type=%T) does not implement io.ReadWriteCloser", resp.Body)
		klog.Info(msg)
		http.Error(w, fmt.Sprintf("Server Error: %s", msg), http.StatusInternalServerError)
		return
	}
	defer func() {
		if err := agentConn.Close(); err != nil {
			klog.Infof("Failed to close the agent connection: %s", err)
		}
	}()

	// Hijack the client-side connection so that we can use it to send / receive
	// bytes to / from the client.
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		msg := fmt.Sprintf("writer (type=%T) does not implement http.Hijacker", w)
		klog.Info(msg)
		http.Error(w, fmt.Sprintf("Server Error: %s", msg), http.StatusInternalServerError)
		return
	}

	klog.V(2).Infof("Hijacking connection.")

	// TODO: Process the buffer?
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		msg := fmt.Sprintf("could not hijack connection: %s", err)
		klog.Info(msg)
		http.Error(w, fmt.Sprintf("Server Error: %s", msg), http.StatusInternalServerError)
		return
	}
	defer func() {
		if err := clientConn.Close(); err != nil {
			klog.Infof("Failed to close the (hijacked) client connection: %s", err)
		}
	}()

	// Bridge the two sides of the connection so that bytes can be proxied
	// between the client and the agent.
	doneC := make(chan struct{})

	// Proxy -> Client.
	go func() {
		klog.Infof("Starting proxy -> client bridge.")

		_, err := io.Copy(flushwriter.New(clientConn), agentConn)
		if err != nil {
			klog.Warningf("Copy (proxy -> client) failed: %s", err)
		}
		klog.Infof("Proxy -> client bridge complete.")
		doneC <- struct{}{}
	}()

	// Proxy -> Agent.
	go func() {
		klog.Infof("Starting proxy -> agent bridge.")

		_, err := io.Copy(flushwriter.New(agentConn), clientConn)
		if err != nil {
			klog.Warningf("Copy (proxy -> agent) failed: %s", err)
		}
		klog.Infof("Proxy -> agent bridge complete.")
		doneC <- struct{}{}
	}()

	// Block waiting for one side of the connection to close.
	<-doneC

	// Kick off a cleanup goroutine that will wait for the other side of the
	// connection to be closed. This allows the deferred statements to run even
	// after the calling function exits, which will clean up both sides of the
	// bridged connection.
	go func() {
		<-doneC
		klog.Infof("Bridging complete.")
		close(doneC)
	}()
}

// takeTransport fetches a http.Transport from the map. If there is no available
// transport, the function returns nil.
func (t *UpgradeProxy) takeTransport(id string) *http.Transport {
	klog.Infof("Fetching CONNECT transport (ID: %q)", id)
	t.m.Lock()
	defer t.m.Unlock()

	// Fetch the slice of transports.
	trs, ok := t.transports[id]

	// If there is no slice, there is no transport available, return.
	if !ok {
		klog.Warningf("No transports for the cluster (ID: %q)", id)
		return nil
	}

	// Take the last item from the slice.
	tr := trs[len(trs)-1]
	trs = trs[:len(trs)-1]
	klog.Infof("%d transports remaining for the cluster (ID: %q)", len(trs), id)

	// Return the slice to the map if there are still transports remaining.
	if len(trs) > 0 {
		t.transports[id] = trs
	} else {
		// Remove the empty slice from the map.
		delete(t.transports, id)
	}

	// Return the transport.
	return tr
}

// putTransport places a http.Transport in the map.
func (t *UpgradeProxy) putTransport(id string, tr *http.Transport) {
	klog.Infof("Adding CONNECT transport (ID: %q)", id)

	t.m.Lock()
	defer t.m.Unlock()

	trs, ok := t.transports[id]

	// If this is the first transport, initialize the slice.
	if !ok {
		trs = []*http.Transport{}
	}

	// Add the transport.
	trs = append(trs, tr)

	// Set the slice in the map.
	t.transports[id] = trs

	klog.Infof("%d transports for cluster (ID: %q)", len(trs), id)
}

// Status returns the current status of the proxy.
func (t *UpgradeProxy) Status() Status {
	t.m.RLock()
	defer t.m.RUnlock()

	var tunnels []TunnelStatus
	for k, v := range t.transports {
		tunnels = append(tunnels, TunnelStatus{
			ID:          k,
			TunnelCount: len(v),
		})
	}

	return Status{
		Type:    proxyTypeUpgrade,
		Tunnels: tunnels,
	}
}

// OnMarkDead implements ConnObserver.OnMarkDead.
//
// This function closes all connections for the given ID. The intention is to call this function to
// close HTTP/1 connections when a corresponding HTTP/2 connection is closed.
func (t *UpgradeProxy) OnMarkDead(id string) {
	t.m.Lock()
	defer t.m.Unlock()

	trs, ok := t.transports[id]
	if !ok {
		return
	}
	for i, tr := range trs {
		c, err := tr.DialTLSContext(nil, "", "")
		if err != nil {
			klog.Infof("failed to get the connection: %s", err)
			continue
		}
		if err := c.Close(); err != nil {
			klog.Infof("failed to close the connection at %d: %s", i, err)
		}
	}
	klog.Infof("removing CONNECT transport; ID=%q", id)
	delete(t.transports, id)
}
