package proxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/llm-operator/session-manager/server/internal/flushwriter"
	"golang.org/x/net/http2"
	"k8s.io/klog/v2"
)

const proxyTypeHTTP = "http"

const allowOriginHeaderName = "access-control-allow-origin"
const originHeaderName = "origin"
const varyHeaderName = "vary"

// HTTPProxy is a http/2 client that can proxy requests along one of multiple
// connections corresponding to identifying information on the incoming request.
type HTTPProxy struct {
	pool   *h2ConnPool
	client *http.Client
}

// NewHTTPProxy returns a new HTTPProxy.
func NewHTTPProxy() *HTTPProxy {
	t := &http2.Transport{}
	return &HTTPProxy{
		pool: newH2ConnPool(t),
		client: &http.Client{
			Transport: t,
			// Do not follow redirects (https://stackoverflow.com/questions/23297520/how-can-i-make-the-go-http-client-not-follow-redirects-automatically).
			// We should just pass the redirect back to the client.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// SetObserver sets the ConnObserver to its connection pool.
func (t *HTTPProxy) SetObserver(obs ConnObserver) {
	t.pool.observer = obs
}

// Add adds the connection to the proxy.
func (t *HTTPProxy) Add(id string, c net.Conn) error {
	return t.pool.AddConn(c, id)
}

// Proxy proxies a HTTP request to an agent using the appropriate connection.
func (t *HTTPProxy) Proxy(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get(originHeaderName)

	// Set the scheme and host.
	r.URL.Host = r.Host
	r.URL.Scheme = "https"

	// NOTE: Request.RequestURI can't be set in client requests.
	// http://golang.org/src/pkg/net/http/client.go
	r.RequestURI = ""

	klog.Infof("proxying request: url=%q", r.URL)
	resp, err := t.client.Do(r)
	if err != nil {
		klog.Infof("failed to proxy request: %s", err)
		http.Error(w, fmt.Sprintf("Server Error: %s", err), http.StatusInternalServerError)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	// Copy headers.
	for k, v := range resp.Header {
		// We want to inject the allow-origin header by ourselves.
		if strings.ToLower(k) == allowOriginHeaderName {
			continue
		}

		for _, vv := range v {
			w.Header().Add(k, vv)
		}
	}
	if origin != "" {
		w.Header().Add(allowOriginHeaderName, origin)
	}
	w.Header().Add(varyHeaderName, originHeaderName)

	// Copy body.
	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(flushwriter.New(w), resp.Body)
	if err != nil {
		klog.Infof("failed to proxy request: %s", err)
		http.Error(w, fmt.Sprintf("Server Error: %s", err), http.StatusInternalServerError)
		return
	}
}

// Status returns the current status of the proxy.
func (t *HTTPProxy) Status() Status {
	var status []TunnelStatus
	for _, ps := range t.pool.status() {
		status = append(status, TunnelStatus{
			ID:          ps.name,
			TunnelCount: ps.count,
		})
	}
	return Status{
		Type:    proxyTypeHTTP,
		Tunnels: status,
	}
}
