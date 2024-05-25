package server

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/llm-operator/session-manager/common/pkg/auth"
	"github.com/llm-operator/session-manager/common/pkg/common"
	"github.com/llm-operator/session-manager/server/internal/proxy"
	"github.com/stretchr/testify/assert"
)

func TestServer_doHandshakeWithAgent(t *testing.T) {
	var (
		id   = "test-id"
		conn = &net.TCPConn{}
	)

	tcs := []struct {
		name          string
		authenticator auth.Authenticator
		identifier    auth.Identifier

		req        *http.Request
		hijackFunc func() (net.Conn, *bufio.ReadWriter, error)

		wantCode int
		wantID   string
		wantConn net.Conn
	}{
		/*
			{
				name:          "auth fails",
				authenticator: &fakeAuthenticator{valid: false},
				req:           &http.Request{},
				wantCode:      http.StatusUnauthorized,
			},
		*/
		{
			name:          "identification fails",
			authenticator: &fakeAuthenticator{valid: true},
			identifier:    &fakeIdentifier{err: fmt.Errorf("auth error")},
			req:           &http.Request{},
			wantCode:      http.StatusBadRequest,
		},
		{
			name:          "missing protocol header",
			authenticator: &fakeAuthenticator{valid: true},
			identifier:    &fakeIdentifier{id: id},
			req:           &http.Request{},
			wantCode:      http.StatusBadRequest,
			wantID:        fmt.Sprintf("%s:443", id),
		},
		{
			name:          "unknown protocol",
			authenticator: &fakeAuthenticator{valid: true},
			identifier:    &fakeIdentifier{id: id},
			req: &http.Request{
				Header: header(common.HeaderProto, "unknown"),
			},
			wantCode: http.StatusBadRequest,
			wantID:   fmt.Sprintf("%s:443", id),
		},
		{
			name:          "upgrade fails",
			authenticator: &fakeAuthenticator{valid: true},
			identifier:    &fakeIdentifier{id: id},
			req: &http.Request{
				Header: header(common.HeaderProto, common.ProtoV1),
			},
			hijackFunc: func() (net.Conn, *bufio.ReadWriter, error) {
				return nil, nil, fmt.Errorf("uh oh")
			},
			wantCode: http.StatusSwitchingProtocols,
			wantID:   fmt.Sprintf("%s:443", id),
		},
		{
			name:          "upgrade succeeds",
			authenticator: &fakeAuthenticator{valid: true},
			identifier:    &fakeIdentifier{id: id},
			req: &http.Request{
				Header: header(common.HeaderProto, common.ProtoV1),
			},
			hijackFunc: func() (net.Conn, *bufio.ReadWriter, error) {
				return conn, nil, fmt.Errorf("uh oh")
			},
			wantCode: http.StatusSwitchingProtocols,
			wantID:   fmt.Sprintf("%s:443", id),
			wantConn: &net.TCPConn{},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			s := Server{
				authenticator: tc.authenticator,
				identifier:    tc.identifier,
			}

			w := &fakeResponseWriter{
				ResponseRecorder: httptest.NewRecorder(),
				hijackFunc:       tc.hijackFunc,
			}

			gotConn, gotID := s.doHandshakeWithAgent(w, tc.req)
			assert.Equal(t, tc.wantCode, w.Result().StatusCode)
			assert.Equal(t, tc.wantID, gotID)

			// If the status code is non-200, we're done testing.
			if tc.wantCode != http.StatusOK {
				return
			}

			// Else, test the upgrade was successful.

			// Headers are present.
			resp := w.Result()
			h := resp.Header.Get("connection")
			assert.Equal(t, "upgrade", h)

			h = resp.Header.Get("upgrade")
			assert.Equal(t, common.ProtoV1, h)

			// Client-side connection was hijacked and returned.
			assert.Equal(t, common.ProtoV1, h)
			assert.Equal(t, tc.wantConn, gotConn)
		})
	}
}

func TestServer_handleAgentHTTP(t *testing.T) {
	id := "test"

	p := &fakeProxy{}
	s := &Server{
		httpProxy:     p,
		upgradeProxy:  &fakeProxy{},
		authenticator: &fakeAuthenticator{valid: true},
		identifier:    &fakeIdentifier{id: id},
	}

	conn := &net.TCPConn{}
	w := &fakeResponseWriter{
		ResponseRecorder: httptest.NewRecorder(),
		hijackFunc: func() (net.Conn, *bufio.ReadWriter, error) {
			return conn, nil, nil
		},
	}

	req := &http.Request{
		Header: header(common.HeaderProto, common.ProtoV1),
	}
	s.handleAgentHTTP(w, req)

	assert.Equal(t, http.StatusSwitchingProtocols, w.Result().StatusCode)
	assert.Equal(t, id+":443", p.id)
	assert.Equal(t, conn, p.conn)
}

func TestServer_handleAgentConnect(t *testing.T) {
	id := "test"

	p := &fakeProxy{}
	s := &Server{
		httpProxy:     &fakeProxy{},
		upgradeProxy:  p,
		authenticator: &fakeAuthenticator{valid: true},
		identifier:    &fakeIdentifier{id: id},
	}

	conn := &net.TCPConn{}
	w := &fakeResponseWriter{
		ResponseRecorder: httptest.NewRecorder(),
		hijackFunc: func() (net.Conn, *bufio.ReadWriter, error) {
			return conn, nil, nil
		},
	}

	req := &http.Request{
		Header: header(common.HeaderProto, common.ProtoV1),
	}
	s.handleAgentConnect(w, req)

	assert.Equal(t, http.StatusSwitchingProtocols, w.Result().StatusCode)
	assert.Equal(t, id+":443", p.id)
	assert.Equal(t, conn, p.conn)
}

func TestConvertWebSocketBearerToken(t *testing.T) {
	tcs := []struct {
		name string

		req     func() *http.Request
		want    []string
		wantErr bool
	}{
		{
			name: "No headers",

			req: func() *http.Request { return &http.Request{} },

			want:    nil,
			wantErr: false,
		},
		{
			name: "No Sec-WebSocket-Protocol header",

			req: func() *http.Request {
				return &http.Request{
					Header: http.Header{},
				}
			},

			want:    nil,
			wantErr: false,
		},
		{
			name: "Sec-WebSocket-Protocol header doesn't have a bearer token",

			req: func() *http.Request {
				req := http.Request{
					Header: http.Header{},
				}
				req.Header.Add("Sec-WebSocket-Protocol", "v4.channel.k8s.io")
				return &req
			},

			want:    nil,
			wantErr: false,
		},
		{
			name: "The header has an entry with the bearer token prefix, but the following string is not Base64",

			req: func() *http.Request {
				req := http.Request{
					Header: http.Header{},
				}
				req.Header.Add("Sec-WebSocket-Protocol", "v4.channel.k8s.io, base64url.bearer.authorization.k8s.io.!")
				return &req
			},

			want:    nil,
			wantErr: true,
		},
		{
			name: "The header has a bearer token entry",

			req: func() *http.Request {
				req := http.Request{
					Header: http.Header{},
				}
				req.Header.Add("Sec-WebSocket-Protocol", "v4.channel.k8s.io, base64url.bearer.authorization.k8s.io.VGVzdA")
				return &req
			},

			want:    []string{"Bearer Test"},
			wantErr: false,
		},
		{
			name: "The header has a bearer token entry (bearer token comes first)",

			req: func() *http.Request {
				req := http.Request{
					Header: http.Header{},
				}
				req.Header.Add("Sec-WebSocket-Protocol", "base64url.bearer.authorization.k8s.io.VGVzdA, v4.channel.k8s.io")
				return &req
			},

			want:    []string{"Bearer Test"},
			wantErr: false,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			req := tc.req()
			err := convertWebSocketBearerToken(req)

			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)

			vs := req.Header.Values("Authorization")
			assert.ElementsMatch(t, tc.want, vs)
		})
	}
}

func TestServer_handleProxy(t *testing.T) {
	id := "test"

	tcs := []struct {
		name          string
		authenticator auth.Authenticator
		identifier    auth.Identifier

		req *http.Request

		wantCode  int
		wantProxy tunnelType
	}{
		{
			name:          "authentication fails",
			authenticator: &fakeAuthenticator{valid: false},
			req:           &http.Request{},
			wantCode:      http.StatusUnauthorized,
		},
		{
			name:          "identification fails",
			authenticator: &fakeAuthenticator{valid: true},
			identifier:    &fakeIdentifier{err: fmt.Errorf("auth error")},
			req:           &http.Request{},
			wantCode:      http.StatusBadRequest,
		},
		{
			name:          "tunnel type HTTP",
			authenticator: &fakeAuthenticator{valid: true},
			identifier:    &fakeIdentifier{id: id},
			req:           &http.Request{}, // no upgrade header
			wantCode:      http.StatusSwitchingProtocols,
			wantProxy:     tunnelTypeHTTP,
		},
		{
			name:          "tunnel type CONNECT",
			authenticator: &fakeAuthenticator{valid: true},
			identifier:    &fakeIdentifier{id: id},
			req: &http.Request{
				Header: header("upgrade", common.ProtoV1),
			},
			wantCode:  http.StatusSwitchingProtocols,
			wantProxy: tunnelTypeUpgrade,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			httpProxy := &fakeProxy{}
			connectProxy := &fakeProxy{}

			s := &Server{
				httpProxy:     httpProxy,
				upgradeProxy:  connectProxy,
				authenticator: tc.authenticator,
				identifier:    tc.identifier,
			}

			w := httptest.NewRecorder()
			s.handleProxy(w, tc.req)

			// If the status code is non-101, we're done testing.
			if tc.wantCode != http.StatusSwitchingProtocols {
				assert.Equal(t, tc.wantCode, w.Result().StatusCode)
				return
			}

			// Else, test the correct proxy received the request.
			switch tc.wantProxy {
			case tunnelTypeHTTP:
				assert.NotNil(t, httpProxy.gotWriter)
				assert.NotNil(t, httpProxy.gotReq)
				assert.Nil(t, connectProxy.gotWriter)
				assert.Nil(t, connectProxy.gotReq)
			case tunnelTypeUpgrade:
				assert.Nil(t, httpProxy.gotWriter)
				assert.Nil(t, httpProxy.gotReq)
				assert.NotNil(t, connectProxy.gotWriter)
				assert.NotNil(t, connectProxy.gotReq)
			default:
				t.Fatalf("unexpected tunnel type")
			}
		})
	}
}

func TestServer_preflight(t *testing.T) {
	s := &Server{
		httpProxy:     &fakeProxy{},
		upgradeProxy:  &fakeProxy{},
		authenticator: &fakeAuthenticator{},
		identifier:    &fakeIdentifier{},
		allowedOriginHosts: map[string]struct{}{
			"app.staging.llm-operator.com": {},
			"app.llm-operator.com":         {},
		},
	}

	for _, origin := range []string{
		"http://localhost",
		"https://app.staging.llm-operator.com",
		"https://app.llm-operator.com",
		"https://app.staging.llm-operator.com:443",
	} {
		t.Run(origin, func(t *testing.T) {
			rh := http.Header{}
			rh.Add("Access-Control-Request-Method", "GET")
			rh.Add("Access-Control-Request-Headers", "origin, authorization")
			rh.Add("Origin", origin)
			req := &http.Request{
				Method: http.MethodOptions,
				URL:    &url.URL{},
				Header: rh,
			}
			w := httptest.NewRecorder()
			s.handleProxy(w, req)

			h := w.Result().Header
			v := h.Get("Access-Control-Allow-Origin")
			assert.Equal(t, v, origin)
			v = h.Get("Vary")
			assert.Equal(t, "Origin", v)
			v = h.Get("Access-Control-Allow-Headers")
			assert.Equal(t, "authorization, content-type", v)
			v = h.Get("Access-Control-Allow-Methods")
			assert.NotEqual(t, "*", v)
			methods := strings.Split(v, ",")
			for _, method := range []string{
				http.MethodGet,
				http.MethodDelete,
				http.MethodPut,
				http.MethodPost,
				http.MethodPatch,
				http.MethodConnect,
			} {
				assert.Contains(t, methods, method)
			}
		})
	}
}

func TestServer_preflightNotAllowed(t *testing.T) {
	s := &Server{
		httpProxy:     &fakeProxy{},
		upgradeProxy:  &fakeProxy{},
		authenticator: &fakeAuthenticator{},
		identifier:    &fakeIdentifier{},
		allowedOriginHosts: map[string]struct{}{
			"app.staging.llm-operator.com": {},
			"app.llm-operator.com":         {},
		},
	}

	for _, origin := range []string{
		"http://app.staging.llm-operator.com",
		"https://example.com",
		"",
		"....",
	} {
		t.Run(origin, func(t *testing.T) {
			rh := http.Header{}
			rh.Add("Access-Control-Request-Method", "GET")
			rh.Add("Access-Control-Request-Headers", "origin, authorization")
			rh.Add("Origin", origin)
			req := &http.Request{
				Method: http.MethodOptions,
				URL:    &url.URL{},
				Header: rh,
			}
			w := httptest.NewRecorder()
			s.handleProxy(w, req)

			assert.NotEqual(t, w.Result().Status, http.StatusOK)

			h := w.Result().Header
			for _, header := range []string{
				"Access-Control-Allow-Origin",
				"Access-Control-Allow-Headers",
				"Access-Control-Allow-Methods",
			} {
				v := h.Get(header)
				assert.Empty(t, v)
			}
		})
	}
}

// fakeResponseWriter is a httptest.ResponseRecorder that also implements
// http.Hijacker.
type fakeResponseWriter struct {
	*httptest.ResponseRecorder

	hijackFunc func() (net.Conn, *bufio.ReadWriter, error)
}

// Hijack implements http.Hijacker by returning the connection from the
// hajackFunc.
func (w *fakeResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.hijackFunc()
}

// fakeAuthenticator is an Authenticator for use in tests.
type fakeAuthenticator struct {
	valid bool
}

// Authenticate implements Authenticator by return any stored error.
func (a *fakeAuthenticator) Authenticate(_ *http.Request) error {
	if !a.valid {
		return auth.ErrUnauthorized
	}
	return nil
}

// fakeIdentifier is an Identifier for use in tests.
type fakeIdentifier struct {
	id  string
	err error
}

// Identify implements Identifier by returning ether the store ID or and error.
func (i *fakeIdentifier) Identify(_ *http.Request) (string, error) {
	if i.err != nil {
		return "", i.err
	}
	return i.id + ":443", nil
}

// fakeProxy is a proxy.Proxy for user in tests.
type fakeProxy struct {
	id   string
	conn net.Conn

	gotWriter http.ResponseWriter
	gotReq    *http.Request
}

// Add stores the ID and connection.
func (p *fakeProxy) Add(id string, conn net.Conn) error {
	p.id = id
	p.conn = conn
	return nil
}

// Proxy stores the writer and the request.
func (p *fakeProxy) Proxy(w http.ResponseWriter, r *http.Request) {
	p.gotWriter = w
	p.gotReq = r
}

// Status returns the current status of the fakeProxy. Always a single
// connection.
func (p *fakeProxy) Status() proxy.Status {
	return proxy.Status{
		Type: "test",
		Tunnels: []proxy.TunnelStatus{
			{
				ID:          p.id,
				TunnelCount: 1,
			},
		},
	}
}
