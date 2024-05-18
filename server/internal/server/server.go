package server

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Shopify/sarama"
	v1 "github.com/cloudnatix/activity-tracker/api/v1"
	"github.com/cloudnatix/authz/pkg/tokenprocess"
	"github.com/cloudnatix/certlib/pkg/store"
	"github.com/cloudnatix/connect-proxy/pkg/auth"
	"github.com/cloudnatix/connect-proxy/pkg/common"
	"github.com/cloudnatix/connect-proxy/proxy/internal/proxy"
	"k8s.io/klog/v2"
)

const (
	// keepAlivePeriod is the period between keep-alives for connections
	// that the proxy accepts from agents.
	keepAlivePeriod = 10 * time.Second

	websocketBearerProtocolPrefix = "base64url.bearer.authorization.k8s.io."
)

// Server is the public facing HTTP server, used to proxy requests to a cluster.
type Server struct {
	httpProxy          proxy.Proxy
	upgradeProxy       proxy.Proxy
	authenticator      auth.Authenticator
	identifier         auth.Identifier
	allowedOriginHosts map[string]struct{}
	// producer produces Kafka messages.
	producer sarama.SyncProducer

	processor tokenprocess.Processor
}

// Opts are options for a Server.
type Opts struct {
	HTTPProxy          proxy.Proxy
	UpgradeProxy       proxy.Proxy
	Authenticator      auth.Authenticator
	Identifier         auth.Identifier
	AllowedOriginHosts map[string]struct{}
	Producer           sarama.SyncProducer
}

// NewServer instantiates a new Server.
func NewServer(opts Opts) *Server {
	return &Server{
		httpProxy:          opts.HTTPProxy,
		upgradeProxy:       opts.UpgradeProxy,
		authenticator:      opts.Authenticator,
		identifier:         opts.Identifier,
		allowedOriginHosts: opts.AllowedOriginHosts,
		producer:           opts.Producer,

		processor: tokenprocess.NewProcessor(),
	}
}

// RunHTTPServerOpts are options for the RunHTTPServer function.
type RunHTTPServerOpts struct {
	Server   *Server
	CertPath string
	KeyPath  string
	Addr     string
}

// RunHTTPServer is a blocking function that starts the HTTP server.
func RunHTTPServer(
	ctx context.Context,
	opts RunHTTPServerOpts,
) error {
	// Inbound HTTP handlers.
	m := http.NewServeMux()
	m.Handle(common.PathAgentHTTP, http.HandlerFunc(opts.Server.handleAgentHTTP))
	m.Handle(common.PathAgentConnect, http.HandlerFunc(opts.Server.handleAgentConnect))
	m.Handle("/" /* fallthrough route */, http.HandlerFunc(opts.Server.handleProxy))

	// Create a reloading TLS certificate store to pick up any updates to the
	// TLS certificates.
	st, err := store.NewReloadingFileStore(store.ReloadingFileStoreOpts{
		KeyPath:  opts.KeyPath,
		CertPath: opts.CertPath,
	})
	if err != nil {
		return err
	}

	var cipherSuites []uint16
	// CipherSuites returns only secure ciphers.
	for _, c := range tls.CipherSuites() {
		cipherSuites = append(cipherSuites, c.ID)
	}

	httpSrv := &http.Server{
		Handler: m,
		TLSConfig: &tls.Config{
			GetCertificate: st.GetCertificateFunc(),
			// Support v1.2 as at least intruder.io needs v1.2 to run its scan.
			MinVersion: tls.VersionTLS12,
			// Exclude insecure ciphers.
			CipherSuites: cipherSuites,
		},
	}

	go func() {
		klog.Infof("Starting reloading certificate store.")
		if err := st.Run(ctx); err != nil {
			// Ensure we fail fast if the cert store can not be reloaded.
			klog.Fatalf("Server run: run certificate store reloader: %s", err)
		}
	}()

	// Set keep-alive as the connection can idle for a long period of time.
	lc := net.ListenConfig{
		KeepAlive: keepAlivePeriod,
	}
	l, err := lc.Listen(context.Background(), "tcp", opts.Addr)
	if err != nil {
		return fmt.Errorf("listen: %s", err)
	}

	klog.Infof("Starting HTTPS listener: addr=%q", opts.Addr)
	tlsListener := tls.NewListener(l, httpSrv.TLSConfig)
	if err := httpSrv.Serve(tlsListener); err != nil {
		return fmt.Errorf("serve TLS: %s", err)
	}

	return nil
}

// handleAgentHTTP is a http.HandlerFunc used to add new connections for HTTP
// proxying.
func (s *Server) handleAgentHTTP(w http.ResponseWriter, r *http.Request) {
	klog.Infof("Handling agent HTTP tunnel request.")

	conn, id := s.doHandshakeWithAgent(w, r)
	if conn == nil {
		return
	}

	if err := s.httpProxy.Add(id, conn); err != nil {
		klog.Infof("Could not initialize agent connection: %s", err)
		_ = conn.Close()
		return
	}

	klog.Infof("Established HTTP tunnel (ID: %q)", id)
}

// handleAgentConnect is a http.HandlerFunc used to add new connections for HTTP
// CONNECT proxying.
func (s *Server) handleAgentConnect(w http.ResponseWriter, r *http.Request) {
	klog.Infof("Handling agent CONNECT tunnel request.")

	conn, id := s.doHandshakeWithAgent(w, r)
	if conn == nil {
		return
	}

	if err := s.upgradeProxy.Add(id, conn); err != nil {
		klog.Infof("Could not initialize agent connection: %s", err)
		if err := conn.Close(); err != nil {
			klog.Errorf("Failed to close the agent connection: %s", err)
		}
		return
	}

	klog.Infof("Established CONNECT tunnel (ID: %q)", id)
}

func (s *Server) handlePreflight(w http.ResponseWriter, r *http.Request) int {
	origin := r.Header.Get("origin")
	originURL, err := url.Parse(origin)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		return http.StatusForbidden
	}
	// Preflight requests are sent automatically from the browser to check
	// the availability of cross-origin requests. For the details, see
	// https://developer.mozilla.org/en-US/docs/Glossary/Preflight_request.
	klog.Infof("Preflight request from the browser: origin hostname = %q.", originURL.Hostname())

	if !s.isAllowedOrigin(originURL) {
		w.WriteHeader(http.StatusForbidden)
		return http.StatusForbidden
	}

	w.Header().Add("Access-Control-Allow-Origin", origin)

	// Header with '*' does NOT include Authorization, thus it will have
	// to be allowed explicitly. See
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Headers#directives.
	w.Header().Add("Access-Control-Allow-Headers", "authorization, content-type")

	// Methods should be listed explicitly; not '*' is used. See
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Methods#directives.
	allowedMethods := []string{
		http.MethodGet,
		http.MethodHead,
		http.MethodDelete,
		http.MethodPatch,
		http.MethodPost,
		http.MethodPut,
		http.MethodTrace,
		http.MethodConnect,
		http.MethodOptions,
	}
	w.Header().Add("Access-Control-Allow-Methods", strings.Join(allowedMethods, ","))

	w.Header().Add("Vary", "Origin")

	w.WriteHeader(http.StatusNoContent)

	if _, err := w.Write(nil); err != nil {
		klog.Errorf("Could not write status: %s", err)
		http.Error(w, "could not write status", http.StatusInternalServerError)
		return http.StatusInternalServerError
	}
	return http.StatusNoContent
}

// convertWebSocketBearerToken extracts a bearer token from the
// Sec-WebSocket-Protocol header on r if any, converts it into an Authorization
// header, and adds it on r.
//
// We expect that the bearer token is in the format used by the Kubernetes API
// server to embed tokens in the Sec-WebSocket-Protocol header of a WebSocket
// handshake.
//
// See https://github.com/kubernetes/apiserver/blob/2ced48ac6e68d133b27a107d854a3e2765bdb353/pkg/authentication/request/websocket/protocol.go
// for the details.
//
// CAUTION: This function converts the extracted bearer token into an
// Authorization header and adds it to r WITHOUT validating that it's really
// a JWT token. The bearer token may include some malicious string intended to
// attack us. Never serialize it and forward to a backend without validating it.
func convertWebSocketBearerToken(r *http.Request) error {
	if r.Header == nil {
		return nil
	}

	wsProto := r.Header.Get("Sec-WebSocket-Protocol")
	if wsProto == "" {
		klog.V(2).Infof("Sec-WebSocket-Protocol not found")
		return nil
	}

	// See the following RFCs for the ABNF of the header:
	// https://datatracker.ietf.org/doc/html/rfc6455#section-4.3
	// https://datatracker.ietf.org/doc/html/rfc2616#section-2.2
	for _, proto := range strings.Split(wsProto, ",") {
		proto = strings.Trim(proto, " \t")
		if !strings.HasPrefix(proto, websocketBearerProtocolPrefix) {
			continue
		}

		encodedToken := proto[len(websocketBearerProtocolPrefix):]

		token, err := base64.RawURLEncoding.DecodeString(encodedToken)
		if err != nil {
			return fmt.Errorf("decode WebSocket bearer token as base64: %s", err)
		}

		r.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
		klog.V(2).Infof("Converted WebSocket bearer token into an Authorization header")

		// Still keep the existing header on "Sec-WebSocket-Protocol". K8s API server
		// doesn't accept a request if the header doesn't exist.
		// TODO(kenji): Investigate why. It is strange since the token in "Sec-WebSocket-Protocol"
		// is not what k8s API servers in customers' clusters accept (CNATIX-1014).
		return nil
	}

	return nil
}

// handleProxy is a HTTP handler that proxies the incoming request on the
// appropriate connection to the cluster.
func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {

	respCode := 0
	upgraded := false
	defer func() {
		if r.Method == http.MethodOptions {
			// Ignore OPTIONS.
			return
		}
		if r.Method == http.MethodGet && !upgraded {
			// Ignore GET except upgrade.
			return
		}
		if err := s.trackHTTPRequest(v1.ConnectProxyRequestKind_PROXY, r, respCode); err != nil {
			klog.Infof("Failed to log the event: %s", err)
		}
	}()

	if r.Method == http.MethodOptions {
		respCode = s.handlePreflight(w, r)
		return
	}

	klog.Infof("Proxying inbound HTTP request (URL: %s)", r.URL)

	if err := convertWebSocketBearerToken(r); err != nil {
		klog.Infof("Failed to convert WebSocket bearer token: %s", err)
	}

	// Authenticate the request.
	err := s.authenticator.Authenticate(r)
	if err != nil {
		klog.Infof("Authentication failed: %s", err)
		http.Error(w, "not authorized", http.StatusUnauthorized)
		respCode = http.StatusUnauthorized
		return
	}

	// Identify the request.
	id, err := s.identifier.Identify(r)
	if err != nil {
		klog.Infof("Identification failed: %s", err)
		http.Error(w, "could not identify request", http.StatusBadRequest)
		respCode = http.StatusUnauthorized
		return
	}

	// Add the port suffix to the host header, if it is not present.
	//
	// TODO(nick): this feels brittle. Is there a better way to do this?
	if !strings.HasSuffix(id, ":443") {
		id = id + ":443"
	}

	r.Host = id
	klog.V(2).Infof("Updated host=%q", r.Host)

	switch tType := inferTunnelType(r); {
	case tType == tunnelTypeHTTP:
		klog.Infof("Proxying HTTP request to cluster %s", r.Host)
		respCode = s.httpProxy.Proxy(w, r)
	case tType == tunnelTypeUpgrade:
		klog.Infof("Proxying HTTP upgrade request to cluster %s", r.Host)
		respCode = s.upgradeProxy.Proxy(w, r)
		upgraded = true
	default:
		klog.Infof("Unknown connection type: %q", tType)
		http.Error(w, "unknown connection type", http.StatusBadRequest)
		respCode = http.StatusUnauthorized
	}
}

// doHandshakeWithAgent authenticates an incoming request from an agent. The
// underlying connection to the agent is returned.
func (s *Server) doHandshakeWithAgent(w http.ResponseWriter, r *http.Request) (conn net.Conn, id string) {
	klog.Infof("Handling handshake (host: %s)", r.Host)

	// Authenticate the request.
	err := s.authenticator.Authenticate(r)
	if err != nil {
		klog.Infof("Authentication failed: %s", err)
		http.Error(w, "not authorized", http.StatusUnauthorized)
		return
	}

	// Identify the request.
	id, err = s.identifier.Identify(r)
	if err != nil {
		klog.Infof("Identification failed: %s", err)
		http.Error(w, "could not identify request", http.StatusBadRequest)
		return
	}
	id = fmt.Sprintf("%s:443", id)

	// Determine the desired protocol.
	proto := r.Header.Get(common.HeaderProto)
	if proto == "" {
		klog.Infof("Missing %q header.", common.HeaderProto)
		http.Error(w, fmt.Sprintf("missing %q header", common.HeaderProto), http.StatusBadRequest)
		// TODO: close connection to proxy.
		return
	}

	switch proto {
	case common.ProtoV1:
	default:
		klog.V(2).Infof("Unknown protocol %q.", proto)
		http.Error(w, fmt.Sprintf("unknown protocol %q", proto), http.StatusBadRequest)
		// TODO: close connection to proxy.
		return
	}

	// Return the response to the CONNECT request. These headers are detailed in
	// RFC 7239, Section 6.3.
	klog.V(2).Infof("Finalizing upgrade.")
	w.Header().Add("Connection", "Upgrade")
	w.Header().Add("Upgrade", proto)
	w.WriteHeader(http.StatusSwitchingProtocols)

	// Hijack and return the (connection, ID) pair.

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		klog.Infof("could not case writer (type=%T) as a http.Hijacker.", w)
		http.Error(w, "connection upgrade could not be completed", http.StatusInternalServerError)
		// TODO: close connection to proxy.
		return
	}

	// TODO: Process the unprocessed buffer?
	conn, _, err = hijacker.Hijack()
	if err != nil {
		klog.Infof("could not hijack connection: %s", err)
		http.Error(w, "connection upgrade could not be completed", http.StatusInternalServerError)
		// TODO: close connection to proxy.
		return
	}

	klog.Infof("Handshake successful (ID: %q)", id)
	return
}

// isAllowedOrigin returns if the originURL is allowed for CORS preflight check.
func (s *Server) isAllowedOrigin(originURL *url.URL) bool {
	h := originURL.Hostname()
	if h == "localhost" {
		// Local host is always allowed. Mostly for the convenience
		// of frontend development.
		return true
	}

	_, ok := s.allowedOriginHosts[h]
	return ok && originURL.Scheme == "https"
}
