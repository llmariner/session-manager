package tunnel

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/llmariner/rbac-manager/pkg/auth"
	"github.com/llm-operator/session-manager/common/pkg/common"
	"k8s.io/klog/v2"
)

const dialSleepTime = time.Second

// Opts are the options for configuring a Tunnel.
type Opts struct {
	PoolSize    int
	DialTimeout time.Duration

	URL *url.URL

	EnvoySocket string

	TLSEnabled bool
}

// Tunnel establishes a TCP connection between the proxy (running remotely) and
// Envoy (running alongside the agent).
type Tunnel struct {
	poolSizeDesired int
	dialTimeout     time.Duration

	url *url.URL

	envoySocket string

	tlsEnabled bool

	m           sync.RWMutex
	poolSizeCur int
}

// NewTunnel instantiates a new Tunnel.
func NewTunnel(opts Opts) (*Tunnel, error) {
	return &Tunnel{
		poolSizeDesired: opts.PoolSize,
		dialTimeout:     opts.DialTimeout,

		url: opts.URL,

		tlsEnabled: opts.TLSEnabled,

		envoySocket: opts.EnvoySocket,
	}, nil
}

// Run is a blocking command that:
// - creates a connection to:
//   - the local Envoy socket
//   - the connect proxy in the Global Controller
//
// - bridges the connections
func (t *Tunnel) Run() error {
	klog.Infof("Starting tunnel loop.")

	fillC := make(chan struct{})
	cleanupC := make(chan struct{})

	// Trigger an initial fill in the background.
	go func() { fillC <- struct{}{} }()

	for {
		select {
		case <-cleanupC:
			klog.V(2).Infof("Cleaning up connection.")

			t.m.Lock()
			t.poolSizeCur--
			t.m.Unlock()

			go func() {
				fillC <- struct{}{}
			}()
		case <-fillC:
			t.m.Lock()
			klog.Infof("Replenishing pool (current = %d, target = %d)", t.poolSizeCur, t.poolSizeDesired)
			desired := t.poolSizeDesired - t.poolSizeCur
			t.m.Unlock() // Release the lock early to unblock readers.

			for i := 0; i < desired; i++ {
				opt := bridgeOpt{}

				var err error

				opt.rwcLocalEnvoy, err = t.dialLocalEnvoy()
				if err != nil {
					return fmt.Errorf("connect to local Envoy: %s", err)
				}

				opt.rwcConnectProxy, err = t.dialConnectProxy()
				if err != nil {
					return fmt.Errorf("connect to session-manager-server: %s", err)
				}

				t.m.Lock()
				t.poolSizeCur++
				t.m.Unlock()

				// Bridge the connection in another goroutine.
				go func(opt bridgeOpt) {
					bridge(opt)
					cleanupC <- struct{}{}
				}(opt)
			}

			klog.Infof("Replenished pool (current: %d).", t.poolSizeCur)
		}
	}
}

func (t *Tunnel) dialLocalEnvoy() (io.ReadWriteCloser, error) {
	klog.Infof("Establishing Unix socket to local Envoy.")

	var localConn net.Conn

	start := time.Now()
	for {
		if time.Now().After(start.Add(t.dialTimeout)) {
			return nil, fmt.Errorf("timed out waiting for local Envoy to become ready")
		}

		klog.Infof("Dialing local Envoy (socket: %q)", t.envoySocket)
		d := net.Dialer{Timeout: t.dialTimeout}
		conn, err := d.Dial("unix", t.envoySocket)
		if err == nil {
			localConn = conn
			break
		}

		klog.Infof("Local Envoy is not ready. Waiting: %s", err)
		time.Sleep(dialSleepTime)
	}

	klog.Infof("Established Unix socket to local Envoy.")

	return localConn, nil
}

func (t *Tunnel) dialConnectProxy() (io.ReadWriteCloser, error) {
	klog.Infof("Establishing TCP connection to session-manager-server.")

	var tcpConn net.Conn

	start := time.Now()
	for {
		if time.Now().After(start.Add(t.dialTimeout)) {
			return nil, fmt.Errorf("timed out waiting for session-manager-server to become ready")
		}

		klog.Infof("Dialing session-manager-server (%q).", t.url.Host)

		var conn net.Conn
		var err error
		if t.tlsEnabled {
			conn, err = tls.Dial("tcp", t.url.Host, &tls.Config{})
		} else {
			d := net.Dialer{Timeout: t.dialTimeout}
			conn, err = d.Dial("tcp", t.url.Host)
		}

		if err == nil {
			tcpConn = conn
			break
		}
		klog.Infof("session-manager-server is not ready. Waiting: %s", err)
		time.Sleep(dialSleepTime)
	}

	klog.Infof("Established TCP connection to session-manager-server.")

	klog.Infof("Handshaking with session-manager-server (URL: %q).", t.url.String())

	// Perform the handshake with the tunnel.
	tr := http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return tcpConn, nil
		},
	}

	req, err := http.NewRequest(http.MethodConnect, t.url.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("create CONNECT request: %s", err)
	}

	auth.AppendWorkerAuthorizationToHeader(req)

	req.Header.Add(common.HeaderProto, common.ProtoV1)

	resp, err := tr.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("send CONNECT request: %s", err)
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, fmt.Errorf("response status code (%d) is not 101", resp.StatusCode)
	}

	// Obtain the io.ReadWriteCloser from the body.
	rwc, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		return nil, fmt.Errorf("cast response body as an io.ReadWriteCloser")
	}

	klog.Infof("Handshaked with session-manager-server.")

	return rwc, nil
}

// Status is the current status of the Tunnel.
type Status struct {
	URL         string `json:"url"`
	SizeDesired int    `json:"size_desired"`
	SizeCurrent int    `json:"size_current"`
}

// Status returns the current status of the Tunnel.
func (t *Tunnel) Status() Status {
	t.m.RLock()
	defer t.m.RUnlock()
	return Status{
		URL:         t.url.String(),
		SizeDesired: t.poolSizeDesired,
		SizeCurrent: t.poolSizeCur,
	}
}

// IsReady returns true if the channel is ready. If not,
// it returns a message describing why it is not ready.
func (t *Tunnel) IsReady() (bool, string) {
	t.m.RLock()
	defer t.m.RUnlock()
	if t.poolSizeDesired != t.poolSizeCur {
		return false, fmt.Sprintf("%d/%d connections are ready for %q",
			t.poolSizeCur, t.poolSizeDesired, t.url.String())
	}
	return true, ""
}

type bridgeOpt struct {
	rwcLocalEnvoy   io.ReadWriteCloser
	rwcConnectProxy io.ReadWriteCloser
}

// bridge bridges the connection with local Envoy and one with the session-manager-server.
func bridge(opt bridgeOpt) {
	klog.Infof("Bridging connections.")

	defer func() {
		if err := opt.rwcLocalEnvoy.Close(); err != nil {
			klog.Infof("Failed to close connection with the local Envoy: %s", err)
		}
	}()
	defer func() {
		if err := opt.rwcConnectProxy.Close(); err != nil {
			klog.Infof("Failed to close connection with the session-manager-server: %s", err)
		}
	}()

	errEnvoyToProxy := make(chan error, 1)
	go func() {
		_, err := io.Copy(opt.rwcConnectProxy, opt.rwcLocalEnvoy)
		errEnvoyToProxy <- err
	}()

	errProxyToEnvoy := make(chan error, 1)
	go func() {
		_, err := io.Copy(opt.rwcLocalEnvoy, opt.rwcConnectProxy)
		errProxyToEnvoy <- err
	}()

	// Wait for the first goroutine to complete.
	var err error
	select {
	case err = <-errProxyToEnvoy:
		// When WebSocket-tunnelled kubectl exec is used and "exit" is typed,
		// a pod terminates the connection, instead of a client. Then, the agent
		// receives "connection reset by peer". We want to just log as this
		// happens commonly.
		//
		// This behavior is specific to WebSocket-tunnelled one.
		//
		// TODO: Add readiness check to detect unhealthy Envoy which we want to
		// notice and fix.
		klog.Infof("session-manager-server to local Envoy copy finished: %v", err)
	case err = <-errEnvoyToProxy:
		klog.Infof("Local Envoy to session-manager-server copy finished: %v", err)
	}
}
