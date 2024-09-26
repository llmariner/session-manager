package admin

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/llmariner/session-manager/agent/internal/tunnel"
	"github.com/llmariner/session-manager/common/pkg/common"
	"k8s.io/klog/v2"
)

// Server is an HTTP server that handles administrative tasks for the
// agent, such as the authentication handshake performed between the proxy and
// the agent, and serving a "Hello, world" message.
type Server struct {
	socketPath string

	s       *http.Server
	tunnels []*tunnel.Tunnel
}

// NewServer creates a new Server with the given ID, binding a listening
// socket at the given path.
func NewServer(socketPath string, tunnels []*tunnel.Tunnel) *Server {
	s := &Server{
		socketPath: socketPath,
		tunnels:    tunnels,
	}

	m := http.NewServeMux()
	m.Handle(common.PathAgentStatus, http.HandlerFunc(s.handleStatus))
	s.s = &http.Server{
		Handler: m,
	}

	return s
}

// Run is a blocking command that starts the Server.
func (s *Server) Run() error {
	// Create a domain socket listener to bind the server to.
	_ = os.Remove(s.socketPath)
	l, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return err
	}

	// Allow other processes to access the socket - the Envoy process runs as
	// the "envoy" user in the container.
	if err := os.Chmod(s.socketPath, 0666); err != nil {
		return err
	}

	klog.Infof("starting admin listener; path=%q", s.socketPath)
	return s.s.Serve(l)
}

// handleStatus returns the current tunnel status.
func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	var statuses []tunnel.Status
	for _, t := range s.tunnels {
		statuses = append(statuses, t.Status())
	}

	status := struct {
		Status []tunnel.Status `json:"status"`
	}{
		Status: statuses,
	}

	b, err := json.Marshal(&status)
	if err != nil {
		klog.Errorf("could not write status: %s", err)
		http.Error(w, "could not write status", http.StatusInternalServerError)
		return
	}

	_, err = w.Write(b)
	if err != nil {
		klog.Errorf("could not write status: %s", err)
		http.Error(w, "could not write status", http.StatusInternalServerError)
		return
	}
}

// IsReady returns true if the server is ready. If not,
// it returns a message describing why it is not ready.
func (s *Server) IsReady() (bool, string) {
	var msgs []string
	for _, t := range s.tunnels {
		if r, msg := t.IsReady(); !r {
			msgs = append(msgs, msg)
		}
	}

	if len(msgs) > 0 {
		return false, strings.Join(msgs, ",")
	}

	return true, ""
}
