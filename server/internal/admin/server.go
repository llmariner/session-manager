package admin

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"

	"github.com/llm-operator/session-manager/common/pkg/common"
	"github.com/llm-operator/session-manager/server/internal/proxy"
	"k8s.io/klog/v2"
)

// Server is an HTTP server for serving administrative endpoints, accessible
// from within the hosting cluster only (i.e. not external).
type Server struct {
	addr string
	srv  *http.Server

	proxies []proxy.Proxy
}

// NewServer instantiates a new Server.
func NewServer(addr string, proxies []proxy.Proxy) *Server {
	s := &Server{
		addr:    addr,
		proxies: proxies,
	}

	m := http.NewServeMux()
	m.Handle(common.PathServerReady, http.HandlerFunc(s.handleReady))
	m.Handle(common.PathServerStatus, http.HandlerFunc(s.handleStatus))
	s.srv = &http.Server{Handler: m}

	return s
}

// Run is a blocking command that starts the HTTP server.
func (s *Server) Run() error {
	l, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("server: run: listen: %s", err)
	}

	klog.Infof("starting admin listener: addr=%q", s.addr)
	err = s.srv.Serve(l)
	if err != nil {
		return fmt.Errorf("server: run: serve: %s", err)
	}

	return nil
}

// handleReady always returns a 200 response.
func (s *Server) handleReady(w http.ResponseWriter, _ *http.Request) {
	klog.V(1).Infof("handling ready request")
	_, _ = w.Write([]byte("ok\n"))
}

// handleStatus returns the current status of the proxy.
func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	var statuses []proxy.Status
	for _, p := range s.proxies {
		statuses = append(statuses, p.Status())
	}

	status := struct {
		Status []proxy.Status `json:"status"`
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
