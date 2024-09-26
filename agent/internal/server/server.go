package server

import (
	"github.com/llmariner/session-manager/agent/internal/admin"
	"github.com/llmariner/session-manager/agent/internal/tunnel"
	"k8s.io/klog/v2"
)

// Opts are the options for the Server.
type Opts struct {
	Admin         *admin.Server
	TunnelHTTP    *tunnel.Tunnel
	TunnelUpgrade *tunnel.Tunnel
}

// Server encapsulates both the adminServer and the proxy that comprise the
// agent.
type Server struct {
	admin         *admin.Server
	tunnelHTTP    *tunnel.Tunnel
	tunnelUpgrade *tunnel.Tunnel
}

// NewServer instantiates a new server from the given adminServer and proxy.
func NewServer(opts Opts) *Server {
	return &Server{
		admin:         opts.Admin,
		tunnelHTTP:    opts.TunnelHTTP,
		tunnelUpgrade: opts.TunnelUpgrade,
	}
}

// Run is a blocking command that starts the Server.
func (s *Server) Run() error {
	doneC := make(chan error)

	go func() {
		klog.Infof("Starting admin server")
		doneC <- s.admin.Run()
	}()

	go func() {
		klog.Infof("Starting HTTP proxy")
		doneC <- s.tunnelHTTP.Run()
	}()

	go func() {
		klog.Infof("Starting HTTP upgrade proxy")
		doneC <- s.tunnelUpgrade.Run()
	}()

	return <-doneC
}
