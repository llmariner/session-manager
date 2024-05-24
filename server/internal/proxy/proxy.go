package proxy

import (
	"net"
	"net/http"
)

// Proxy routes HTTP requests along one of many connections, corresponding to
// identifying information on the request.
type Proxy interface {
	// Add adds the net.Conn with the given identifier to the Proxy
	Add(id string, c net.Conn) error

	// Proxy routes the HTTP on the appropriate connection.
	Proxy(w http.ResponseWriter, r *http.Request)

	// Status returns the current status of the Proxy.
	Status() Status
}

// TunnelStatus is the current state of a tunnel to an agent.
type TunnelStatus struct {
	ID          string `json:"id"`
	TunnelCount int    `json:"tunnel_count"`
}

// Status is the current state of the proxy.
type Status struct {
	Type    string         `json:"type"`
	Tunnels []TunnelStatus `json:"tunnels"`
}
