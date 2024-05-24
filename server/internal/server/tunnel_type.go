package server

import (
	"net/http"
)

// tunnelType is the protocol of the tunnel.
type tunnelType int

const (
	tunnelTypeHTTP tunnelType = iota
	tunnelTypeUpgrade
)

// inferTunnelType returns the tunnelType to use when routing a request.
func inferTunnelType(req *http.Request) tunnelType {
	if req.Header.Get("upgrade") != "" {
		return tunnelTypeUpgrade
	}
	return tunnelTypeHTTP
}
