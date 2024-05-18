package auth

import (
	"net/http"
	"strings"

	"k8s.io/klog/v2"
)

// Identifier maps a request to an ID that can be used for routing.
type Identifier interface {
	Identify(r *http.Request) (string, error)
}

// HostBasedIdentifier uses the HTTP host to infer the ID for routing a request.
type HostBasedIdentifier struct{}

// Identify implements Identifier.
//
// Returns the ID for routing the request.
func (i *HostBasedIdentifier) Identify(r *http.Request) (string, error) {
	klog.V(2).Infof("Identifying request (host: %q)", r.Host)

	// Use the subdomain as the identifier.
	parts := strings.Split(r.Host, ".")
	id := parts[0]

	klog.V(2).Infof("Identified ID for routing %q", id)
	return id, nil
}
