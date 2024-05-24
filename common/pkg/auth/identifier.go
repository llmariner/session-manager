package auth

import (
	"fmt"
	"net/http"
	"strings"

	"k8s.io/klog/v2"
)

// Identifier maps a request to an ID that can be used for routing.
type Identifier interface {
	Identify(r *http.Request) (string, error)
}

// NewHostBasedIdentifier creates a new HostBasedIdentifier.
func NewHostBasedIdentifier(port int) *HostBasedIdentifier {
	return &HostBasedIdentifier{port: port}
}

// HostBasedIdentifier uses the HTTP host to infer the ID for routing a request.
type HostBasedIdentifier struct {
	port int
}

// Identify implements Identifier.
//
// Returns the ID for routing the request.
func (i *HostBasedIdentifier) Identify(r *http.Request) (string, error) {
	klog.V(2).Infof("Identifying request (host: %q)", r.Host)

	// Use the subdomain as the identifier.
	parts := strings.Split(r.Host, ".")
	id := parts[0]

	klog.V(2).Infof("Identified ID for routing %q", id)
	// Add the port suffix to the host header, if it is not present.
	//
	// TODO(nick): this feels brittle. Is there a better way to do this?
	portStr := fmt.Sprintf(":%d", i.port)
	if !strings.HasSuffix(id, portStr) {
		id = id + portStr
	}
	return id, nil
}

// NewStaticIdentifier creates a new StaticIdentifier.
func NewStaticIdentifier(id string) *StaticIdentifier {
	return &StaticIdentifier{id: id}
}

// StaticIdentifier uses the fixed identifier for routing a request.
type StaticIdentifier struct {
	id string
}

// Identify implements Identifier.
func (i *StaticIdentifier) Identify(r *http.Request) (string, error) {
	return i.id, nil
}
