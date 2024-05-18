package certlib

import (
	"context"
	"crypto/tls"
)

// Store is a cache of tls.Certificates.
type Store interface {

	// GetCertificateFunc returns a function that will return the appropriate
	// tls.Certificate based on the incoming tls.ClientHelloInfo.
	GetCertificateFunc() func(info *tls.ClientHelloInfo) (*tls.Certificate, error)

	// Run starts the Store.
	Run(ctx context.Context) error
}
