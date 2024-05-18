package certlib

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	"k8s.io/klog/v2"
)

const defaultReloadInterval = time.Hour

// ReloadingFileStoreOpts are options for a ReloadingFileStore.
type ReloadingFileStoreOpts struct {
	KeyPath        string
	CertPath       string
	ReloadInterval time.Duration
}

// ReloadingFileStore is a Store that will return the same tls.Certificate for
// all incoming TLS handshakes. The certificate is periodically regenerated
// by loading the key material from a well known path.
type ReloadingFileStore struct {
	keyPath  string
	certPath string
	t        <-chan time.Time
	m        sync.RWMutex
	cert     *tls.Certificate
}

// NewReloadingFileStore returns a pointer to a new ReloadingFileStore.
func NewReloadingFileStore(opts ReloadingFileStoreOpts) (*ReloadingFileStore, error) {
	d := defaultReloadInterval
	if opts.ReloadInterval > 0 {
		d = opts.ReloadInterval
	}

	s := &ReloadingFileStore{
		keyPath:  opts.KeyPath,
		certPath: opts.CertPath,
		t:        time.NewTicker(d).C,
	}
	if err := s.reload(); err != nil {
		return nil, fmt.Errorf("cert: new cert store: %s", err)
	}
	return s, nil
}

// GetCertificateFunc implements Store by returning a function that returns the
// currently cached value of the tls.Certificate.
func (s *ReloadingFileStore) GetCertificateFunc() func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return s.getCert(), nil
	}
}

// Run starts the Store, performing an initial load of the tls.Certificate
// before entering the reload loop.
func (s *ReloadingFileStore) Run(ctx context.Context) error {
	klog.Infof("starting store")

	// Perform an initial load.
	if err := s.reload(); err != nil {
		return err
	}

	// Enter the blocking refresh loop.
	for {
		select {
		case <-s.t:
			if err := s.reload(); err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// reload loads and parses the tls.Certificate from the well known paths, and
// updates the value of the certificate in the Store to point at this
// (potentially, new) value.
func (s *ReloadingFileStore) reload() error {
	klog.Infof("performing reload: cert = %s; key = %s", s.certPath, s.keyPath)

	cert, err := tls.LoadX509KeyPair(s.certPath, s.keyPath)
	if err != nil {
		return fmt.Errorf("reload: load keypair: %s", err)
	}

	s.m.Lock()
	s.cert = &cert
	s.m.Unlock()

	klog.Infof("reload complete")
	return nil
}

// getCert returns the pointer to the current tls.Certificate.
//
// This method should be used to fetch the certificate, rather than directly
// accessing, given multiple goroutines can attempt to mutate the current value.
func (s *ReloadingFileStore) getCert() *tls.Certificate {
	s.m.RLock()
	defer s.m.RUnlock()
	return s.cert
}
