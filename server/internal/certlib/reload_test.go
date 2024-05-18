package certlib

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	keyFile  = "key.pem"
	certFile = "crt.pem"
)

func TestNewReloadingFileStore(t *testing.T) {
	cn1, cn2 := "example1.com", "example2.com"
	dir := t.TempDir()

	// Generate a certificate.
	if err := genCertPair(dir, cn1); err != nil {
		t.Fatal(err)
	}

	// Initialize a cert store with the new cert.
	tickC := make(chan time.Time)
	store := &ReloadingFileStore{
		keyPath:  dir + "/" + keyFile,
		certPath: dir + "/" + certFile,
		t:        tickC,
	}

	// The cert store initially has no certificate loaded.
	assert.Nil(t, store.getCert())

	// Start the store.
	ctx, cancel := context.WithCancel(context.Background())
	errC := make(chan error)
	go func() {
		errC <- store.Run(ctx)
	}()

	// Trigger a reload.
	tickC <- time.Now()

	// The store now has a cert loaded.
	assertCNEventually(t, cn1, store, 5*time.Second)

	// Generate a new cert.
	if err := genCertPair(dir, cn2); err != nil {
		t.Fatal(err)
	}

	// Trigger a reload.
	tickC <- time.Now()

	// The new cert is different to the first.
	assertCNEventually(t, cn2, store, 5*time.Second)

	cancel()
	assert.Equal(t, context.Canceled, <-errC)
}

// genCertPair generates and writes out a new TLS key and certificate to the
// given directory.
func genCertPair(dir, cn string) error {
	key, cert, err := newCertPair(cn)
	if err != nil {
		return err
	}

	if err := os.WriteFile(dir+"/"+keyFile, key, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(dir+"/"+certFile, cert, 0644); err != nil {
		return err
	}

	return nil
}

// newCertPair constructs a new RSA key and TLS certificate and return the
// bytes in PEM-encoded format.
func newCertPair(cn string) ([]byte, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Minute)

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}

	keyBytes = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	})

	certBytes = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	return keyBytes, certBytes, nil
}

// assertCNEventually asserts that the CN on the TLS certificate currently
// loaded in to the store is equal to the expected value within the given
// duration.
func assertCNEventually(t *testing.T, expected string, s *ReloadingFileStore, duration time.Duration) {
	assert.Eventually(t, func() bool {
		c, err := x509.ParseCertificate(s.getCert().Certificate[0])
		assert.NoError(t, err)
		return expected == c.Subject.CommonName
	}, duration, time.Second)
}
