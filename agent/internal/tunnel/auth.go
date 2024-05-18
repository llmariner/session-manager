package tunnel

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"k8s.io/klog/v2"
)

// TokenGenerator is used to generate an authentication token to use when
// establishing a tunnel with the proxy.
type TokenGenerator interface {

	// Generate returns an authentication token.
	Generate() (string, error)
}

// ReloadingTokenGenerator is a TokenGenerator that periodically reloads the
// contents of a file to return as the token.
type ReloadingTokenGenerator struct {
	path string

	m     sync.RWMutex
	tickC <-chan time.Time
	token string
}

// NewReloadingTokenGenerator returns a new ReloadingTokenGenerator.
func NewReloadingTokenGenerator(path string, interval time.Duration) *ReloadingTokenGenerator {
	return &ReloadingTokenGenerator{
		path:  path,
		tickC: time.NewTicker(interval).C,
	}
}

// Run starts the ReloadingTokenGenerator.
//
// This is a blocking function.
func (g *ReloadingTokenGenerator) Run(ctx context.Context) error {
	// Perform an initial token load.
	if err := g.reload(); err != nil {
		return err
	}

	for {
		select {
		case <-g.tickC:
			if err := g.reload(); err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// reload reloads the token from the file.
func (g *ReloadingTokenGenerator) reload() error {
	klog.Infof("reloading token from file: %s", g.path)
	b, err := os.ReadFile(g.path)
	if err != nil {
		return fmt.Errorf("auth: reload token: %s", err)
	}
	g.m.Lock()
	defer g.m.Unlock()
	g.token = string(b)
	return nil
}

// Generate returns the currently loaded token.
func (g *ReloadingTokenGenerator) Generate() (string, error) {
	g.m.RLock()
	defer g.m.RUnlock()
	return g.token, nil
}
