package tunnel

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewReloadingTokenGenerator(t *testing.T) {
	d := t.TempDir()
	path := d + "/secret"
	secret := "something secret"
	err := os.WriteFile(path, []byte(secret), 0600)
	assert.NoError(t, err)

	tickC := make(chan time.Time)
	g := &ReloadingTokenGenerator{
		path:  path,
		tickC: tickC,
	}

	// Token initially starts empty.
	token, err := g.Generate()
	assert.NoError(t, err)
	assert.Empty(t, token)

	// Start the generator.
	ctx, cancel := context.WithCancel(context.Background())
	errC := make(chan error)
	go func() { errC <- g.Run(ctx) }()

	// Trigger a reload.
	tickC <- time.Now()

	// Token is populated with the original secret.
	assert.Eventually(t, func() bool {
		token, err := g.Generate()
		if err != nil {
			return false
		}
		return token == secret
	}, 10*time.Second, 100*time.Millisecond)

	// Replace the contents of the file.
	newSecret := "something new"
	err = os.WriteFile(path, []byte(newSecret), 0600)
	assert.NoError(t, err)

	// Token is not populated until the reload is triggered.
	assert.Never(t, func() bool {
		token, err := g.Generate()
		if err != nil {
			return true
		}
		return token == newSecret
	}, time.Second, 100*time.Millisecond)

	// Triggering a reload picks up the new secret.
	tickC <- time.Now()
	assert.Eventually(t, func() bool {
		token, err := g.Generate()
		if err != nil {
			return false
		}
		return token == newSecret
	}, 10*time.Second, 100*time.Millisecond)

	// Shutdown.
	cancel()
	err = <-errC
	assert.ErrorIs(t, context.Canceled, err)
}
