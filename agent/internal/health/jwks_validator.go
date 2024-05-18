package health

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	checkInterval = 5 * time.Minute
)

// NewJWKSValidator returns a new JWKS validator.
func NewJWKSValidator(uri string) *JWKSValidator {
	return &JWKSValidator{
		uri: uri,
	}
}

// JWKSValidator validates JWKS.
type JWKSValidator struct {
	uri string

	lastReady           bool
	lastMessage         string
	lastUpdateTimestamp time.Time
}

// IsReady returns true if the server is ready. If not,
// it returns a message describing why it is not ready.
func (v *JWKSValidator) IsReady() (bool, string) {
	now := time.Now()
	if now.Sub(v.lastUpdateTimestamp) < checkInterval {
		return v.lastReady, v.lastMessage
	}

	if err := v.validateJWKS(); err != nil {
		v.lastReady = false
		v.lastMessage = fmt.Sprintf("jwks validation: %s", err)
	} else {
		v.lastReady = true
		v.lastMessage = ""
	}
	v.lastUpdateTimestamp = now

	return v.lastReady, v.lastMessage
}

func (v *JWKSValidator) validateJWKS() error {
	resp, err := http.Get(v.uri)
	if err != nil {
		return err
	}

	defer func() {
		_ = resp.Body.Close()
	}()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// TODO(kenji): Check the content. We currently focus on just fetching the
	// JWKS as it is the failure we have seen so far.
	if len(body) == 0 {
		return fmt.Errorf("empty body")
	}
	return nil
}
