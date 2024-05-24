package auth

import (
	"fmt"
	"net/http"
	"regexp"

	"github.com/llm-operator/session-manager/common/pkg/jwt"
)

// Common errors.
var (
	ErrMissingAuthHeader          = fmt.Errorf("auth: missing Authorization header")
	ErrInvalidAuthorizationHeader = fmt.Errorf("auth: invalid Authorization header format")
	ErrUnauthorized               = fmt.Errorf("auth: unauthorized")
)

var authRegex = regexp.MustCompile(`(?i)^bearer\s(.*)$`)

// Authenticator authenticates an inbound http.Request.
type Authenticator interface {
	Authenticate(r *http.Request) error
}

// NoOpAuthenticator always authenticates a request.
type NoOpAuthenticator struct{}

// Authenticate implements Authenticator by always authenticating the request.
func (a *NoOpAuthenticator) Authenticate(_ *http.Request) error {
	return nil
}

// JWTAuthenticator authenticates requests by validating a JWT on the request.
type JWTAuthenticator struct {
	v jwt.Validator
}

// NewJWTAuthenticator returns a new JWTAuthenticator.
func NewJWTAuthenticator(v jwt.Validator) *JWTAuthenticator {
	return &JWTAuthenticator{v: v}
}

// Authenticate implements Authenticator by validating the JWT present on a
// request in the Authorization header.
func (a *JWTAuthenticator) Authenticate(r *http.Request) error {
	// TODO(kenji): Add this back later.
	/*
		klog.V(2).Infof("Authenticating request: %s", r.URL)

		auth := r.Header.Get("Authorization")
		if auth == "" {
			return ErrMissingAuthHeader
		}

		matches := authRegex.FindStringSubmatch(auth)
		if len(matches) != 2 {
			return ErrInvalidAuthorizationHeader
		}

		_, err := a.v.Validate(matches[1])
		if err != nil {
			return ErrUnauthorized
		}
	*/
	return nil
}

// CompositeAuthenticator is an Authenticator that wraps a number of inner
// authenticators that processes the incoming request sequentially.
type CompositeAuthenticator struct {
	as []Authenticator
}

// NewCompositeAuthenticator returns a new CompositeAuthenticator.
func NewCompositeAuthenticator(as ...Authenticator) *CompositeAuthenticator {
	return &CompositeAuthenticator{as: as}
}

// Authenticate implements Authenticator by iterating through each of the
// inner authenticators, in sequence, returning the first error encountered, or
// nil if no authentication error was encountered.
func (a *CompositeAuthenticator) Authenticate(r *http.Request) error {
	for i, a := range a.as {
		if err := a.Authenticate(r); err != nil {
			return fmt.Errorf("composite auth (authenticator: %d): %w", i, err)
		}
	}
	return nil
}
