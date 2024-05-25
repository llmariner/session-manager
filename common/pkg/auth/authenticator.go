package auth

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/llm-operator/rbac-manager/pkg/auth"
	"github.com/llm-operator/session-manager/common/pkg/jwt"
	"k8s.io/klog/v2"
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
	return nil
}

type reqIntercepter interface {
	InterceptHTTPRequest(req *http.Request) (int, auth.UserInfo, error)
}

// RBACServerAuthenticator authenticates requests with RBAC server.
type RBACServerAuthenticator struct {
	intercepter reqIntercepter
}

// NewRBACServerAuthenticator returns a new RBACServerAuthenticator.q
func NewRBACServerAuthenticator(ctx context.Context, addr string) (*RBACServerAuthenticator, error) {
	i, err := auth.NewInterceptor(ctx, auth.Config{
		RBACServerAddr: addr,
		// TODO(kenji): Revisit.
		AccessResource: "api.fine_tuning.jobs",
	})
	if err != nil {
		return nil, err
	}
	return &RBACServerAuthenticator{
		intercepter: i,
	}, nil
}

// Authenticate implements Authenticator by authenticating the request with the
func (a *RBACServerAuthenticator) Authenticate(r *http.Request) error {
	_, userInfo, err := a.intercepter.InterceptHTTPRequest(r)
	if err != nil {
		return ErrUnauthorized
	}

	if !strings.HasPrefix(r.URL.Path, "/api/v1/namespaces/") {
		// Unexpected path.
		return ErrUnauthorized
	}
	s := strings.Split(r.URL.Path, "/")
	if len(s) < 5 {
		return ErrUnauthorized
	}
	namespace := s[4]
	if userInfo.KubernetesNamespace != namespace {
		return ErrUnauthorized
	}

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
