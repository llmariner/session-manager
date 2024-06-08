package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/llm-operator/rbac-manager/pkg/auth"
)

// Common errors.
var (
	ErrMissingAuthHeader          = fmt.Errorf("auth: missing Authorization header")
	ErrInvalidAuthorizationHeader = fmt.Errorf("auth: invalid Authorization header format")
	ErrUnauthorized               = fmt.Errorf("auth: unauthorized")
)

// Authenticator authenticates an inbound http.Request.
type Authenticator interface {
	// Authenticate authenticates the request. If the request is authenticated, it
	// returns a cluster ID and a path.
	Authenticate(r *http.Request) (string, string, error)
}

type reqIntercepter interface {
	InterceptHTTPRequest(req *http.Request) (int, auth.UserInfo, error)
}

// ExternalAuthenticator authenticates external requests with RBAC server.
type ExternalAuthenticator struct {
	intercepter reqIntercepter
}

// NewExternalAuthenticator returns a new ExternalAuthenticator.q
func NewExternalAuthenticator(ctx context.Context, addr string) (*ExternalAuthenticator, error) {
	i, err := auth.NewInterceptor(ctx, auth.Config{
		RBACServerAddr: addr,
		// TODO(kenji): Revisit.
		AccessResource: "api.fine_tuning.jobs",
	})
	if err != nil {
		return nil, err
	}
	return &ExternalAuthenticator{
		intercepter: i,
	}, nil
}

// Authenticate implements Authenticator by authenticating the request with the
func (a *ExternalAuthenticator) Authenticate(r *http.Request) (string, string, error) {
	_, userInfo, err := a.intercepter.InterceptHTTPRequest(r)
	if err != nil {
		return "", "", ErrUnauthorized
	}

	route, ok := extractRoute(r.URL.Path)
	if !ok {
		return "", "", ErrUnauthorized
	}

	var found bool
	for _, kenv := range userInfo.AssignedKubernetesEnvs {
		if kenv.ClusterID == route.clusterID && kenv.Namespace == route.namespace {
			found = true
			break
		}
	}

	if !found {
		return "", "", ErrUnauthorized
	}

	return route.clusterID, route.path, nil
}

type reqWorkerIntercepter interface {
	InterceptHTTPRequest(req *http.Request) (int, auth.ClusterInfo, error)
}

// WorkerAuthenticator authenticates external requests with RBAC server.
type WorkerAuthenticator struct {
	intercepter reqWorkerIntercepter
}

// NewWorkerAuthenticator returns a new WorkerAuthenticator.q
func NewWorkerAuthenticator(ctx context.Context, addr string) (*WorkerAuthenticator, error) {
	i, err := auth.NewWorkerInterceptor(ctx, auth.WorkerConfig{
		RBACServerAddr: addr,
	})
	if err != nil {
		return nil, err
	}
	return &WorkerAuthenticator{
		intercepter: i,
	}, nil
}

// Authenticate implements Authenticator by authenticating the request with the
func (a *WorkerAuthenticator) Authenticate(r *http.Request) (string, string, error) {
	_, clusterInfo, err := a.intercepter.InterceptHTTPRequest(r)
	if err != nil {
		return "", "", ErrUnauthorized
	}

	return clusterInfo.ClusterID, r.URL.Path, nil
}

type route struct {
	clusterID string
	namespace string
	path      string
}

func extractRoute(origPath string) (route, bool) {
	s := strings.Split(origPath, "/")
	if len(s) < 7 {
		return route{}, false
	}

	if !(s[0] == "" && s[1] == "v1" && s[2] == "sessions") {
		return route{}, false
	}

	return route{
		clusterID: s[3],
		namespace: s[7],
		path:      "/" + strings.Join(s[4:], "/"),
	}, true
}
