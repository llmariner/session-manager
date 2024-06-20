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
	route, ok := extractRoute(r.URL.Path)
	if !ok {
		return "", "", ErrUnauthorized
	}

	if route.isIngress {
		// TODO(kenji): Implement the authorization.
		return route.clusterID, route.path, nil
	}

	_, userInfo, err := a.intercepter.InterceptHTTPRequest(r)
	if err != nil {
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
	path      string

	isIngress bool
	namespace string
}

func extractRoute(origPath string) (route, bool) {
	if !strings.HasPrefix(origPath, "/v1/sessions/") {
		return route{}, false
	}

	s := strings.Split(origPath, "/")
	if len(s) < 7 {
		return route{}, false
	}
	clusterID := s[3]

	if s[4] == "v1" && s[5] == "services" {
		return route{
			clusterID: clusterID,
			isIngress: true,
			// It is natural to truncate "/v1/sessions/<cluster ID>" when
			// forwarding the request, but we're not doing that here since
			// it does not work well with Jupyter Notebook.
			path: origPath,
		}, true
	}

	var namespace string
	switch s[4] {
	case "api":
		namespace = s[7]
	case "apis":
		if len(s) < 8 {
			return route{}, false
		}
		namespace = s[8]
	default:
		return route{}, false
	}
	return route{
		clusterID: clusterID,
		namespace: namespace,
		path:      "/" + strings.Join(s[4:], "/"),
	}, true
}
