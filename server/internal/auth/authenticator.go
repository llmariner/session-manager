package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	rbacv1 "github.com/llmariner/rbac-manager/api/v1"
	"github.com/llmariner/rbac-manager/pkg/auth"
	"github.com/llmariner/session-manager/common/pkg/common"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"k8s.io/klog/v2"
)

const (
	cookieNameRedirect = "LLMOperatorRedirect"
	cookieNameToken    = "LLMOperatorToken"
)

// Common errors.
var (
	ErrMissingAuthHeader          = fmt.Errorf("auth: missing Authorization header")
	ErrInvalidAuthorizationHeader = fmt.Errorf("auth: invalid Authorization header format")
	ErrUnauthorized               = fmt.Errorf("auth: unauthorized")
	ErrLoginRequired              = fmt.Errorf("auth: login required")
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

// NoopAuthenticator does not authenticate requests.
type NoopAuthenticator struct{}

// Authenticate implements Authenticator by returning an empty string.
func (a *NoopAuthenticator) Authenticate(r *http.Request) (string, string, error) {
	route, ok := extractRoute(r.URL.Path)
	if !ok {
		return "default", r.URL.Path, nil
	}
	return route.clusterID, route.path, nil
}

// ExternalAuthenticator authenticates external requests with RBAC server.
type ExternalAuthenticator struct {
	intercepter    reqIntercepter
	rbacClient     rbacv1.RbacInternalServiceClient
	tokenExchanger TokenExchanger
	loginCache     *cache
	enableSlurm    bool

	gpuOperatorNamespace string

	// loginState is set only when using Okta for authentication.
	loginState string
}

// NewExternalAuthenticator returns a new ExternalAuthenticator.
func NewExternalAuthenticator(
	ctx context.Context,
	rbacServerAddr string,
	tex TokenExchanger,
	cacheExpiration, cacheCleanup time.Duration,
	enableSlurm bool,
	gpuOperatorNamespace string,
	loginState string,
) (*ExternalAuthenticator, error) {
	i, err := auth.NewInterceptor(ctx, auth.Config{
		RBACServerAddr: rbacServerAddr,
		// TODO(kenji): Revisit.
		GetAccessResourceForHTTPRequest: func(method string, url url.URL) string {
			part := strings.Split(url.Path, "/")
			if n := len(part); n <= 7 && (part[4] == "api" || part[4] == "apis") {
				return "api.k8s.clusterscope"
			}
			return "api.fine_tuning.jobs"
		},
	})
	if err != nil {
		return nil, err
	}

	conn, err := grpc.NewClient(rbacServerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}

	return &ExternalAuthenticator{
		intercepter:    i,
		rbacClient:     rbacv1.NewRbacInternalServiceClient(conn),
		tokenExchanger: tex,
		loginCache:     newCacheWithCleaner(ctx, cacheExpiration, cacheCleanup),
		enableSlurm:    enableSlurm,

		gpuOperatorNamespace: gpuOperatorNamespace,

		loginState: loginState,
	}, nil
}

// HandleLogin handles the login request.
func (a *ExternalAuthenticator) HandleLogin(w http.ResponseWriter, r *http.Request) {
	cookie := &http.Cookie{
		Name:     cookieNameRedirect,
		Value:    r.URL.String(),
		Path:     common.PathLoginCallback,
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)
	http.Redirect(w, r, a.tokenExchanger.getLoginURL(), http.StatusFound)
}

// HandleLoginCallback handles the login callback.
func (a *ExternalAuthenticator) HandleLoginCallback(w http.ResponseWriter, r *http.Request) {
	if a.loginState != "" {
		state := r.FormValue("state")
		if state != a.loginState {
			http.Error(w, fmt.Sprintf("invalid oauth state: %s", r.FormValue("state")), http.StatusBadRequest)
			return
		}
	}
	if r.Method != http.MethodGet {
		http.Error(w, fmt.Sprintf("method not implemented: %s", r.Method), http.StatusNotImplemented)
		return
	}

	if errMsg := r.FormValue("error"); errMsg != "" {
		http.Error(w, fmt.Sprintf("%s: %s", errMsg, r.FormValue("error_description")), http.StatusBadRequest)
		return
	}
	code := r.FormValue("code")
	if code == "" {
		http.Error(w, fmt.Sprintf("no code in request: %q", r.Form), http.StatusBadRequest)
		return
	}

	token, err := a.tokenExchanger.obtainToken(r.Context(), code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	c, err := r.Cookie(cookieNameRedirect)
	if err != nil {
		http.Error(w, "failed to get a cookie", http.StatusBadRequest)
		return
	}
	redirectURL := c.Value

	// TODO(aya): revisit cookie settings.
	cookie := &http.Cookie{
		Name:     cookieNameToken,
		Value:    token,
		Path:     "/v1/sessions",
		MaxAge:   86400,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// Authenticate implements Authenticator by authenticating the request with the
func (a *ExternalAuthenticator) Authenticate(r *http.Request) (string, string, error) {
	route, ok := extractRoute(r.URL.Path)
	if !ok {
		return "", "", ErrUnauthorized
	}

	switch {
	case route.ingressRoute != nil:
		if err := a.authenticateService(r, route); err != nil {
			return "", "", err
		}
		return route.clusterID, route.path, nil

	case route.apiServerRoute != nil:
		_, userInfo, err := a.intercepter.InterceptHTTPRequest(r)
		if err != nil {
			return "", "", ErrUnauthorized
		}

		var found bool
		for _, kenv := range userInfo.AssignedKubernetesEnvs {
			if kenv.ClusterID == route.clusterID &&
				(route.apiServerRoute.clusterScope ||
					kenv.Namespace == route.apiServerRoute.namespace) {
				found = true
				break
			}
		}

		if !found {
			if route.apiServerRoute.namespace != a.gpuOperatorNamespace {
				return "", "", ErrUnauthorized
			}

			// If the namespace is for GPU operator, allow the access to the namespace if
			// the user can access "api.clusters".
			token, ok := extractTokenFromAuthHeader(r.Header)
			if !ok {
				return "", "", ErrUnauthorized
			}
			if !a.authorizeResourceAccess(r.Context(), token, "api.clusters", "write") {
				return "", "", ErrUnauthorized
			}
		}

		return route.clusterID, route.path, nil

	case route.slurmRoute != nil && a.enableSlurm:
		_, userInfo, err := a.intercepter.InterceptHTTPRequest(r)
		if err != nil {
			return "", "", ErrUnauthorized
		}

		// Just check the cluster assignment and do not check the namespace.
		var found bool
		for _, kenv := range userInfo.AssignedKubernetesEnvs {
			if kenv.ClusterID == route.clusterID {
				found = true
				break
			}
		}

		if !found {
			return "", "", ErrUnauthorized
		}

		return route.clusterID, route.path, nil

	default:
		return "", "", fmt.Errorf("auth: unexpected route: %+v", route)
	}
}

func (a *ExternalAuthenticator) authenticateService(r *http.Request, route route) error {
	cookie, err := r.Cookie(cookieNameToken)
	if cookie == nil || cookie.Value == "" {
		klog.V(2).Infof("failed to get a cookie: %s", err)
		return ErrLoginRequired
	}
	token := cookie.Value

	v, ok := a.loginCache.get(token)
	if ok && v == route.ingressRoute.service {
		// NOTE: we should check if token is still valid, but we're not doing that here.
		// Cache expiration should set short enough to take care of this.
		return nil
	}

	// TODO(aya): revisit
	if !a.authorizeResourceAccess(r.Context(), token, "api.workspaces.notebooks", "read") {
		return ErrLoginRequired
	}

	a.loginCache.set(token, route.ingressRoute.service)
	return nil
}

func (a *ExternalAuthenticator) authorizeResourceAccess(
	ctx context.Context,
	token,
	accessResource,
	capability string,
) bool {
	resp, err := a.rbacClient.Authorize(ctx, &rbacv1.AuthorizeRequest{
		Token:          token,
		AccessResource: accessResource,
		Capability:     capability,
	})
	if err != nil || !resp.Authorized {
		klog.V(2).Infof("failed to authorize token: %s (%+v)", err, resp)
		return false
	}
	return true
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

type ingressRoute struct {
	service string
}

type apiServerRoute struct {
	namespace    string
	clusterScope bool
}

type slurmRoute struct {
}

type route struct {
	clusterID string
	path      string

	ingressRoute   *ingressRoute
	apiServerRoute *apiServerRoute
	slurmRoute     *slurmRoute
}

func extractRoute(origPath string) (route, bool) {
	if !strings.HasPrefix(origPath, "/v1/sessions/") {
		return route{}, false
	}

	s := strings.Split(origPath, "/")
	if len(s) < 5 {
		return route{}, false
	}
	clusterID := s[3]

	if s[4] == "v1" && s[5] == "services" {
		return route{
			clusterID: clusterID,
			ingressRoute: &ingressRoute{
				// e.g., notebooks/<notebook ID>
				service: fmt.Sprintf("%s/%s", s[6], s[7]),
			},
			// It is natural to truncate "/v1/sessions/<cluster ID>" when
			// forwarding the request, but we're not doing that here since
			// it does not work well with Jupyter Notebook.
			path: origPath,
		}, true
	}

	var namespace string
	switch s[4] {
	case "api":
		if len(s) > 7 {
			namespace = s[7]
		}
	case "apis":
		if len(s) > 8 {
			namespace = s[8]
		}
	case "slurm":
		return route{
			clusterID:  clusterID,
			slurmRoute: &slurmRoute{},
			path:       "/" + strings.Join(s[4:], "/"),
		}, true
	default:
		return route{}, false
	}

	route := route{
		clusterID:      clusterID,
		apiServerRoute: &apiServerRoute{},
		path:           "/" + strings.Join(s[4:], "/"),
	}
	if namespace != "" {
		route.apiServerRoute.namespace = namespace
	} else {
		route.apiServerRoute.clusterScope = true
	}
	return route, true
}

func extractTokenFromAuthHeader(header http.Header) (string, bool) {
	auth := header.Get("Authorization")
	if len(auth) < 1 {
		return "", false
	}
	return strings.TrimPrefix(auth, "Bearer "), true
}
