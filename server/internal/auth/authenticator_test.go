package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	rbacv1 "github.com/llm-operator/rbac-manager/api/v1"
	"github.com/llm-operator/rbac-manager/pkg/auth"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
)

func TestExternalAuthenticatorTest(t *testing.T) {
	tcs := []struct {
		name          string
		req           *http.Request
		userInfo      auth.UserInfo
		failAuthToken bool
		wantClusterID string
		wantPath      string
		wantErr       error
	}{
		{
			name: "auth passes",
			req: &http.Request{
				URL: &url.URL{
					Path: "/v1/sessions/my-cluster/api/v1/namespaces/my-namespace/pods/",
				},
			},
			userInfo: auth.UserInfo{
				AssignedKubernetesEnvs: []auth.AssignedKubernetesEnv{
					{
						ClusterID: "my-cluster",
						Namespace: "my-namespace",
					},
				},
			},
			wantClusterID: "my-cluster",
			wantPath:      "/api/v1/namespaces/my-namespace/pods/",
			wantErr:       nil,
		},
		{
			name: "different cluster",
			req: &http.Request{
				URL: &url.URL{
					Path: "/v1/sessions/different-cluster/api/v1/namespaces/my-namespace/pods/",
				},
			},
			userInfo: auth.UserInfo{
				AssignedKubernetesEnvs: []auth.AssignedKubernetesEnv{
					{
						ClusterID: "my-cluster",
						Namespace: "my-namespace",
					},
				},
			},
			wantErr: ErrUnauthorized,
		},
		{
			name: "different namespace",
			req: &http.Request{
				URL: &url.URL{
					Path: "/v1/sessions/my-cluster/api/v1/namespaces/different-namespace/pods/",
				},
			},
			userInfo: auth.UserInfo{
				AssignedKubernetesEnvs: []auth.AssignedKubernetesEnv{
					{
						ClusterID: "my-cluster",
						Namespace: "my-namespace",
					},
				},
			},
			wantErr: ErrUnauthorized,
		},
		{
			name: "invalid path",
			req: &http.Request{
				URL: &url.URL{
					Path: "invalid-path",
				},
			},
			userInfo: auth.UserInfo{
				AssignedKubernetesEnvs: []auth.AssignedKubernetesEnv{
					{
						ClusterID: "my-cluster",
						Namespace: "my-namespace",
					},
				},
			},
			wantErr: ErrUnauthorized,
		},
		{
			name: "invalid path",
			req: &http.Request{
				URL: &url.URL{
					Path: "/v1/sessions/my-cluster/apiserver/api/v1/namespaces/",
				},
			},
			userInfo: auth.UserInfo{
				AssignedKubernetesEnvs: []auth.AssignedKubernetesEnv{
					{
						ClusterID: "my-cluster",
						Namespace: "my-namespace",
					},
				},
			},
			wantErr: ErrUnauthorized,
		},
		{
			name: "non-core API path",
			req: &http.Request{
				URL: &url.URL{
					Path: "/v1/sessions/my-cluster/apis/batch/v1/namespaces/my-namespace/jobs/",
				},
			},
			userInfo: auth.UserInfo{
				AssignedKubernetesEnvs: []auth.AssignedKubernetesEnv{
					{
						ClusterID: "my-cluster",
						Namespace: "my-namespace",
					},
				},
			},
			wantClusterID: "my-cluster",
			wantPath:      "/apis/batch/v1/namespaces/my-namespace/jobs/",
		},
		{
			name: "ingress path without token",
			req: &http.Request{
				URL: &url.URL{
					Path: "/v1/sessions/my-cluster/v1/services/notebooks/nid",
				},
			},
			userInfo: auth.UserInfo{
				AssignedKubernetesEnvs: []auth.AssignedKubernetesEnv{
					{
						ClusterID: "my-cluster",
						Namespace: "my-namespace",
					},
				},
			},
			wantErr: ErrLoginRequired,
		},
		{
			name: "ingress path invalid token",
			req: &http.Request{
				URL: &url.URL{
					Path: "/v1/sessions/my-cluster/v1/services/notebooks/nid",
				},
				Header: http.Header{
					"Cookie": []string{fmt.Sprintf("%s=%s", cookieNameToken, "token")},
				},
			},
			failAuthToken: true,
			userInfo: auth.UserInfo{
				AssignedKubernetesEnvs: []auth.AssignedKubernetesEnv{
					{
						ClusterID: "my-cluster",
						Namespace: "my-namespace",
					},
				},
			},
			wantErr: ErrLoginRequired,
		},
		{
			name: "ingress path",
			req: &http.Request{
				URL: &url.URL{
					Path: "/v1/sessions/my-cluster/v1/services/notebooks/nid",
				},
				Header: http.Header{
					"Cookie": []string{fmt.Sprintf("%s=%s", cookieNameToken, "token")},
				},
			},
			userInfo: auth.UserInfo{
				AssignedKubernetesEnvs: []auth.AssignedKubernetesEnv{
					{
						ClusterID: "my-cluster",
						Namespace: "my-namespace",
					},
				},
			},
			wantClusterID: "my-cluster",
			wantPath:      "/v1/sessions/my-cluster/v1/services/notebooks/nid",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			i := &fakeRequsetIntercepter{
				userInfo: tc.userInfo,
			}
			a := ExternalAuthenticator{
				intercepter: i,
				rbacClient:  &fakeRBACClient{!tc.failAuthToken},
				loginCache:  &cache{},
			}
			gotClusterID, gotPth, err := a.Authenticate(tc.req)
			if err != nil {
				assert.ErrorIs(t, err, tc.wantErr)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.wantPath, gotPth)
			assert.Equal(t, tc.wantClusterID, gotClusterID)
		})
	}
}

func TestExtractRoute(t *testing.T) {
	tcs := []struct {
		path   string
		want   route
		wantOK bool
	}{
		{
			path: "/v1/sessions/my-cluster/api/v1/namespaces/my-namespace/pods",
			want: route{
				clusterID: "my-cluster",
				namespace: "my-namespace",
				path:      "/api/v1/namespaces/my-namespace/pods",
			},
			wantOK: true,
		},
		{
			path:   "/v1/clusters",
			wantOK: false,
		},
		{
			path:   "/v1/a/b/c/d/e/f/g",
			wantOK: false,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.path, func(t *testing.T) {
			r, ok := extractRoute(tc.path)
			assert.Equal(t, tc.wantOK, ok)
			if tc.wantOK {
				assert.Equal(t, tc.want, r)
			}
		})
	}
}

type fakeRequsetIntercepter struct {
	userInfo auth.UserInfo
}

func (f *fakeRequsetIntercepter) InterceptHTTPRequest(req *http.Request) (int, auth.UserInfo, error) {
	return http.StatusOK, f.userInfo, nil
}

type fakeRBACClient struct {
	aurhorize bool
}

func (f *fakeRBACClient) Authorize(ctx context.Context, in *rbacv1.AuthorizeRequest, opts ...grpc.CallOption) (*rbacv1.AuthorizeResponse, error) {
	return &rbacv1.AuthorizeResponse{Authorized: f.aurhorize}, nil
}

func (f *fakeRBACClient) AuthorizeWorker(ctx context.Context, in *rbacv1.AuthorizeWorkerRequest, opts ...grpc.CallOption) (*rbacv1.AuthorizeWorkerResponse, error) {
	return &rbacv1.AuthorizeWorkerResponse{Authorized: f.aurhorize}, nil
}
