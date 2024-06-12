package auth

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/llm-operator/rbac-manager/pkg/auth"
	"github.com/stretchr/testify/assert"
)

func TestExternalAuthenticatorTest(t *testing.T) {
	tcs := []struct {
		name          string
		req           *http.Request
		userInfo      auth.UserInfo
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
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			i := &fakeRequsetIntercepter{
				userInfo: tc.userInfo,
			}
			a := ExternalAuthenticator{i}
			gotClusterID, gotPth, err := a.Authenticate(tc.req)
			if err != nil {
				assert.ErrorIs(t, tc.wantErr, err)
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
