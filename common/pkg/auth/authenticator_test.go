package auth

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/golang-jwt/jwt"
	"github.com/llm-operator/rbac-manager/pkg/auth"
	ijwt "github.com/llm-operator/session-manager/common/pkg/jwt"
	"github.com/stretchr/testify/assert"
)

func TestNoOpAuthenticator(t *testing.T) {
	a := NoOpAuthenticator{}
	err := a.Authenticate(&http.Request{})
	assert.NoError(t, err)
}

func TestJWTAuthenticator(t *testing.T) {
	tcs := []struct {
		name string
		req  *http.Request
		v    ijwt.Validator
		err  error
	}{
		{
			name: "missing header",
			req:  &http.Request{},
			v:    &testJWTValidator{valid: true},
			err:  ErrMissingAuthHeader,
		},
		{
			name: "invalid header",
			req: &http.Request{
				Header: header("Authorization", "invalid format"),
			},
			v:   &testJWTValidator{valid: true},
			err: ErrInvalidAuthorizationHeader,
		},
		{
			name: "auth fails",
			req: &http.Request{
				Header: header("Authorization", "Bearer something-secret"),
			},
			v:   &testJWTValidator{valid: false},
			err: ErrUnauthorized,
		},
		{
			name: "auth passes",
			req: &http.Request{
				Header: header("Authorization", "Bearer something-secret"),
			},
			v:   &testJWTValidator{valid: true},
			err: nil,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			a := JWTAuthenticator{v: tc.v}
			err := a.Authenticate(tc.req)
			if err != nil {
				assert.ErrorIs(t, tc.err, err)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestRBACServerAuthenticatorTest(t *testing.T) {
	tcs := []struct {
		name     string
		req      *http.Request
		userInfo auth.UserInfo
		wantErr  error
	}{
		{
			name: "auth passes",
			req: &http.Request{
				URL: &url.URL{
					Path: "/api/v1/namespaces/my-namespace/pods/",
				},
			},
			userInfo: auth.UserInfo{
				KubernetesNamespace: "my-namespace",
			},
			wantErr: nil,
		},
		{
			name: "different namespace",
			req: &http.Request{
				URL: &url.URL{
					Path: "/api/v1/namespaces/different-namespace/pods/",
				},
			},
			userInfo: auth.UserInfo{
				KubernetesNamespace: "my-namespace",
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
				KubernetesNamespace: "my-namespace",
			},
			wantErr: ErrUnauthorized,
		},
		{
			name: "invalid path",
			req: &http.Request{
				URL: &url.URL{
					Path: "/api/v1/namespaces/",
				},
			},
			userInfo: auth.UserInfo{
				KubernetesNamespace: "my-namespace",
			},
			wantErr: ErrUnauthorized,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			i := &fakeRequsetIntercepter{
				userInfo: tc.userInfo,
			}
			a := RBACServerAuthenticator{i}
			err := a.Authenticate(tc.req)
			if err != nil {
				assert.ErrorIs(t, tc.wantErr, err)
				return
			}
			assert.NoError(t, err)
		})
	}
}

// failingAuthenticator is an Authenticator that returns an error when
// encountering a request with a header that matches a key and value.
type failingAuthenticator struct {
	key, value string
	err        error
}

// Authenticate implements Authenticator by returning an error when a header
// on the given request matches the key and value.
func (a *failingAuthenticator) Authenticate(r *http.Request) error {
	h := r.Header.Get(a.key)
	if h == a.value {
		return a.err
	}
	return nil
}

func TestNewCompositeAuthenticator(t *testing.T) {
	var (
		k1, v1 = "foo", "bar"
		k2, v2 = "baz", "bam"

		err1 = fmt.Errorf("error 1")
		err2 = fmt.Errorf("error 2")
	)

	tcs := []struct {
		name string
		req  *http.Request
		as   []Authenticator
		want error
	}{
		{
			name: "empty authenticator",
			req:  &http.Request{},
			as:   []Authenticator{},
			want: nil,
		},
		{
			name: "first authenticator fails",
			req: &http.Request{
				Header: header(k1, v1),
			},
			as: []Authenticator{
				&failingAuthenticator{k1, v1, err1},
				&failingAuthenticator{k2, v2, err2},
			},
			want: err1,
		},
		{
			name: "second authenticator fails",
			req: &http.Request{
				Header: header(k2, v2),
			},
			as: []Authenticator{
				&failingAuthenticator{k1, v1, err1},
				&failingAuthenticator{k2, v2, err2},
			},
			want: err2,
		},
		{
			name: "no authenticator fails",
			req:  &http.Request{},
			as: []Authenticator{
				&failingAuthenticator{k1, v1, err1},
				&failingAuthenticator{k2, v2, err2},
			},
			want: nil,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			a := NewCompositeAuthenticator(tc.as...)
			err := a.Authenticate(tc.req)
			if err != nil {
				assert.ErrorIs(t, err, tc.want)
				return
			}
			assert.NoError(t, err)
		})
	}
}

type testJWTValidator struct {
	valid bool
}

func (v *testJWTValidator) Validate(_ string) (*jwt.Token, error) {
	if v.valid {
		return &jwt.Token{}, nil
	}
	return nil, fmt.Errorf("uh oh")
}

// header returns a http.Header with a single key-value pair.
func header(key, value string) http.Header {
	h := http.Header{}
	h.Set(key, value)
	return h
}

type fakeRequsetIntercepter struct {
	userInfo auth.UserInfo
}

func (f *fakeRequsetIntercepter) InterceptHTTPRequest(req *http.Request) (int, auth.UserInfo, error) {
	return http.StatusOK, f.userInfo, nil
}
