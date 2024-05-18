package cnatix

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/cloudnatix/connect-proxy/pkg/auth"
	v1 "github.com/cloudnatix/multiclustercontroller/api/proto/v1"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type fakeClient struct {
	v1.MultiClusterControllerServiceClient

	resp *v1.GetClusterResponse
	err  error
}

func (c *fakeClient) GetCluster(_ context.Context, _ *v1.GetClusterRequest, _ ...grpc.CallOption) (*v1.GetClusterResponse, error) {
	return c.resp, c.err
}

func TestMCCClusterChecker(t *testing.T) {
	var (
		clientErr = fmt.Errorf("client error")
		clusterID = "test-cluster"
	)

	tcs := []struct {
		name    string
		client  v1.MultiClusterControllerServiceClient
		wantErr error
	}{
		{
			name:    "client returns 404 error",
			client:  &fakeClient{err: status.Error(codes.NotFound, "not found")},
			wantErr: errClusterNotFound,
		},
		{
			name:    "client returns non-404 error",
			client:  &fakeClient{err: clientErr},
			wantErr: errGetCluster,
		},
		{
			name:    "nil cluster",
			client:  &fakeClient{resp: &v1.GetClusterResponse{Cluster: nil}},
			wantErr: errClusterNotFound,
		},
		{
			name:    "mismatched cluster",
			client:  &fakeClient{resp: &v1.GetClusterResponse{Cluster: &v1.Cluster{Uuid: "not-test-cluster"}}},
			wantErr: errClusterNotFound,
		},
		{
			name:    "matched cluster",
			client:  &fakeClient{resp: &v1.GetClusterResponse{Cluster: &v1.Cluster{Uuid: clusterID}}},
			wantErr: nil,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			checker := &MCCClusterChecker{client: tc.client}
			err := checker.Check(context.Background(), clusterID)
			if err != nil {
				assert.ErrorIs(t, err, tc.wantErr)
				return
			}
			assert.NoError(t, err)
		})
	}
}

type fakeIdentifier struct {
	id  string
	err error
}

func (i *fakeIdentifier) Identify(_ *http.Request) (string, error) {
	return i.id, i.err
}

type fakeChecker struct {
	auth string
	err  error
}

func (c *fakeChecker) Check(ctx context.Context, _ string) error {
	if c.err != nil {
		return c.err
	}

	// Capture the auth header from the outgoing context.
	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		return fmt.Errorf("could not fetch map from context")
	}

	vs := md.Get(httpHeaderAuthorization)
	if len(vs) != 1 {
		return fmt.Errorf("context did not contain a single auth header value")
	}
	c.auth = vs[0]

	return nil
}

func TestNewClusterAuthenticator(t *testing.T) {
	var (
		id        = "test-id"
		errID     = fmt.Errorf("id error")
		errCheck  = fmt.Errorf("check failed")
		authValue = "something secret"
	)

	header := http.Header{}
	header.Set(httpHeaderAuthorization, authValue)

	tcs := []struct {
		name       string
		identifier auth.Identifier
		checker    *fakeChecker
		req        *http.Request

		wantAuth string
		wantErr  error
	}{
		{
			name:       "ID check fails",
			identifier: &fakeIdentifier{err: errID},
			checker:    &fakeChecker{},
			req:        &http.Request{},
			wantErr:    errID,
		},
		{
			name:       "missing auth header",
			identifier: &fakeIdentifier{id: id},
			checker:    &fakeChecker{},
			req:        &http.Request{},
			wantErr:    errMissingAuthHeader,
		},
		{
			name:       "check fails",
			identifier: &fakeIdentifier{id: id},
			checker:    &fakeChecker{err: errCheck},
			req: &http.Request{
				Header: header,
			},
			wantErr: errCheck,
		},
		{
			name:       "check succeeds",
			identifier: &fakeIdentifier{id: id},
			checker:    &fakeChecker{},
			req: &http.Request{
				Header: header,
			},
			wantAuth: authValue,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			a := NewClusterAuthenticator(tc.checker, tc.identifier)
			err := a.Authenticate(tc.req)
			if err != nil {
				assert.ErrorIs(t, err, tc.wantErr)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.wantAuth, tc.checker.auth)
		})
	}
}
