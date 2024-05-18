package cnatix

import (
	"context"
	"fmt"
	"net/http"

	"github.com/cloudnatix/connect-proxy/pkg/auth"
	v1 "github.com/cloudnatix/multiclustercontroller/api/proto/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"k8s.io/klog/v2"
)

var (
	errMissingAuthHeader = fmt.Errorf("cnatix: missing auth header")
	errClusterNotFound   = fmt.Errorf("cnatix: cluster not found")
	errGetCluster        = fmt.Errorf("cnatix: get cluster failed")
)

const httpHeaderAuthorization = "Authorization"

// ClusterChecker confirms the existing of the cluster with the given ID.
type ClusterChecker interface {
	Check(ctx context.Context, id string) error
}

// MCCClusterChecker is a ClusterChecker that consults the
// multiclustercontroller (MCC).
type MCCClusterChecker struct {
	client v1.MultiClusterControllerServiceClient
}

// NewMCCClusterChecker returns a new MCCClusterChecker.
func NewMCCClusterChecker(addr string) (*MCCClusterChecker, error) {
	cc, err := grpc.Dial(addr, grpc.WithInsecure())
	if err != nil {
		return nil, fmt.Errorf("cnatix: dial mcc: %s", err)
	}

	client := v1.NewMultiClusterControllerServiceClient(cc)
	return &MCCClusterChecker{client: client}, nil
}

// Check implements ClusterChecker by checking for the existence of the given
// cluster in the multiclustercontroller.
func (g *MCCClusterChecker) Check(ctx context.Context, id string) error {
	klog.V(2).Infof("consulting MCC for ID=%q", id)
	resp, err := g.client.GetCluster(ctx, &v1.GetClusterRequest{Uuid: id})
	if err != nil {
		if status.Convert(err).Code() == codes.NotFound {
			klog.Infof("auth failed: cluster not found")
			return errClusterNotFound
		}

		klog.Infof("auth failed: could not infer cluster permissions: %s", err)
		return errGetCluster
	}

	// Confirm that the response payload contains the UUID. This check is not
	// strictly necessary, but it serves as an additional safeguard.
	if resp.Cluster != nil && resp.Cluster.Uuid != id {
		actual := "MISSING"
		if resp.Cluster != nil {
			actual = resp.Cluster.Uuid
		}
		klog.Infof("auth failed: queried ID=%q does not match returned ID=%q", id, actual)
		return errClusterNotFound
	}

	klog.V(2).Infof("auth succeeded for ID=%q", id)
	return nil
}

// ClusterAuthenticator authenticates requests by validating the authentication
// payload on the incoming request has permission to access the cluster the
// request is referencing.
type ClusterAuthenticator struct {
	c ClusterChecker
	i auth.Identifier
}

// NewClusterAuthenticator returns a new ClusterAuthenticator.
func NewClusterAuthenticator(c ClusterChecker, i auth.Identifier) *ClusterAuthenticator {
	return &ClusterAuthenticator{
		c: c,
		i: i,
	}
}

// Authenticate implements Authenticator by validating the authentication
// payload against the multiclustercontroller to confirm that the request
// is permitted to access the given cluster.
func (a *ClusterAuthenticator) Authenticate(r *http.Request) error {
	// Fetch the cluster ID.
	id, err := a.i.Identify(r)
	if err != nil {
		return err
	}

	// Attach the authentication payload from the inbound request to the
	// context used when making the RPC.
	h := r.Header.Get(httpHeaderAuthorization)
	if h == "" {
		klog.Warningf("request denied: missing HTTP authentication header")
		return errMissingAuthHeader
	}
	ctx := metadata.AppendToOutgoingContext(r.Context(), httpHeaderAuthorization, h)

	// Check the cluster.
	return a.c.Check(ctx, id)
}
