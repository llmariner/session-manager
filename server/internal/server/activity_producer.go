package server

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	v1 "github.com/cloudnatix/activity-tracker/api/v1"
	"github.com/cloudnatix/kafka/pkg/producer"
	"github.com/cloudnatix/kafka/pkg/topic"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"k8s.io/klog/v2"
)

// publishMessage publishes messages to Kafka cluster.
func (s *Server) publishMessage(data *v1.Activity, ts time.Time) error {
	any, err := anypb.New(data)
	if err != nil {
		return fmt.Errorf("marshal any: %s", err)
	}
	klog.V(2).Infof("Publish an activity message: %+v", data)
	return producer.PublishMessage(s.producer, topic.ActivitiesTopicName, "", any, ts)
}

func (s *Server) trackHTTPRequest(kind v1.ConnectProxyRequestKind, req *http.Request, respCode int) error {
	ts := time.Now()
	activity, err := s.composeActivityMessage(kind, ts, req, respCode)
	if err != nil {
		return err
	}
	return s.publishMessage(activity, ts)
}

var execLogsPattern = regexp.MustCompile("^/api/v1/namespaces/[^/]+/pods/[^/]+/(log|exec)")

func (s *Server) composeActivityMessage(
	kind v1.ConnectProxyRequestKind,
	timestamp time.Time,
	req *http.Request,
	respCode int,
) (*v1.Activity, error) {
	var clientID, tenantID, clusterUUID, path string
	azr, err := s.processor.ProcessTokenInHTTPRequest(req)
	if err == nil {
		clientID = string(azr.UserID)
		tenantID = string(azr.TenantID)
	} else {
		klog.Infof("composeActivityMessage:req: method: %s, url:%s, %s", req.Method, req.URL, err)
	}

	// Identify clusterUUID from host in the request.
	// Legitimate host should be in the format as clusterUUID.connect.staging.cloudnatix.com.
	if req.Host != "" {
		clusterUUID, err = s.identifier.Identify(req)
		if err != nil {
			klog.Infof("Cannot parse clusterUUID from the request: %s: %s", req.Host, err)
		}
		// Remove port number in the clusterUUID if there is any.
		parts := strings.Split(clusterUUID, ":")
		clusterUUID = parts[0]
	}
	if req.URL != nil {
		klog.Infof("req.URL: %+v", req.URL)
		path = req.URL.Path
	}
	var operation string
	if matched := execLogsPattern.FindStringSubmatch(path); len(matched) > 1 {
		operation = matched[1]
	}
	cpActivity := &v1.ConnectProxyActivity{
		Kind:         kind,
		ClusterUuid:  clusterUUID,
		Host:         req.Host,
		Method:       req.Method,
		Url:          path,
		ResponseCode: int32(respCode),
		Operation:    operation,
	}
	return &v1.Activity{
		Uuid:      uuid.New().String(),
		Timestamp: timestamppb.New(timestamp.UTC()),
		// TODO(guangrui): revisit action definition.
		Action:   "proxy_http_request",
		Subject:  clientID,
		ClientIp: req.RemoteAddr,
		TenantId: tenantID,
		Source:   v1.ActivitySource_CONNECT_PROXY,
		Kind: &v1.Activity_ConnectProxy{
			ConnectProxy: cpActivity,
		},
	}, nil
}
