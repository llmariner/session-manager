package server

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	v1 "github.com/cloudnatix/activity-tracker/api/v1"
	"github.com/cloudnatix/authz/pkg/authz"
	"github.com/cloudnatix/authz/pkg/tokenprocess"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestComposeActivityMessage(t *testing.T) {
	var (
		id       = "cluster-uuid-0001"
		host     = id + ".connect.staging.cloudnatix.com:443"
		host2    = id + ":443"
		path     = "/apis/metrics.k8s.io/v1beta1?timeout=32s"
		clientIP = "73.92.0.38:51350"

		// refer from authz/pkg/tokeprocess/tokenprocess_test.go
		testAuthHeaderForEndUser   = "Bearer eyJraWQiOiJYaFNObnNSLXMxaExpdEs2MHpha1JxVDRJMU1sdnVMQUQtczZLZnVSWWx3IiwiYWxnIjoiUlMyNTYifQ.eyJ2ZXIiOjEsImp0aSI6IkFULjh1aFg0SzNTc2NpcGlmcE51Z3IydmJ1UmdhbmptMVpDYURUQk5BS0N1VFkiLCJpc3MiOiJodHRwczovL2Nsb3VkbmF0aXgub2t0YS5jb20vb2F1dGgyL2Nsb3VkbmF0aXgiLCJhdWQiOiJhcGk6Ly9jbG91ZG5hdGl4IiwiaWF0IjoxNTkxMzM4NTEyLCJleHAiOjE1OTE0MjQ5MTIsImNpZCI6IjBvYWE2ODg5OWNUeDFyTXFuNHg2IiwidWlkIjoiMDB1YjRkNHR2SmtlWEN1eEo0eDYiLCJzY3AiOlsiZW1haWwiLCJwcm9maWxlIiwib3BlbmlkIl0sInN1YiI6ImFwYXF1aW5vQGdtYWlsLmNvbSIsImNuX3RlbmFudF9pZCI6IjBvYWI0ZHJ2cTBOd01NQUJqNHg2In0.EAZ_qXEsebA1f0Kk1XeOwXYysydf4KRfwAowMBNO6-KGCW5xTPz6kuLG_n-9H5p5AnmlRERJ0gBb0JJ0A8vAXdT7CRlfU_JH4H9RBvItk5yay7Qdn-ZnHHfVk86W0eM0pqiZpqgH-ZHul7Y8_YCquu-p0YXN2WVUS8jZQ7QdtzKXX403fyQFGOhMw0hqh1qJsAua8wKKQf9N6pOLVftHOg5NgyydS-FsAJA73VBTvHbyjcvxRLn1HM3Ju1LuBQo00HQkmhmHR2gJj5pNTYTQvX67VsIXt6oa9LEanKoSABwaPS4nudtmFh1js5zK7CUyYK6hrhtoV-GaBbqjsEM88Q"
		expectedTenantIDForEndUser = authz.TenantID("0oab4drvq0NwMMABj4x6")
		expectedUserID             = authz.UserID("00ub4d4tvJkeXCuxJ4x6")

		now = time.Unix(0, 1)
	)
	tcs := []struct {
		name     string
		req      *http.Request
		kind     v1.ConnectProxyRequestKind
		respCode int
		ts       time.Time
		exp      *v1.Activity
		isError  bool
	}{
		{
			name: "proxy put",
			req: &http.Request{
				Header: http.Header{
					"Authorization": []string{testAuthHeaderForEndUser},
				},
				Method: http.MethodPut,
				URL: &url.URL{
					Path: path,
				},
				Host:       host,
				RemoteAddr: clientIP,
			},
			kind:     v1.ConnectProxyRequestKind_PROXY,
			respCode: 200,
			ts:       now,
			exp: &v1.Activity{
				Subject:   string(expectedUserID),
				ClientIp:  clientIP,
				TenantId:  string(expectedTenantIDForEndUser),
				Action:    "proxy_http_request",
				Source:    v1.ActivitySource_CONNECT_PROXY,
				Timestamp: timestamppb.New(now.UTC()),
				Kind: &v1.Activity_ConnectProxy{
					ConnectProxy: &v1.ConnectProxyActivity{
						Kind:         v1.ConnectProxyRequestKind_PROXY,
						ClusterUuid:  "cluster-uuid-0001",
						Host:         host,
						Method:       "PUT",
						Url:          path,
						ResponseCode: 200,
					},
				},
			},
			isError: false,
		},
		{
			name: "no auth header",
			req: &http.Request{
				Header: http.Header{},
				Method: http.MethodPut,
				URL: &url.URL{
					Path: path,
				},
				Host:       host,
				RemoteAddr: clientIP,
			},
			kind:     v1.ConnectProxyRequestKind_PROXY,
			respCode: 200,
			ts:       now,
			exp: &v1.Activity{
				Subject:   "",
				ClientIp:  clientIP,
				TenantId:  "",
				Action:    "proxy_http_request",
				Source:    v1.ActivitySource_CONNECT_PROXY,
				Timestamp: timestamppb.New(now.UTC()),
				Kind: &v1.Activity_ConnectProxy{
					ConnectProxy: &v1.ConnectProxyActivity{
						Kind:         v1.ConnectProxyRequestKind_PROXY,
						ClusterUuid:  "cluster-uuid-0001",
						Host:         host,
						Method:       "PUT",
						Url:          path,
						ResponseCode: 200,
					},
				},
			},
			isError: false,
		},
		{
			name: "no domain name in the host",
			req: &http.Request{
				Header: http.Header{},
				Method: http.MethodPut,
				URL: &url.URL{
					Path: path,
				},
				Host:       host2,
				RemoteAddr: clientIP,
			},
			kind:     v1.ConnectProxyRequestKind_PROXY,
			respCode: 200,
			ts:       now,
			exp: &v1.Activity{
				Subject:   "",
				ClientIp:  clientIP,
				TenantId:  "",
				Action:    "proxy_http_request",
				Source:    v1.ActivitySource_CONNECT_PROXY,
				Timestamp: timestamppb.New(now.UTC()),
				Kind: &v1.Activity_ConnectProxy{
					ConnectProxy: &v1.ConnectProxyActivity{
						Kind:         v1.ConnectProxyRequestKind_PROXY,
						ClusterUuid:  "cluster-uuid-0001",
						Host:         host2,
						Method:       "PUT",
						Url:          path,
						ResponseCode: 200,
					},
				},
			},
			isError: false,
		},
		{
			name: "log viewer",
			req: &http.Request{
				Header: http.Header{
					"Authorization": []string{testAuthHeaderForEndUser},
				},
				Method: http.MethodGet,
				URL: &url.URL{
					Path:     "/api/v1/namespaces/dashboard/pods/dashboard-bcd9c66d8-lhx4c/log",
					RawQuery: "container=dashboard",
				},
				Host:       host,
				RemoteAddr: clientIP,
			},
			kind:     v1.ConnectProxyRequestKind_PROXY,
			respCode: 200,
			ts:       now,
			exp: &v1.Activity{
				Subject:   string(expectedUserID),
				ClientIp:  clientIP,
				TenantId:  string(expectedTenantIDForEndUser),
				Action:    "proxy_http_request",
				Source:    v1.ActivitySource_CONNECT_PROXY,
				Timestamp: timestamppb.New(now.UTC()),
				Kind: &v1.Activity_ConnectProxy{
					ConnectProxy: &v1.ConnectProxyActivity{
						Kind:         v1.ConnectProxyRequestKind_PROXY,
						ClusterUuid:  "cluster-uuid-0001",
						Host:         host,
						Method:       "GET",
						Url:          "/api/v1/namespaces/dashboard/pods/dashboard-bcd9c66d8-lhx4c/log",
						ResponseCode: 200,
						Operation:    "log",
					},
				},
			},
		},
		{
			name: "exec",
			req: &http.Request{
				Header: http.Header{
					"Authorization": []string{testAuthHeaderForEndUser},
				},
				Method: http.MethodPost,
				URL: &url.URL{
					Path:     "/api/v1/namespaces/dashboard/pods/dashboard-bcd9c66d8-lhx4c/exec",
					RawQuery: "command=bash&container=dashboard&stdin=true&stdout=true&tty=true",
				},
				Host:       host,
				RemoteAddr: clientIP,
			},
			kind:     v1.ConnectProxyRequestKind_PROXY,
			respCode: 200,
			ts:       now,
			exp: &v1.Activity{
				Subject:   string(expectedUserID),
				ClientIp:  clientIP,
				TenantId:  string(expectedTenantIDForEndUser),
				Action:    "proxy_http_request",
				Source:    v1.ActivitySource_CONNECT_PROXY,
				Timestamp: timestamppb.New(now.UTC()),
				Kind: &v1.Activity_ConnectProxy{
					ConnectProxy: &v1.ConnectProxyActivity{
						Kind:         v1.ConnectProxyRequestKind_PROXY,
						ClusterUuid:  "cluster-uuid-0001",
						Host:         host,
						Method:       "POST",
						Url:          "/api/v1/namespaces/dashboard/pods/dashboard-bcd9c66d8-lhx4c/exec",
						ResponseCode: 200,
						Operation:    "exec",
					},
				},
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			s := Server{
				authenticator: &fakeAuthenticator{valid: true},
				identifier:    &fakeIdentifier{id: id},
				processor:     tokenprocess.NewProcessor(),
			}
			got, err := s.composeActivityMessage(tc.kind, tc.ts, tc.req, tc.respCode)
			assert.Equal(t, tc.isError, err != nil)
			// ignore uuid.
			got.Uuid = ""
			assert.Equal(t, tc.exp, got)
		})
	}
}
