package common

// Proxy endpoints.
const (
	PathAgentHTTP    = "/v1/sessions-worker-service/http"
	PathAgentUpgrade = "/v1/sessions-worker-service/upgrade"
	PathServerReady  = "/_/ready"
	PathServerStatus = "/_/status"
)

// PathAgentStatus is the path for querying the agent's status.
const PathAgentStatus = "/_/status"

// Common HTTP headers and values.
const (
	HeaderProto = "x-llmo-tunnel-proto"
	ProtoV1     = "llmo-session-manager-server/1.0"
)
