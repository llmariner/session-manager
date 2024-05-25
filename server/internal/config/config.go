package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
	"k8s.io/klog/v2"
)

// Config is the configuration for the proxy.
type Config struct {
	Server Server `yaml:"server"`
	Admin  Admin  `yaml:"admin"`
}

// Server is the configuration for the external HTTPS server.
type Server struct {
	Port      int `yaml:"port"`
	AgentPort int `yaml:"agentPort"`

	Auth       Auth       `yaml:"auth"`
	Identifier Identifier `yaml:"identifier"`

	TLS *TLS `yaml:"tls"`
	// AllowedOriginHosts is a slice of Origin hosts that we allow in CORS preflight check.
	AllowedOriginHosts []string `yaml:"allowedOriginHosts"`
}

// GetAllowedOriginHosts returns allowed Origin hosts.
func (s *Server) GetAllowedOriginHosts() map[string]struct{} {
	res := map[string]struct{}{}
	for _, h := range s.AllowedOriginHosts {
		res[h] = struct{}{}
	}
	return res
}

// Admin is the configuration for the internal-only admin HTTP server.
type Admin struct {
	Port int `yaml:"port"`
}

// Auth is the authentication configuration for the proxy.
type Auth struct {
	Static     *StaticAuth     `yaml:"static,omitempty"`
	JWKS       *JWKSAuth       `yaml:"jwks,omitempty"`
	RBACServer *RBACServerAuth `yaml:"rbacServer"`
}

// StaticAuth is the configuration for a server.JWTAuthenticator using a
// file-based public key.
type StaticAuth struct {
	Path string `yaml:"path"`
}

// JWKSAuth is the configuration for a server.JWTAuthenticator using a
// JWKS-based public key.
type JWKSAuth struct {
	URL     string        `yaml:"url"`
	Refresh time.Duration `yaml:"refreshInterval"`
}

// RBACServerAuth is the configuration for authentication with RBAC server.
type RBACServerAuth struct {
	Addr string `yaml:"addr"`
}

// Identifier is the configuration for the proxy's identifier.
type Identifier struct {
	Static    *StaticIdentifier    `yaml:"static,omitempty"`
	HostBased *HostBasedIdentifier `yaml:"hostBased,omitempty"`
}

// StaticIdentifier is the configuration for a static identifier.
type StaticIdentifier struct {
	ID string `yaml:"id"`
}

// HostBasedIdentifier is the configuration for a host-based identifier.
type HostBasedIdentifier struct {
	// Port is the port that the identifier append when it is missing.
	Port int `yaml:"port"`
}

// TLS is the TLS configuration for the proxy.
type TLS struct {
	Key  string `yaml:"key"`
	Cert string `yaml:"cert"`
}

// Parse parses a configuration file at the given path and returns a Config
// struct.
func Parse(configPath string) (*Config, error) {
	klog.V(2).Infof("parsing configuration file; path=%q", configPath)

	var c Config
	b, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("config: parse: read: %s", err)
	}

	if err = yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("config: parse: unmarshal: %s", err)
	}

	klog.V(2).Infof("parsed configuration file\n%+v", c)
	return &c, nil
}
