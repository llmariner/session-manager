package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
	"k8s.io/klog/v2"
)

// Config is the configuration for the proxy.
type Config struct {
	BaseURL string `yaml:"baseUrl"`
	Server  Server `yaml:"server"`
	Admin   Admin  `yaml:"admin"`
}

// Server is the configuration for the external HTTPS server.
type Server struct {
	Port      int `yaml:"port"`
	AgentPort int `yaml:"agentPort"`

	Auth Auth `yaml:"auth"`

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
	RBACServer *RBACServerAuth `yaml:"rbacServer"`
	OIDC       OIDC            `yaml:"oidc"`
}

// RBACServerAuth is the configuration for authentication with RBAC server.
type RBACServerAuth struct {
	Addr string `yaml:"addr"`
}

// OIDC is the configuration for OIDC.
type OIDC struct {
	ClientID     string `yaml:"clientId"`
	ClientSecret string `yaml:"clientSecret"`
	IssuerURL    string `yaml:"issuerUrl"`
	ResolverAddr string `yaml:"resolverAddr"`
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
