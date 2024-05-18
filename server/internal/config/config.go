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
	Addr string `yaml:"addr"`
	Auth Auth   `yaml:"auth"`
	TLS  TLS    `yaml:"tls"`
	// AllowedOriginHosts is a slice of Origin hosts that we allow in CORS preflight check.
	AllowedOriginHosts []string              `yaml:"allowedOriginHosts"`
	ActivityTracker    activityTrackerConfig `yaml:"activityTracker"`
	Sentry             sentryConfig          `yaml:"sentry"`
}

// GetAllowedOriginHosts returns allowed Origin hosts.
func (s *Server) GetAllowedOriginHosts() map[string]struct{} {
	res := map[string]struct{}{}
	for _, h := range s.AllowedOriginHosts {
		res[h] = struct{}{}
	}
	return res
}

type activityTrackerConfig struct {
	EnableActivityTracker bool     `yaml:"enableActivityTracker"`
	BrokerAddrs           []string `yaml:"brokerAddrs"`
}

// sentryConfig is the configuration for Sentry.
type sentryConfig struct {
	// DSN is the Sentry data source name.
	DSN string `yaml:"dsn"`
}

// Admin is the configuration for the internal-only admin HTTP server.
type Admin struct {
	Addr string `yaml:"addr"`
}

// Auth is the authentication configuration for the proxy.
type Auth struct {
	MCCAuth *MCCAuth    `yaml:"mcc,omitempty"`
	Static  *StaticAuth `yaml:"static,omitempty"`
	JWKS    *JWKSAuth   `yaml:"jwks,omitempty"`
}

// MCCAuth is the configuration for communicating with the
// multiclustercontroller.
type MCCAuth struct {
	Addr string `yaml:"addr"`
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
