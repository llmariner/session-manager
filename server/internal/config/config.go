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
	BaseURL string `yaml:"baseUrl"`
	Server  Server `yaml:"server"`
	Admin   Admin  `yaml:"admin"`
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	if c.BaseURL == "" {
		return fmt.Errorf("baseUrl must be set")
	}
	if err := c.Server.validate(); err != nil {
		return err
	}
	if err := c.Admin.validate(); err != nil {
		return err
	}

	return nil
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

func (s *Server) validate() error {
	if s.Port <= 0 {
		return fmt.Errorf("port must be greater than 0")
	}
	if s.AgentPort <= 0 {
		return fmt.Errorf("agentPort must be greater than 0")
	}

	if err := s.Auth.validate(); err != nil {
		return err
	}

	if s.TLS != nil {
		if err := s.TLS.validate(); err != nil {
			return err
		}
	}

	return nil
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

func (a *Admin) validate() error {
	if a.Port <= 0 {
		return fmt.Errorf("port must be greater than 0")
	}
	return nil
}

// Auth is the authentication configuration for the proxy.
type Auth struct {
	RBACServer      *RBACServerAuth `yaml:"rbacServer"`
	DexServer       *DexServerAuth  `yaml:"dexServerAuth"`
	OIDC            OIDC            `yaml:"oidc"`
	CacheExpiration time.Duration   `yaml:"cacheExpiration"`
	CacheCleanup    time.Duration   `yaml:"cacheCleanup"`
}

func (a *Auth) validate() error {
	if a.RBACServer == nil {
		// Authentication is not enabled.
		return nil
	}

	if err := a.RBACServer.validate(); err != nil {
		return fmt.Errorf("rbacServer: %s", err)
	}

	if err := a.DexServer.validate(); err != nil {
		return fmt.Errorf("dexServer: %s", err)
	}

	if err := a.OIDC.validate(); err != nil {
		return err
	}
	if a.CacheExpiration <= 0 {
		return fmt.Errorf("cacheExpiration must be greater than 0")
	}
	if a.CacheCleanup <= 0 {
		return fmt.Errorf("cacheCleanup must be greater than 0")
	}

	return nil
}

// RBACServerAuth is the configuration for authentication with RBAC server.
type RBACServerAuth struct {
	Addr string `yaml:"addr"`
}

func (r *RBACServerAuth) validate() error {
	if r.Addr == "" {
		return fmt.Errorf("addr must be set")
	}
	return nil
}

// DexServerAuth is the configuration for authentication with Dex server.
type DexServerAuth struct {
	Addr string `yaml:"addr"`
}

func (r *DexServerAuth) validate() error {
	if r.Addr == "" {
		return fmt.Errorf("addr must be set")
	}
	return nil
}

// OIDC is the configuration for OIDC.
type OIDC struct {
	ClientID     string `yaml:"clientId"`
	ClientSecret string `yaml:"clientSecret"`
	IssuerURL    string `yaml:"issuerUrl"`
	ResolverAddr string `yaml:"resolverAddr"`
}

func (o *OIDC) validate() error {
	if o.ClientID == "" {
		return fmt.Errorf("clientId must be set")
	}
	if o.ClientSecret == "" {
		return fmt.Errorf("clientSecret must be set")
	}
	if o.IssuerURL == "" {
		return fmt.Errorf("issuerUrl must be set")
	}
	if o.ResolverAddr == "" {
		return fmt.Errorf("resolverAddr must be set")
	}
	return nil
}

// TLS is the TLS configuration for the proxy.
type TLS struct {
	Key  string `yaml:"key"`
	Cert string `yaml:"cert"`
}

// validate validates the configuration.
func (c *TLS) validate() error {
	if c.Key == "" {
		return fmt.Errorf("key must be set")
	}
	if c.Cert == "" {
		return fmt.Errorf("cert must be set")
	}
	return nil
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
