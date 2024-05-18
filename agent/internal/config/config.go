package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
	"k8s.io/klog/v2"
)

// Config is the configuration for the agent.
type Config struct {
	ID     string       `yaml:"id"`
	Admin  Admin        `yaml:"admin"`
	Proxy  Proxy        `yaml:"proxy"`
	Envoy  Envoy        `yaml:"envoy"`
	Sentry sentryConfig `yaml:"sentry"`

	// HTTPPort is the port that the agent listens on for HTTP connections.
	HTTPPort int    `yaml:"httpPort"`
	JWKSURI  string `yaml:"jwksUri"`
}

// Admin is the configuration for the Admin server.
type Admin struct {
	Socket string `yaml:"socket"`
}

// Proxy is the configuration for connecting to the proxy.
type Proxy struct {
	Auth    Auth   `yaml:"auth"`
	HTTP    Tunnel `yaml:"http"`
	Connect Tunnel `yaml:"connect"`
}

// Auth is the authentication configuration for the proxy.
type Auth struct {
	Path           string        `yaml:"path"`
	ReloadInterval time.Duration `yaml:"reloadInterval"`
}

// Tunnel is the configuration for a tunnel.
type Tunnel struct {
	URL         string        `yaml:"url"`
	CA          string        `yaml:"ca"`
	PoolSize    int           `yaml:"poolSize"`
	DialTimeout time.Duration `yaml:"dialTimeout"`
}

// Envoy is the configuration for connecting to Envoy.
type Envoy struct {
	Socket string `yaml:"socket"`
}

// sentryConfig is the configuration for Sentry.
type sentryConfig struct {
	// DSN is the Sentry data source name.
	DSN string `yaml:"dsn"`
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

	klog.V(2).Infof("parsed configuration file\n%+vq", c)
	return &c, nil
}
