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
	Admin Admin `yaml:"admin"`
	Proxy Proxy `yaml:"proxy"`
	Envoy Envoy `yaml:"envoy"`

	SessionManagerServerWorkerServiceAddr string `yaml:"sessionManagerServerWorkerServiceAddr"`

	// HTTPPort is the port that the agent listens on for HTTP connections.
	HTTPPort int `yaml:"httpPort"`
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	if err := c.Admin.validate(); err != nil {
		return fmt.Errorf("admin: %s", err)
	}
	if err := c.Proxy.validate(); err != nil {
		return fmt.Errorf("proxy: %s", err)
	}
	if err := c.Envoy.validate(); err != nil {
		return fmt.Errorf("envoy: %s", err)
	}
	if c.HTTPPort <= 0 {
		return fmt.Errorf("httpPort must be greater than 0")
	}

	if c.SessionManagerServerWorkerServiceAddr == "" && c.Proxy.BaseURL == "" {
		return fmt.Errorf("sessionManagerServerWorkerServiceAddr or proxy.BaseURL must be set")
	}

	return nil

}

// Admin is the configuration for the Admin server.
type Admin struct {
	Socket string `yaml:"socket"`
}

func (a *Admin) validate() error {
	if a.Socket == "" {
		return fmt.Errorf("config: admin: socket: must be set")
	}
	return nil
}

// Proxy is the configuration for connecting to the proxy.
type Proxy struct {
	BaseURL string `yaml:"baseUrl"`
	HTTP    Tunnel `yaml:"http"`
	Upgrade Tunnel `yaml:"upgrade"`

	TLS TLS `yaml:"tls"`
}

func (p *Proxy) validate() error {
	if err := p.HTTP.validate(); err != nil {
		return fmt.Errorf("http: %s", err)
	}
	if err := p.Upgrade.validate(); err != nil {
		return fmt.Errorf("upgrade: %s", err)
	}
	return nil
}

// Tunnel is the configuration for a tunnel.
type Tunnel struct {
	Path        string        `yaml:"path"`
	PoolSize    int           `yaml:"poolSize"`
	DialTimeout time.Duration `yaml:"dialTimeout"`
}

func (t *Tunnel) validate() error {
	if t.Path == "" {
		return fmt.Errorf("path must be set")
	}
	if t.PoolSize <= 0 {
		return fmt.Errorf("poolSize must be greater than 0")
	}
	if t.DialTimeout <= 0 {
		return fmt.Errorf("dialTimeout must be greater than 0")
	}
	return nil
}

// TLS is the configuration for TLS.
type TLS struct {
	Enable bool `yaml:"enable"`
}

// Envoy is the configuration for connecting to Envoy.
type Envoy struct {
	Socket string `yaml:"socket"`
}

func (e *Envoy) validate() error {
	if e.Socket == "" {
		return fmt.Errorf("socket must be set")
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
