package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/llm-operator/session-manager/common/pkg/auth"
	"github.com/llm-operator/session-manager/common/pkg/jwt"
	"github.com/llm-operator/session-manager/server/internal/admin"
	"github.com/llm-operator/session-manager/server/internal/config"
	"github.com/llm-operator/session-manager/server/internal/proxy"
	"github.com/llm-operator/session-manager/server/internal/server"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/klog/v2"
)

var rootCmd = &cobra.Command{
	RunE: func(cmd *cobra.Command, args []string) error {
		configPath, err := cmd.Flags().GetString("config")
		if err != nil {
			return err
		}

		c, err := config.Parse(configPath)
		if err != nil {
			return err
		}

		return run(cmd.Context(), c)
	},
}

func run(ctx context.Context, c *config.Config) error {
	var identifier auth.Identifier
	if s := c.Server.Identifier.Static; s != nil {
		identifier = auth.NewStaticIdentifier(s.ID)
	} else if h := c.Server.Identifier.HostBased; h != nil {
		identifier = auth.NewHostBasedIdentifier(h.Port)
	} else {
		return fmt.Errorf("identifier must be specified")
	}

	var authenticators []auth.Authenticator
	if s := c.Server.Auth.Static; s != nil {
		v, err := jwt.NewStaticValidator(s.Path)
		if err != nil {
			return err
		}
		authenticators = append(authenticators, auth.NewJWTAuthenticator(v))
	}

	if j := c.Server.Auth.JWKS; j != nil {
		v, err := jwt.NewJWKSValidator(ctx, j.URL, jwt.JWKSValidatorOpts{
			Refresh: j.Refresh,
		})
		if err != nil {
			return err
		}
		authenticators = append(authenticators, auth.NewJWTAuthenticator(v))
	}

	if r := c.Server.Auth.RBACServer; r != nil {
		a, err := auth.NewRBACServerAuthenticator(ctx, r.Addr)
		if err != nil {
			return err
		}
		authenticators = append(authenticators, a)
	}

	if len(authenticators) == 0 {
		return fmt.Errorf("authenticator must be specified")
	}

	// External HTTPS server.
	httpProxy := proxy.NewHTTPProxy()
	upgradeProxy := proxy.NewUpgradeProxy()
	httpProxy.SetObserver(upgradeProxy)
	s := server.NewServer(server.Opts{
		HTTPProxy:          httpProxy,
		UpgradeProxy:       upgradeProxy,
		Authenticator:      auth.NewCompositeAuthenticator(authenticators...),
		Identifier:         identifier,
		AllowedOriginHosts: c.Server.GetAllowedOriginHosts(),
	})

	errS := make(chan error)
	go func() {
		var tls *server.TLSConfig
		if t := c.Server.TLS; t != nil {
			tls = &server.TLSConfig{
				CertPath: t.Cert,
				KeyPath:  t.Key,
			}
		}

		err := server.RunHTTPServer(
			ctx,
			server.RunHTTPServerOpts{
				Server:    s,
				TLS:       tls,
				Port:      c.Server.Port,
				AgentPort: c.Server.AgentPort,
			},
		)
		if err != nil {
			err = fmt.Errorf("run: %s", err)
		}
		errS <- err
	}()

	// Internal admin HTTP server.
	proxies := []proxy.Proxy{httpProxy, upgradeProxy}
	adminS := admin.NewServer(fmt.Sprintf(":%d", c.Admin.Port), proxies)

	errAdminS := make(chan error)
	go func() {
		errAdminS <- adminS.Run()
	}()

	var err error

	// Await first error.
	select {
	case err = <-errS:
	case err = <-errAdminS:
	}

	return err

}

func init() {
	// Add verbosity flag from klog.
	klog.InitFlags(flag.CommandLine)
	v := flag.CommandLine.Lookup("v")
	pflag.CommandLine.AddGoFlag(v)

	rootCmd.Flags().String("config", "", "Path to configuration file")
	_ = rootCmd.MarkFlagRequired("config")
	rootCmd.SilenceUsage = true
}
