package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"

	"github.com/llmariner/session-manager/server/internal/admin"
	"github.com/llmariner/session-manager/server/internal/auth"
	"github.com/llmariner/session-manager/server/internal/config"
	"github.com/llmariner/session-manager/server/internal/proxy"
	"github.com/llmariner/session-manager/server/internal/server"
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
	// External HTTPS server.
	httpProxy := proxy.NewHTTPProxy()
	upgradeProxy := proxy.NewUpgradeProxy()
	httpProxy.SetObserver(upgradeProxy)

	var wauth auth.Authenticator
	if c.Server.Auth.RBACServer != nil {
		wa, err := auth.NewWorkerAuthenticator(ctx, c.Server.Auth.RBACServer.Addr)
		if err != nil {
			return fmt.Errorf("new worker authenticator: %w", err)
		}
		wauth = wa
	} else {
		wauth = &auth.NoopAuthenticator{}
	}

	var (
		eauth      auth.Authenticator
		loginFn    http.HandlerFunc
		callbackFn http.HandlerFunc
	)
	if c.Server.Auth.DexServer != nil {
		tex, err := auth.NewTokenExchanger(ctx, auth.TokenExchangerOptions{
			ClientID:     c.Server.Auth.OIDC.ClientID,
			ClientSecret: c.Server.Auth.OIDC.ClientSecret,
			IssuerURL:    c.Server.Auth.OIDC.IssuerURL,
			RedirectURI:  c.Server.Auth.OIDC.RedirectURI,

			DexServerAddr: c.Server.Auth.DexServer.Addr,
		})
		if err != nil {
			return fmt.Errorf("new token exchanger: %w", err)
		}
		ea, err := auth.NewExternalAuthenticator(
			ctx,
			c.Server.Auth.RBACServer.Addr,
			tex,
			c.Server.Auth.CacheExpiration,
			c.Server.Auth.CacheCleanup,
			c.Server.Slurm.Enable,
		)
		if err != nil {
			return fmt.Errorf("new worker authenticator: %w", err)
		}
		eauth = ea
		loginFn = ea.HandleLogin
		callbackFn = ea.HandleLoginCallback
	} else {
		eauth = &auth.NoopAuthenticator{}
		loginFn = func(w http.ResponseWriter, r *http.Request) {}
		callbackFn = func(w http.ResponseWriter, r *http.Request) {}
	}

	s := server.NewServer(server.Opts{
		HTTPProxy:             httpProxy,
		UpgradeProxy:          upgradeProxy,
		AgentAuthenticator:    wauth,
		ExternalAuthenticator: eauth,
		LoginFunc:             loginFn,
		LoginCallBackFunc:     callbackFn,
		AllowedOriginHosts:    c.Server.GetAllowedOriginHosts(),
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

	// Await first error.
	var err error
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
