package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/cloudnatix/connect-proxy/agent/internal/admin"
	"github.com/cloudnatix/connect-proxy/agent/internal/config"
	"github.com/cloudnatix/connect-proxy/agent/internal/health"
	"github.com/cloudnatix/connect-proxy/agent/internal/server"
	"github.com/cloudnatix/connect-proxy/agent/internal/tunnel"
	"github.com/getsentry/sentry-go"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/klog/v2"
)

const (
	sentryBufferFlushDuration = 2 * time.Second
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

		if err := sentry.Init(sentry.ClientOptions{
			Dsn:         c.Sentry.DSN,
			Environment: c.ID,
		}); err != nil {
			return err
		}
		defer sentry.Flush(sentryBufferFlushDuration)

		if err := run(cmd.Context(), c); err != nil {
			sentry.CaptureException(err)
			return err
		}
		return nil
	},
}

func run(ctx context.Context, c *config.Config) error {
	// Token generator.
	errC := make(chan error)
	if c.Proxy.Auth.ReloadInterval == 0 {
		c.Proxy.Auth.ReloadInterval = 1<<63 - 1 // max 64 bit integer
	}
	g := tunnel.NewReloadingTokenGenerator(c.Proxy.Auth.Path, c.Proxy.Auth.ReloadInterval)
	go func() { errC <- g.Run(ctx) }()

	// HTTP tunnel.
	urlHTTP, err := url.Parse(c.Proxy.HTTP.URL)
	if err != nil {
		return err
	}
	tunnelHTTP, err := tunnel.NewTunnel(tunnel.Opts{
		PoolSize:    c.Proxy.HTTP.PoolSize,
		DialTimeout: c.Proxy.HTTP.DialTimeout,

		URL:            urlHTTP,
		TokenGenerator: g,
		CA:             c.Proxy.HTTP.CA,

		EnvoySocket: c.Envoy.Socket,
	})
	if err != nil {
		return err
	}

	// HTTP upgrade tunnel.
	urlUpgrade, err := url.Parse(c.Proxy.Connect.URL)
	if err != nil {
		return err
	}
	tunnelUpgrade, err := tunnel.NewTunnel(tunnel.Opts{
		PoolSize:    c.Proxy.Connect.PoolSize,
		DialTimeout: c.Proxy.Connect.DialTimeout,

		URL:            urlUpgrade,
		TokenGenerator: g,
		CA:             c.Proxy.Connect.CA,

		EnvoySocket: c.Envoy.Socket,
	})
	if err != nil {
		return err
	}

	// Admin server.
	ts := []*tunnel.Tunnel{tunnelHTTP, tunnelUpgrade}
	adminSrv := admin.NewServer(c.Admin.Socket, ts)

	// Server.
	go func() {
		s := server.NewServer(server.Opts{
			Admin:         adminSrv,
			TunnelHTTP:    tunnelHTTP,
			TunnelUpgrade: tunnelUpgrade,
		})
		errC <- s.Run()
	}()

	healthHandler := health.NewProbeHandler()
	healthHandler.AddProbe(adminSrv)
	if c.JWKSURI != "" {
		healthHandler.AddProbe(health.NewJWKSValidator(c.JWKSURI))
	}
	healthMux := http.NewServeMux()
	healthMux.HandleFunc("/ready", healthHandler.ProbeHandler)
	srv := http.Server{
		Addr:    fmt.Sprintf(":%d", c.HTTPPort),
		Handler: healthMux,
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			errC <- err
		}
	}()

	return <-errC
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
