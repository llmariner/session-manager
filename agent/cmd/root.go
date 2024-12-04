package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/go-logr/logr"
	"github.com/go-logr/stdr"
	"github.com/llmariner/cluster-manager/pkg/status"
	"github.com/llmariner/session-manager/agent/internal/admin"
	"github.com/llmariner/session-manager/agent/internal/config"
	"github.com/llmariner/session-manager/agent/internal/health"
	"github.com/llmariner/session-manager/agent/internal/server"
	"github.com/llmariner/session-manager/agent/internal/tunnel"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
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
	errC := make(chan error)

	logger := stdr.New(log.Default())

	// HTTP tunnel.
	baseURL := c.Proxy.BaseURL
	if baseURL == "" {
		// Construct the base URL from c.SessionManagerServerWorkerServiceAddr.
		protocol := "http"
		if c.Proxy.TLS.Enable {
			protocol = "https"
		}
		baseURL = fmt.Sprintf("%s://%s", protocol, c.SessionManagerServerWorkerServiceAddr)
	}
	urlHTTP, err := url.Parse(baseURL + c.Proxy.HTTP.Path)
	if err != nil {
		return err
	}
	tunnelHTTP, err := tunnel.NewTunnel(tunnel.Opts{
		PoolSize:    c.Proxy.HTTP.PoolSize,
		DialTimeout: c.Proxy.HTTP.DialTimeout,

		URL: urlHTTP,

		TLSEnabled: c.Proxy.TLS.Enable,

		EnvoySocket: c.Envoy.Socket,
	})
	if err != nil {
		return err
	}

	// HTTP upgrade tunnel.
	urlUpgrade, err := url.Parse(baseURL + c.Proxy.Upgrade.Path)
	if err != nil {
		return err
	}
	tunnelUpgrade, err := tunnel.NewTunnel(tunnel.Opts{
		PoolSize:    c.Proxy.Upgrade.PoolSize,
		DialTimeout: c.Proxy.Upgrade.DialTimeout,

		URL: urlUpgrade,

		TLSEnabled: c.Proxy.TLS.Enable,

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

	// Component Status sender.
	if c.ComponentStatusSender.Enable {
		go func() {
			ss, err := status.NewBeaconSender(c.ComponentStatusSender, grpcOption(c), logger)
			if err != nil {
				errC <- err
			}
			ss.Run(logr.NewContext(ctx, logger))
		}()
	}

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

func grpcOption(c *config.Config) grpc.DialOption {
	if c.Proxy.TLS.Enable {
		return grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{}))
	}
	return grpc.WithTransportCredentials(insecure.NewCredentials())
}
