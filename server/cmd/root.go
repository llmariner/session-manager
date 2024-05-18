package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/Shopify/sarama"
	"github.com/cloudnatix/connect-proxy/pkg/auth"
	"github.com/cloudnatix/connect-proxy/pkg/auth/cnatix"
	"github.com/cloudnatix/connect-proxy/pkg/jwt"
	"github.com/cloudnatix/connect-proxy/proxy/internal/admin"
	"github.com/cloudnatix/connect-proxy/proxy/internal/config"
	"github.com/cloudnatix/connect-proxy/proxy/internal/proxy"
	"github.com/cloudnatix/connect-proxy/proxy/internal/server"
	"github.com/cloudnatix/kafka/pkg/producer"
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

		if err := sentry.Init(sentry.ClientOptions{Dsn: c.Server.Sentry.DSN}); err != nil {
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
	// Authentication.
	var validator jwt.Validator
	if c.Server.Auth.Static != nil {
		v, err := jwt.NewStaticValidator(c.Server.Auth.Static.Path)
		if err != nil {
			return err
		}
		validator = v
	} else if c.Server.Auth.JWKS != nil {
		v, err := jwt.NewJWKSValidator(ctx, c.Server.Auth.JWKS.URL, jwt.JWKSValidatorOpts{
			Refresh: c.Server.Auth.JWKS.Refresh,
		})
		if err != nil {
			return err
		}
		validator = v
	} else {
		return fmt.Errorf("auth must be specified")
	}

	identifier := &auth.HostBasedIdentifier{}
	authenticators := []auth.Authenticator{
		// Always perform JWT based auth.
		auth.NewJWTAuthenticator(validator),
	}

	// Optionally add MCC-based authentication.
	if c.Server.Auth.MCCAuth != nil {
		checker, err := cnatix.NewMCCClusterChecker(c.Server.Auth.MCCAuth.Addr)
		if err != nil {
			return err
		}
		a := cnatix.NewClusterAuthenticator(checker, identifier)
		authenticators = append(authenticators, a)
	}

	var pr sarama.SyncProducer
	if c.Server.ActivityTracker.EnableActivityTracker {
		klog.Infof("Creating producer, addr: %+v", c.Server.ActivityTracker.BrokerAddrs)
		var err error
		pr, err = producer.NewSyncProducer(c.Server.ActivityTracker.BrokerAddrs)
		if err != nil {
			return err
		}
		defer func() {
			klog.Infof("Closing producer")
			if errClose := pr.Close(); err != nil {
				klog.Errorf("producer close error: %s", errClose)
			}
		}()
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
		Producer:           pr,
	})

	errS := make(chan error)
	go func() {
		err := server.RunHTTPServer(
			ctx,
			server.RunHTTPServerOpts{
				Server:   s,
				CertPath: c.Server.TLS.Cert,
				KeyPath:  c.Server.TLS.Key,
				Addr:     c.Server.Addr,
			},
		)
		if err != nil {
			err = fmt.Errorf("run: %s", err)
		}
		errS <- err
	}()

	// Internal admin HTTP server.
	proxies := []proxy.Proxy{httpProxy, upgradeProxy}
	adminS := admin.NewServer(c.Admin.Addr, proxies)

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
