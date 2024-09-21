package auth

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// TokenExchangerOptions is the options for TokenExchanger.
type TokenExchangerOptions struct {
	ClientID     string
	ClientSecret string
	IssuerURL    string
	RedirectURI  string

	DexServerAddr string
}

// NewTokenExchanger returns a new TokenExchanger.
func NewTokenExchanger(ctx context.Context, opts TokenExchangerOptions) (*TokenExchanger, error) {
	// Allow the issuer URL to be different from the discovery URL (= URL that is passed to oidc.newProvider()).
	// This is required since the discovery URL is the Dex server URL.
	pCtx := oidc.InsecureIssuerURLContext(ctx, opts.IssuerURL)

	// Special handling for the localhost in the token URL, JWKS URL, etc. The issuer URL can be set to localhost
	// when the ingress controller does not have a publicly reachable DNS name. (A browser running in a local env
	// access Dex via port-forwarding or some other mechanism).
	//
	// When the issuer URL is set to localhost, the token URL, JWKS URL, etc. are also set to localhost. This doesn't
	// work for session manager server running inside the cluster as localhost is not a valid address for Dex.
	// The following is a hack to allow session manager server to access Dex in such a case.
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if strings.HasPrefix(addr, "localhost") {
					addr = opts.DexServerAddr
				}
				d := net.Dialer{}
				return d.DialContext(ctx, network, addr)
			},
		},
	}
	pCtx = oidc.ClientContext(pCtx, httpClient)

	provider, err := oidc.NewProvider(pCtx, fmt.Sprintf("http://%s/v1/dex", opts.DexServerAddr))
	if err != nil {
		return nil, fmt.Errorf("failed to get provider: %v", err)
	}

	loginURL, err := url.Parse(provider.Endpoint().AuthURL)
	if err != nil {
		return nil, fmt.Errorf("parse auth-url: %v", err)
	}

	q := loginURL.Query()
	q.Add("client_id", opts.ClientID)
	q.Add("redirect_uri", opts.RedirectURI)
	q.Add("response_type", "code")
	q.Add("scope", "openid email")
	loginURL.RawQuery = q.Encode()

	return &TokenExchanger{
		loginURL: loginURL.String(),
		verifier: provider.Verifier(&oidc.Config{ClientID: opts.ClientID}),
		auth: &oauth2.Config{
			ClientID:     opts.ClientID,
			ClientSecret: opts.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  opts.RedirectURI,
		},
		httpClient: httpClient,
	}, nil
}

// TokenExchanger exchanges the code for a token.
type TokenExchanger struct {
	loginURL string
	auth     *oauth2.Config
	verifier *oidc.IDTokenVerifier

	httpClient *http.Client
}

func (t *TokenExchanger) obtainToken(ctx context.Context, code string) (string, error) {
	ctx = oidc.ClientContext(ctx, t.httpClient)
	token, err := t.auth.Exchange(ctx, code)
	if err != nil {
		return "", fmt.Errorf("failed to get token: %v", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return "", fmt.Errorf("no id_token in token response")
	}
	if _, err := t.verifier.Verify(ctx, rawIDToken); err != nil {
		return "", fmt.Errorf("failed to verify ID token: %v", err)
	}

	accessToken, ok := token.Extra("access_token").(string)
	if !ok {
		return "", fmt.Errorf("no access_token in token response")
	}
	return accessToken, nil
}
