package auth

import (
	"context"
	"fmt"
	"net/url"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/llm-operator/session-manager/common/pkg/common"
	"golang.org/x/oauth2"
)

// TokenExchangerOptions is the options for TokenExchanger.
type TokenExchangerOptions struct {
	ClientID      string
	ClientSecret  string
	BaseURL       string
	IssuerURL     string
	DexServerAddr string
	ResolverAddr  string
}

// NewTokenExchanger returns a new TokenExchanger.
func NewTokenExchanger(ctx context.Context, opts TokenExchangerOptions) (*TokenExchanger, error) {
	// Allow the issuer URL to be different from the discovery URL (= URL that is passed to oidc.newProvider()).
	// This is required since the discovery URL is the Dex server URL.
	pCtx := oidc.InsecureIssuerURLContext(ctx, opts.IssuerURL)

	provider, err := oidc.NewProvider(pCtx, fmt.Sprintf("http://%s/v1/dex", opts.DexServerAddr))
	if err != nil {
		return nil, fmt.Errorf("failed to get provider: %v", err)
	}

	baseURL, err := url.Parse(opts.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse base-url: %v", err)
	}
	baseURL.Path = common.PathLoginCallback
	if opts.ResolverAddr != "" {
		baseURL.Host = opts.ResolverAddr
	}
	redirectURL := baseURL.String()

	loginURL, err := url.Parse(provider.Endpoint().AuthURL)
	if err != nil {
		return nil, fmt.Errorf("parse auth-url: %v", err)
	}
	if opts.ResolverAddr != "" {
		loginURL.Host = opts.ResolverAddr
	}
	q := loginURL.Query()
	q.Add("client_id", opts.ClientID)
	q.Add("redirect_uri", redirectURL)
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
			RedirectURL:  redirectURL,
		},
	}, nil
}

// TokenExchanger exchanges the code for a token.
type TokenExchanger struct {
	loginURL string
	auth     *oauth2.Config
	verifier *oidc.IDTokenVerifier
}

func (t *TokenExchanger) obtainToken(ctx context.Context, code string) (string, error) {
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
