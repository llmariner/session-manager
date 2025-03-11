package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OktaTokenExchanger exchanges a code for a token with Okta directly.
type OktaTokenExchanger struct {
	config *oauth2.Config
	// The code verifier is a cryptographically random
	// string using the characters A-Z, a-z, 0-9, and the
	// punctuation characters -._~ between 43 and 128 characters long
	// (https://www.oauth.com/oauth2-servers/pkce/authorization-request/).
	codeVerifier string
	url          string
}

var _ TokenExchanger = &OktaTokenExchanger{}

// NewOktaTokenExchanger creates a new token exchanger.
func NewOktaTokenExchanger(c *oauth2.Config, state, codeVerifier string) (*OktaTokenExchanger, error) {
	sha := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(sha[:])
	url := c.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"))
	return &OktaTokenExchanger{
		config:       c,
		codeVerifier: codeVerifier,
		url:          url,
	}, nil
}

// ObtainToken obtains a token from the issuer.
func (e *OktaTokenExchanger) obtainToken(ctx context.Context, code string) (string, error) {
	token, err := e.config.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", e.codeVerifier))
	if err != nil {
		return "", fmt.Errorf("failed to get token: %v", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return "", fmt.Errorf("no id_token in token response")
	}

	ctx = oidc.ClientContext(ctx, http.DefaultClient)
	provider, err := oidc.NewProvider(ctx, strings.TrimSuffix(e.config.Endpoint.TokenURL, "/v1/token"))
	if err != nil {
		return "", fmt.Errorf("failed to get provider: %s", err)
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: e.config.ClientID})
	if _, err := verifier.Verify(ctx, rawIDToken); err != nil {
		return "", fmt.Errorf("failed to verify ID token: %v", err)
	}

	accessToken, ok := token.Extra("access_token").(string)
	if !ok {
		return "", fmt.Errorf("no access_token in token response")
	}
	return accessToken, nil
}

func (e *OktaTokenExchanger) getLoginURL() string {
	return e.url
}
