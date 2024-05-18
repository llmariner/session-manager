package jwt

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/lestrrat-go/jwx/jwk"
)

// JWKSValidator is a Validator that will use the public keys found at the given
// URL to validate against.
type JWKSValidator struct {
	ctx context.Context
	url string

	ar *jwk.AutoRefresh
}

// JWKSValidatorOpts are options for the JWKSValidator.
type JWKSValidatorOpts struct {
	Refresh time.Duration
	Client  *http.Client
}

// NewJWKSValidator returns a new JWKSValidator.
func NewJWKSValidator(ctx context.Context, url string, opts JWKSValidatorOpts) (*JWKSValidator, error) {
	var refreshOpts []jwk.AutoRefreshOption
	if opts.Refresh > 0 {
		refreshOpts = append(refreshOpts, jwk.WithRefreshInterval(opts.Refresh))
	}
	if opts.Client != nil {
		refreshOpts = append(refreshOpts, jwk.WithHTTPClient(opts.Client))
	}

	ar := jwk.NewAutoRefresh(ctx)
	ar.Configure(url, refreshOpts...)

	// Perform an initial token refresh so the keys are cached.
	_, err := ar.Refresh(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("jwt: new jwks validator: %s", err)
	}

	return &JWKSValidator{
		ctx: ctx,
		url: url,
		ar:  ar,
	}, nil
}

// Validate validates the incoming token string against the public key.
func (v *JWKSValidator) Validate(tokenString string) (*jwt.Token, error) {
	set, err := v.ar.Fetch(v.ctx, v.url)
	if err != nil {
		return nil, fmt.Errorf("jwt: validate: %s", err)
	}

	// Validate with all keys until we find a match.
	for i := 0; i < set.Len(); i++ {
		key, ok := set.Get(i)
		if !ok {
			return nil, fmt.Errorf("jwt: validate: idx %d out of range (keys = %d)", i, set.Len())
		}

		var rawKey interface{}
		if err = key.Raw(&rawKey); err != nil {
			return nil, fmt.Errorf("jwt: validate: raw: %s", err)
		}

		switch k := rawKey.(type) {
		case *rsa.PublicKey:
		default:
			return nil, fmt.Errorf("jwt: validate: unknown key type: %T", k)
		}

		t, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return rawKey, nil
		})

		if t != nil && t.Valid {
			return t, nil
		}
	}

	return nil, fmt.Errorf("jwt: validate: no key to validate")
}
