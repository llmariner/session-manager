package jwt

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt"
)

// StaticValidator validates incoming JWTs against a public key in PEM format
// from a file.
type StaticValidator struct {
	key interface{}
}

// NewStaticValidator returns a new StaticValidator.
func NewStaticValidator(path string) (*StaticValidator, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("jwt: new validator: read key: %s", err)
	}

	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("jwt: new validator: decode key: %s", err)
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("jwt: new validator: parse key: %s", err)
	}

	return &StaticValidator{key: key}, nil
}

// Validate validates the incoming token string against the public key.
func (v *StaticValidator) Validate(tokenString string) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return v.key, nil
	})
}
