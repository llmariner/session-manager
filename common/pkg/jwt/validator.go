package jwt

import "github.com/golang-jwt/jwt"

// Validator parses and validates a raw JWT token string.
type Validator interface {

	// Validate parses and validates a raw JWT token string, returning a pointer
	// to the verified jwt.Token.
	Validate(tokenString string) (*jwt.Token, error)
}
