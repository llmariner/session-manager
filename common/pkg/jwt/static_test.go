package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
)

const (
	key1 = "jwt1.pub"
	key2 = "jwt2.pub"
)

func TestStaticValidator(t *testing.T) {
	// Generate a private key.
	key, b, err := newKey()
	assert.NoError(t, err)

	// Write out the public key component for the key to a file in PEM format.
	dir := t.TempDir()
	path := fmt.Sprintf("%s/%s", dir, key1)
	err = ioutil.WriteFile(path, b, 0644)
	assert.NoError(t, err)

	// Generate a token with a claim.
	claims := jwt.MapClaims{}
	claims["foo"] = "bar"

	token := jwt.New(jwt.SigningMethodRS256)
	token.Claims = claims

	signed, err := token.SignedString(key)
	assert.NoError(t, err)

	// Run the test-proper, asserting that the Validator can validate the token
	// string against the public key.

	v, err := NewStaticValidator(path)
	assert.NoError(t, err)

	got, err := v.Validate(signed)
	assert.NoError(t, err)
	assert.True(t, got.Valid)

	// Validation against a different public key fails.
	_, b, err = newKey()
	assert.NoError(t, err)

	path = fmt.Sprintf("%s/%s", dir, key2)
	err = ioutil.WriteFile(path, b, 0644)
	assert.NoError(t, err)

	v, err = NewStaticValidator(path)
	assert.NoError(t, err)

	got, err = v.Validate(signed)
	assert.Error(t, err)
	assert.False(t, got.Valid)
}

// newKey returns a pointer to a new rsa.PrivateKey and the public key in PEM
// format.
func newKey() (*rsa.PrivateKey, []byte, error) {
	// Generate a private key.
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, nil, err
	}

	// Write out the public key component for the key to a file in PEM format.
	b, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	block := &pem.Block{
		Type:  "RSA Public Key",
		Bytes: b,
	}
	b = pem.EncodeToMemory(block)

	return key, b, nil
}
