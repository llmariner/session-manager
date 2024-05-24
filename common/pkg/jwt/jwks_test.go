package jwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"gopkg.in/square/go-jose.v2"
)

const (
	keysPath     = "/keys"
	waitInterval = 500 * time.Millisecond
)

var (
	keysURL = fmt.Sprintf("http://_%s", keysPath)

	dialFunc = func(path string) func(context.Context, string, string) (net.Conn, error) {
		return func(_ context.Context, _, addr string) (net.Conn, error) {
			return net.Dial("unix", path)
		}
	}
)

func TestJWKSValidator_SingleKeypair(t *testing.T) {
	// Generate a single keypair.
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	assert.NoError(t, err)

	// Sign a token with the private key.
	claims := jwt.MapClaims{}
	claims["foo"] = "bar"

	token := jwt.New(jwt.SigningMethodRS256)
	token.Claims = claims

	signed, err := token.SignedString(key)
	assert.NoError(t, err)

	jwks := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Algorithm: string(jose.RS256),
				Key:       &key.PublicKey,
			},
		},
	}
	assertSignedBy(t, jwks, signed)
}

func TestJWKSValidator_MultiKeypair(t *testing.T) {
	// Generate three keys.
	keys := make([]*rsa.PrivateKey, 3)
	for i := 0; i < 3; i++ {
		key, err := rsa.GenerateKey(rand.Reader, 1024)
		assert.NoError(t, err)
		keys[i] = key
	}

	// Sign a token with last of the keys.
	claims := jwt.MapClaims{}
	claims["foo"] = "bar"

	token := jwt.New(jwt.SigningMethodRS256)
	token.Claims = claims

	signed, err := token.SignedString(keys[len(keys)-1])
	assert.NoError(t, err)

	var webKeys []jose.JSONWebKey
	for _, key := range keys {
		webKeys = append(webKeys, jose.JSONWebKey{
			Algorithm: string(jose.RS256),
			Key:       &key.PublicKey,
		})
	}

	jwks := &jose.JSONWebKeySet{Keys: webKeys}
	assertSignedBy(t, jwks, signed)
}

// assertSignedBy asserts that the given token string was signed by a public
// key contained in the given JWKS.
func assertSignedBy(t *testing.T, jwks *jose.JSONWebKeySet, tokenString string) {
	// Start a webserver that will server up the JWKs on a well-known endpoint.
	//
	// Do not use t.TempDir() as the path name can be too long for Unix domain socket.
	dir, err := os.MkdirTemp("./", "socket")
	assert.NoError(t, err)
	defer func() {
		_ = os.RemoveAll(dir)
	}()

	path := dir + "/server.sock"

	ctx := context.Background()
	s, err := setupJWKSServer(path, jwks)
	assert.NoError(t, err)
	defer func() { _ = s.shutdown(ctx) }()

	// Validate the key with a validator that pulls the public keys from the
	// server.
	v, err := NewJWKSValidator(context.Background(), keysURL, JWKSValidatorOpts{
		Client: &http.Client{
			Transport: &http.Transport{
				DialContext: dialFunc(path),
			},
		},
	})
	assert.NoError(t, err)

	token, err := v.Validate(tokenString)
	assert.NoError(t, err)
	assert.True(t, token.Valid)
}

// setupJWKSServer starts a new http.Server that will serve up the given JWKS
// on a domain socket at the given path.
func setupJWKSServer(socketPath string, jwks *jose.JSONWebKeySet) (*testJWKSServer, error) {
	s := newTestServer(socketPath, jwks)
	go func() {
		if err := s.run(); err != nil && err != http.ErrServerClosed {
			panic(err)
		}
	}()

	// Wait on the server to become ready in a separate goroutine.
	readyC := make(chan error)
	go func() {
		c := &http.Client{
			Transport: &http.Transport{
				DialContext: dialFunc(socketPath),
			},
		}

		attempts := 0
		for {
			resp, err := c.Get(keysURL)
			if resp != nil && resp.StatusCode == http.StatusOK {
				break
			}
			attempts++
			if attempts == 5 {
				readyC <- fmt.Errorf("timed out waiting: %s", err)
				break
			}
			time.Sleep(waitInterval)
		}
		close(readyC)
	}()

	// Block until ready, or error.
	err := <-readyC

	return s, err
}

// testJWKSServer is HTTP server that serves up a set of JWKs.
type testJWKSServer struct {
	socketPath string
	keySet     *jose.JSONWebKeySet
	srv        *http.Server
}

// newTestServer returns a new testJWKSServer.
func newTestServer(socketPath string, jwks *jose.JSONWebKeySet) *testJWKSServer {
	s := &testJWKSServer{
		socketPath: socketPath,
		keySet:     jwks,
	}

	m := http.NewServeMux()
	m.HandleFunc(keysPath, s.handleJWKs)
	s.srv = &http.Server{Handler: m}

	return s
}

// run starts the testJWKSServer. This method is blocking.
func (s *testJWKSServer) run() error {
	l, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return err
	}
	return s.srv.Serve(l)
}

// shutdown stops the testJWKSServer.
func (s *testJWKSServer) shutdown(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}

// handleJWKs is a HTTP handler that returns the JSON representation of this
// server's jose.JSONWebKeySet.
func (s *testJWKSServer) handleJWKs(w http.ResponseWriter, _ *http.Request) {
	b, err := json.Marshal(s.keySet)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_, err = w.Write(b)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
