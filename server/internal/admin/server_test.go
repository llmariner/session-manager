package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestServer_handleReady(t *testing.T) {
	s := &Server{}

	w := httptest.NewRecorder()
	r, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	assert.NoError(t, err)

	s.handleReady(w, r)
	assert.Equal(t, http.StatusOK, w.Result().StatusCode)
}
