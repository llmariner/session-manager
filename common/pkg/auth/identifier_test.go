package auth

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestURLIdentifier_Identify(t *testing.T) {
	id := "test-id"
	tcs := []struct {
		name string
		req  *http.Request
		err  error
		want string
	}{
		{
			name: "simple subdomain",
			req:  newRequest(fmt.Sprintf("https://%s.example.com", id)),
			want: id,
		},
		{
			name: "complex subdomain",
			req:  newRequest(fmt.Sprintf("https://%s.level-1.level-2.example.com", id)),
			want: id,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			i := &HostBasedIdentifier{}
			got, err := i.Identify(tc.req)
			if err != nil {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// newRequest constructs a new http.Request.
func newRequest(url string) *http.Request {
	r, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		panic(fmt.Errorf("could not construct request: %s", err))
	}
	return r
}
