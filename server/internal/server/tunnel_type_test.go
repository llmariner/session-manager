package server

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInferTunnelType(t *testing.T) {
	tcs := []struct {
		name string
		req  *http.Request
		want tunnelType
	}{
		{
			name: "upgrade - lower case",
			req: &http.Request{
				Header: header("upgrade", "foo"),
			},
			want: tunnelTypeUpgrade,
		},
		{
			name: "upgrade - upper case",
			req: &http.Request{
				Header: header("Upgrade", "foo"),
			},
			want: tunnelTypeUpgrade,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got := inferTunnelType(tc.req)
			assert.Equal(t, tc.want, got)
		})
	}
}

// header returns a http.Header with a single key-value pair.
func header(key, value string) http.Header {
	h := http.Header{}
	h.Set(key, value)
	return h
}
