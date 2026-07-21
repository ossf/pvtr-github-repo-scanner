package data

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetPrivateVulnReporting(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		statusCode  int
		httpErr     error
		wantEnabled bool
		wantKnown   bool
	}{
		{
			name:        "enabled",
			body:        `{"enabled": true}`,
			wantEnabled: true,
			wantKnown:   true,
		},
		{
			name:        "disabled",
			body:        `{"enabled": false}`,
			wantEnabled: false,
			wantKnown:   true,
		},
		{
			name:        "not found leaves status unknown",
			body:        `{"message": "Not Found"}`,
			statusCode:  http.StatusNotFound,
			wantEnabled: false,
			wantKnown:   false,
		},
		{
			name:        "malformed body leaves status unknown",
			body:        `not json`,
			wantEnabled: false,
			wantKnown:   false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := NewPayloadWithHTTPMock(Payload{}, []byte(test.body), test.statusCode, test.httpErr)
			payload.RestData.getPrivateVulnReporting()

			assert.Equal(t, test.wantEnabled, payload.PrivateVulnReporting.Enabled)
			assert.Equal(t, test.wantKnown, payload.PrivateVulnReporting.Known)
		})
	}
}
