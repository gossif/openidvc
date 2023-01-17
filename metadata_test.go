package openidvc_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gossif/openidvc"
	"github.com/stretchr/testify/assert"
)

func TestMetadataRequestHandler(t *testing.T) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://issuer.example.com//.well-known/openid-configuration", nil)

	openidvc.ProviderMetadataRequestHandler(w, req)
	resp := w.Result()
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, resp.Header.Get("Content-Type"), "application/json")
	assert.Contains(t, w.Body.String(), "https://example.com/authorize")
}
