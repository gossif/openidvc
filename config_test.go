package openidvc_test

import (
	"testing"
	"time"

	"github.com/gossif/openidvc"
	"github.com/stretchr/testify/assert"
)

func TestGetServerConfig(t *testing.T) {
	serverConfig := openidvc.GetServerConfig()
	assert.Equal(t, time.Minute*10, serverConfig.ExpirationTime)
}

func TestGetProviderMetadata(t *testing.T) {
	providerMetadata := openidvc.GetProviderMetadata()
	assert.Equal(t, "https://example.com", providerMetadata.Issuer)
}
