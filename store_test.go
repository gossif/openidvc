package openidvc_test

import (
	"testing"
	"time"

	"github.com/gossif/openidvc"
	"github.com/stretchr/testify/assert"
)

func TestStoreRequestUri(t *testing.T) {
	openidvc.SetExpirationTime(time.Second * 1)

	clientId := "http://example.com"
	requestUri := "http://example.com/redirect"
	authhReq := openidvc.AuthorizationRequest{
		ClientId:   clientId,
		RequestUri: requestUri,
	}

	err := authhReq.StoreRequestUri()
	assert.NoError(t, err)
	_, err = openidvc.GetByClientRequestUri(clientId, requestUri)
	assert.NoError(t, err)

	// test if expiration works
	time.Sleep(time.Second * 2)
	_, err = openidvc.GetByClientRequestUri(clientId, requestUri)
	assert.ErrorContains(t, err, "not found")
}
