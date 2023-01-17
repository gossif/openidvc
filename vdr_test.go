package openidvc_test

import (
	"testing"

	"github.com/gossif/openidvc"
	"github.com/stretchr/testify/assert"
)

type testExampleVDR struct{}

var expectedDoc map[string]interface{} = map[string]interface{}{
	"@context":        "https://www.w3.org/ns/did/v1",
	"assertionMethod": []string{"did:ebsi:zyCxHufy7JuGtpap7KezmeY#4d98ef1d2c5947a586b2226b200ade72"},
	"authentication":  []string{"did:ebsi:zyCxHufy7JuGtpap7KezmeY#4d98ef1d2c5947a586b2226b200ade72"},
	"id":              "did:ebsi:zyCxHufy7JuGtpap7KezmeY",
	"verificationMethod": []map[string]interface{}{
		{
			"id":         "did:ebsi:zyCxHufy7JuGtpap7KezmeY#4d98ef1d2c5947a586b2226b200ade72",
			"type":       "JsonWebKey2020",
			"controller": "did:ebsi:zyCxHufy7JuGtpap7KezmeY",
			"publicKeyJwk": map[string]interface{}{
				"crv": "P-256",
				"kid": "did:ebsi:zyCxHufy7JuGtpap7KezmeY#4d98ef1d2c5947a586b2226b200ade72",
				"kty": "EC",
				"x":   "nAyQZC6WAvSqnttlft7YOJrqmJx47t3-6l97XQfAGlU",
				"y":   "OWcile-qNKOsmXUsUDdYTwn39lvA_Qiml5gFMGaFraQ",
			},
		},
	},
}

func (t *testExampleVDR) ResolveDid(did string) (interface{}, error) {
	return expectedDoc, nil
}

func TestSuccesfulResolveDid(t *testing.T) {
	for scenario, fn := range map[string]func(t *testing.T){
		"resolve example": testResolveExampleMethod,
		"singleton":       testSingleton,
	} {
		t.Run(scenario, func(t *testing.T) {
			fn(t)
		})
	}
}

func testResolveExampleMethod(t *testing.T) {
	registry := openidvc.NewDecetralizedIdentifierRegistry()
	registry.RegisterMethod("example", &testExampleVDR{})

	actualDoc, err := registry.ResolveDid("did:example:123")
	assert.NoError(t, err)
	assert.Equal(t, expectedDoc, actualDoc)
}

func testSingleton(t *testing.T) {
	registry := openidvc.NewDecetralizedIdentifierRegistry()
	registry.RegisterMethod("example", &testExampleVDR{})

	secondRegistry := openidvc.NewDecetralizedIdentifierRegistry()
	actualDoc, err := secondRegistry.ResolveDid("did:example:123")
	assert.NoError(t, err)
	assert.Equal(t, expectedDoc, actualDoc)
}
