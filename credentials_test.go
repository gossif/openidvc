package openidvc_test

import (
	"crypto/rsa"
	"crypto/sha512"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gossif/openidvc"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	accessToken       string = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiaHR0cHM6Ly9leGFtcGxlLmNvbSJdLCJleHAiOjQ4MjY2MTE2NTAsImlhdCI6MTY3MzAxMTY1MCwiaXNzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbSIsIm5vbmNlIjoiTVVfVjVENTdWa2ZlZWpaX2RtZWdNMFVXYjJHeGdtdHFrYVR3d3JpQkVpYyIsInNjb3BlIjoiY3JlZGVudGlhbF9pc3N1YW5jZSIsInN1YiI6Imh0dHBzOi8vaG9sZGVyLmV4YW1wbGUuY29tIn0.PaNBN8QNZaPPSD2AmlRya_rdkx2yIfhUmOKgVel7Cez6Ul-ieSKrczMmcEWBaMX6Eo_BTnCK8Csbxb6hfNMJXV-NC-mwRNvi_8HU6l0sIU0HzFftYBFowRQmthGLgWZzt7KJILV_ckh0oots39A-7M6LsMrQ4Pp5MeOhm3JZheP3fx1DoqMsf4wMWAkm3wVuWbbWDV8o4p_Xu8UVYAyr-qS5bF9L7FfSUIVaKk-tWddwmBc_zgUj6e4qTS3OtutlmZ-gCF8LkctF4Dawj6R_wovMcG_uo3nGxhoMi1oajG3mh2qZa3EMiMYZR1hRK6e73ptPqLwb7qda7-kZnJ4CrQ"
	rsaPrivateKeyJson string = `{
		"d": "irgBfC7floWMzNuh_CYx_hdlgETeGZg6kwmdaxTDoJmRU9iT9F0htTK_gX2qbbpwxv-y1-l1krnjwWniTOqJ5qay5tiSQqWmLfjNzD3KpDJO05kv94xly49ygwweoADiWht56ZqDNzAXQE3ZHgaKg1NNbULEss1vIUQX71VQ5agf-smmYLUsZaUfD94YxjcAduaoDtKbOKrdkjHsN4OT_nmq-AxR7-sg0f3-Gu8onMLa2ee76McPNuShQFAemlhWn4Kt7eJVKFHe8Y27v08x9RqxMeKd52jtuJzxeBeVLhuqsel75K6svV-W8TrK4TgAyQ7O2OBrSwRsDoR8HNIroQ",
		"dp": "B7p3xtvdVSs_HMIa2-oUHPrF9B_Kr8ehlBKviJerwuBAypsMrPwRg2-O2OFRTQ7MXvnSkv5D9SrS3hNlIqw4XE4iZem0lllmxUfaVNL8t9yk1uOCL2sv6okko0oIg3-mXiZ1PXSsclIvFeALSZUWZIrBS0XNIy-kUNbQiWmU19U",
		"dq": "NsjCaJ9nNaaPp7a2Pt0HLGpoQRzLOywy3h84ykZEtO6xTONKAYH0UEuY015pakWJM6zwXDlOsvCht4H_THmg3K0G8r17Ea_07V3cUhDx4ho7R_cD5NvBRGeIH5eADZFtWyiV3rYwEDZRAi72I3S5c_09Nsibef5-C6n9kXu7z2U",
		"e": "AQAB",
		"kty": "RSA",
		"n": "tEfyIcAtMDZv-wHCwWWffHawAyOhCl4zg1dhOsHBR_ieSzlIYEG92rMqPPHd0lX4AbVIWVQTOxvKnIx01e4LF9zg0UsJdW4f5ipWU63_e2z_pOgTvciM9xy5NHwJ48Wcg9ESkLlrfT63xd52HtKzHCdRC3lW4LgQpPvX5HNr5t9o9-oUxsQExm5Sph3anRXpRnIG9nQhj1vcJ3GU8yb9mMQzOHkwuDl3vNXddk5NNpGPi2Qza7_Z98ryeU564AkbUaTiDJru0c8TPeD5zJv9MqrluzoBCyOfGy2MgjPxjtmAsq84qA1B0ciYQkfNXlT8uEEgLTxw_ChIzNxufHJ5lw",
		"p": "05GXWLeE7CwWPibiD3-uoSMslJxsmWCZho0cXgRQr80QWIY7dX48Qfxk_hfCO3dG-uNLJ6fGMeowbiuLcv34yN_-uMsDpD_aN-LfWcBuqRnz-TGEsoM-a3maPrwuyXssdpI4c7F__9qCdz7JozisH8ZztJ8pYdIt0bYmF8CCLtM",
		"q": "2iRCR9sKo78xK3qEQ044e5V_fK4VXtKZXY64ZeTTxKMpuW0PxLVSy_idI7cYkfDHusmrz0-6QrckAlwXTpOgWU7mCX6W49kYDRvKLsY_ec24dKCDVZZMXyO0RT1argIBWMO-ua6iczp8WEhsap6B4qUrQWakwVVQLql2VzcAt60",
		"qi": "DFz_lBXhrZc9l-6LukocWdb6SfgvNRx5UHWHMTyTF1AOMsfBRA9d1jCtG1KMlDDHlqJq6O0Ru27ULkC3t148WU08bh1JB1GWve7Zmj7rGg8Moo-uN4XAylh7Fvmt0yPxqoS0zNjDVzeIcyCPiYrpHy8wafA1rxqJlgdXZjvRWLA"
	  }`
	cnonce string = "MU_V5D57VkfeejZ_dmegM0UWb2GxgmtqkaTwwriBEic"
)

func TestCredentialRequest(t *testing.T) {
	for scenario, fn := range map[string]func(t *testing.T){
		"new request":              testNewCredentialRequest,
		"request for legal entity": testNewCredentialRequestLegalEntity,
		"deferred response":        testDeferredCredentialResponse,
		"new deferred request":     testNewDeferredCredentialRequest,
		"invalid nonce":            testInvalidNonce,
	} {
		t.Run(scenario, func(t *testing.T) {
			fn(t)
		})
	}
}

func testNewCredentialRequest(t *testing.T) {
	var rsaPrivateKey rsa.PrivateKey

	credRequest := openidvc.CredentialRequest{
		ClientId:             "https://holder.example.com",
		AuthorizationDetails: string(`[{"format":"jwt_vc_json","type":"openid_credential","types":["VerifiableCredential","UniversityDegreeCredential"]}]`),
		CNonceExpiresIn:      time.Minute * 5,
		BearerTokenExpiresIn: time.Minute * 5,
		CNonce:               cnonce,
	}
	accessToken := accessToken
	credRequest.BearerTokenSHA512 = sha512.Sum512([]byte(accessToken))

	// Store the bearer token, so we can verify it up when the credential requests arrives
	require.NoError(t, credRequest.StoreCredentialRequest())
	require.NoError(t, jwk.ParseRawKey([]byte(rsaPrivateKeyJson), &rsaPrivateKey))

	jsonCredentialRequest := `{"format":"jwt_vc_json","proof":{"jwt":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiaHR0cHM6Ly9leGFtcGxlLmNvbSJdLCJleHAiOjQ4MjY2MTM2NDksImlhdCI6MTY3MzAxMzY0OSwiaXNzIjoiaHR0cHM6Ly9ob2xkZXIuZXhhbXBsZS5jb20iLCJqd2siOiJ7XCJjcnZcIjpcIlAtMjU2XCIsXCJrdHlcIjpcIkVDXCIsXCJ4XCI6XCJuQXlRWkM2V0F2U3FudHRsZnQ3WU9KcnFtSng0N3QzLTZsOTdYUWZBR2xVXCIsXCJ5XCI6XCJPV2NpbGUtcU5LT3NtWFVzVURkWVR3bjM5bHZBX1FpbWw1Z0ZNR2FGcmFRXCJ9Iiwibm9uY2UiOiJNVV9WNUQ1N1ZrZmVlalpfZG1lZ00wVVdiMkd4Z210cWthVHd3cmlCRWljIn0.3K9CNdEn_qzNWdhz0HxBqbuP_d1q9lbnwuhFlSBOdGbSI3Qz_X3Ag4yvo68wemoZRjdyivYYUHlGzv3pQOAquA","proof_type":"jwt"},"types":["VerifiableCredential","UniversityDegreeCredential"]}`

	req := httptest.NewRequest(http.MethodPost, "https://issuer.example.com/credential", strings.NewReader(string(jsonCredentialRequest)))
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	_, err := openidvc.NewIssuer().NewCredentialRequest(req, openidvc.WithAccessTokenSigningKey(jwa.RS256, rsaPrivateKey.PublicKey))
	assert.NoError(t, err)
}

func testNewCredentialRequestLegalEntity(t *testing.T) {
	var rsaPrivateKey rsa.PrivateKey

	registry := openidvc.NewDecetralizedIdentifierRegistry()
	registry.RegisterMethod("ebsi", &testExampleVDR{})

	credRequest := openidvc.CredentialRequest{
		ClientId:             "https://holder.example.com",
		AuthorizationDetails: string(`[{"format":"jwt_vc_json","type":"openid_credential","types":["VerifiableCredential","UniversityDegreeCredential"]}]`),
		CNonceExpiresIn:      time.Minute * 5,
		BearerTokenExpiresIn: time.Minute * 5,
		CNonce:               cnonce,
	}
	accessToken := accessToken
	credRequest.BearerTokenSHA512 = sha512.Sum512([]byte(accessToken))

	// Store the bearer token, so we can verify it up when the credential requests arrives
	require.NoError(t, credRequest.StoreCredentialRequest())
	require.NoError(t, jwk.ParseRawKey([]byte(rsaPrivateKeyJson), &rsaPrivateKey))

	jsonCredentialRequest := `{"format":"jwt_vc_json","proof":{"jwt":"eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDplYnNpOnp5Q3hIdWZ5N0p1R3RwYXA3S2V6bWVZIzRkOThlZjFkMmM1OTQ3YTU4NmIyMjI2YjIwMGFkZTcyIiwidHlwIjoiSldUIn0.eyJhdWQiOlsiaHR0cHM6Ly9leGFtcGxlLmNvbSJdLCJleHAiOjQ4MjY3NzIxMjksImlhdCI6MTY3MzE3MjEyOSwiaXNzIjoiaHR0cHM6Ly9ob2xkZXIuZXhhbXBsZS5jb20iLCJub25jZSI6Ik1VX1Y1RDU3VmtmZWVqWl9kbWVnTTBVV2IyR3hnbXRxa2FUd3dyaUJFaWMifQ.Sbb9jtUk6DRsrKoM63peJeHpqCKQMgSFAwYe4LTn5_h8wi0PZRFzkWUfVEFUvBZ-i9W715T0j3diMYQAe7xuUw","proof_type":"jwt"},"types":["VerifiableCredential","UniversityDegreeCredential"]}`

	req := httptest.NewRequest(http.MethodPost, "https://issuer.example.com/credential", strings.NewReader(jsonCredentialRequest))
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	_, err := openidvc.NewIssuer().NewCredentialRequest(req, openidvc.WithAccessTokenSigningKey(jwa.RS256, rsaPrivateKey.PublicKey))
	assert.NoError(t, err)
}

func testDeferredCredentialResponse(t *testing.T) {
	var rsaPrivateKey rsa.PrivateKey

	credRequest := openidvc.CredentialRequest{
		ClientId:             "https://holder.example.com",
		AuthorizationDetails: string(`[{"format":"jwt_vc_json","type":"openid_credential","types":["VerifiableCredential","UniversityDegreeCredential"]}]`),
		CNonceExpiresIn:      time.Minute * 5,
		BearerTokenExpiresIn: time.Minute * 5,
		CNonce:               cnonce,
	}
	accessToken := accessToken
	credRequest.BearerTokenSHA512 = sha512.Sum512([]byte(accessToken))

	// Store the bearer token, so we can verify it up when the credential requests arrives
	require.NoError(t, credRequest.StoreCredentialRequest())
	require.NoError(t, jwk.ParseRawKey([]byte(rsaPrivateKeyJson), &rsaPrivateKey))

	credResponse, err := credRequest.CreateCredentialResponse(
		openidvc.WithCredentialDeferred(),
		openidvc.WithAcceptanceTokenSigningKey(jwa.RS256, rsaPrivateKey),
	)
	require.NoError(t, err)
	assert.NotEmpty(t, credResponse.AcceptanceToken)
	assert.NotEmpty(t, credResponse.CNonce)
	assert.NotEmpty(t, credResponse.CNonceExpiresIn)
}

func testNewDeferredCredentialRequest(t *testing.T) {
	var rsaPrivateKey rsa.PrivateKey

	credRequest := openidvc.CredentialRequest{
		ClientId:             "https://holder.example.com",
		AuthorizationDetails: string(`[{"format":"jwt_vc_json","type":"openid_credential","types":["VerifiableCredential","UniversityDegreeCredential"]}]`),
		CNonceExpiresIn:      time.Minute * 5,
		BearerTokenExpiresIn: time.Minute * 5,
		CNonce:               cnonce,
		Deferred:             true,
	}
	accessToken := accessToken
	credRequest.BearerTokenSHA512 = sha512.Sum512([]byte(accessToken))

	// Store the bearer token, so we can verify it up when the credential requests arrives
	require.NoError(t, credRequest.StoreCredentialRequest())
	require.NoError(t, jwk.ParseRawKey([]byte(rsaPrivateKeyJson), &rsaPrivateKey))

	jsonCredentialRequest := `{"format":"jwt_vc_json","proof":{"jwt":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiaHR0cHM6Ly9leGFtcGxlLmNvbSJdLCJleHAiOjQ4MjY2MTM2NDksImlhdCI6MTY3MzAxMzY0OSwiaXNzIjoiaHR0cHM6Ly9ob2xkZXIuZXhhbXBsZS5jb20iLCJqd2siOiJ7XCJjcnZcIjpcIlAtMjU2XCIsXCJrdHlcIjpcIkVDXCIsXCJ4XCI6XCJuQXlRWkM2V0F2U3FudHRsZnQ3WU9KcnFtSng0N3QzLTZsOTdYUWZBR2xVXCIsXCJ5XCI6XCJPV2NpbGUtcU5LT3NtWFVzVURkWVR3bjM5bHZBX1FpbWw1Z0ZNR2FGcmFRXCJ9Iiwibm9uY2UiOiJNVV9WNUQ1N1ZrZmVlalpfZG1lZ00wVVdiMkd4Z210cWthVHd3cmlCRWljIn0.3K9CNdEn_qzNWdhz0HxBqbuP_d1q9lbnwuhFlSBOdGbSI3Qz_X3Ag4yvo68wemoZRjdyivYYUHlGzv3pQOAquA","proof_type":"jwt"},"types":["VerifiableCredential","UniversityDegreeCredential"]}`

	req := httptest.NewRequest(http.MethodPost, "https://issuer.example.com/deferred", strings.NewReader(string(jsonCredentialRequest)))
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")

	_, err := openidvc.NewIssuer().NewDeferredCredentialRequest(req, openidvc.WithAccessTokenSigningKey(jwa.RS256, rsaPrivateKey.PublicKey))
	assert.NoError(t, err)
}

func testInvalidNonce(t *testing.T) {
	var rsaPrivateKey rsa.PrivateKey

	credRequest := openidvc.CredentialRequest{
		ClientId:             "https://holder.example.com",
		AuthorizationDetails: string(`[{"format":"jwt_vc_json","type":"openid_credential","types":["VerifiableCredential","UniversityDegreeCredential"]}]`),
		CNonceExpiresIn:      time.Minute * 5,
		BearerTokenExpiresIn: time.Minute * 5,
		CNonce:               "wrongcnonce",
	}
	accessToken := accessToken
	credRequest.BearerTokenSHA512 = sha512.Sum512([]byte(accessToken))

	// Store the bearer token, so we can verify it up when the credential requests arrives
	require.NoError(t, credRequest.StoreCredentialRequest())
	require.NoError(t, jwk.ParseRawKey([]byte(rsaPrivateKeyJson), &rsaPrivateKey))

	jsonCredentialRequest := `{"format":"jwt_vc_json","proof":{"jwt":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiaHR0cHM6Ly9leGFtcGxlLmNvbSJdLCJleHAiOjQ4MjY2MTM2NDksImlhdCI6MTY3MzAxMzY0OSwiaXNzIjoiaHR0cHM6Ly9ob2xkZXIuZXhhbXBsZS5jb20iLCJqd2siOiJ7XCJjcnZcIjpcIlAtMjU2XCIsXCJrdHlcIjpcIkVDXCIsXCJ4XCI6XCJuQXlRWkM2V0F2U3FudHRsZnQ3WU9KcnFtSng0N3QzLTZsOTdYUWZBR2xVXCIsXCJ5XCI6XCJPV2NpbGUtcU5LT3NtWFVzVURkWVR3bjM5bHZBX1FpbWw1Z0ZNR2FGcmFRXCJ9Iiwibm9uY2UiOiJNVV9WNUQ1N1ZrZmVlalpfZG1lZ00wVVdiMkd4Z210cWthVHd3cmlCRWljIn0.3K9CNdEn_qzNWdhz0HxBqbuP_d1q9lbnwuhFlSBOdGbSI3Qz_X3Ag4yvo68wemoZRjdyivYYUHlGzv3pQOAquA","proof_type":"jwt"},"types":["VerifiableCredential","UniversityDegreeCredential"]}`

	req := httptest.NewRequest(http.MethodPost, "https://issuer.example.com/credential", strings.NewReader(string(jsonCredentialRequest)))
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	_, err := openidvc.NewIssuer().NewCredentialRequest(req, openidvc.WithAccessTokenSigningKey(jwa.RS256, rsaPrivateKey.PublicKey))
	assert.ErrorContains(t, err, "invalid_token")
}

// generateAccessToken generates the access token for the token response
// but also the acceptance token for a deferred credential request, acceptance token is used as access token
func createBearerToken() ([]byte, error) {
	var rsaPrivateKey rsa.PrivateKey
	err := jwk.ParseRawKey([]byte(rsaPrivateKeyJson), &rsaPrivateKey)
	if err != nil {
		fmt.Println(err)
	}
	//publicKey := privateKey.PublicKey
	//publicKeyJwk, _ := jwk.FromRaw(publicKey)
	//publicKeyBytes, _ := json.Marshal(publicKeyJwk)

	//jwkKey, _ := jwk.FromRaw(rsaPrivateKey)
	//jwkBytes, _ := json.Marshal(jwkKey)
	accessToken, err := jwt.NewBuilder().
		Issuer("https://holder.example.com").
		Audience([]string{"https://example.com"}).
		Subject("https://holder.example.com").
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Second*1)).
		Claim("nonce", "MU_V5D57VkfeejZ_dmegM0UWb2GxgmtqkaTwwriBEic").
		Claim("scope", "credential_issuance").
		Build()
	if err != nil {
		return nil, err
	}
	serialized, err := jwt.Sign(accessToken, jwt.WithKey(jwa.RS256, rsaPrivateKey))
	if err != nil {
		return nil, err
	}
	return serialized, nil
}
