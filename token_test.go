package openidvc_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/gorilla/schema"
	"github.com/gossif/openidvc"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenValidatorShouldError(t *testing.T) {
	type errorTestCases struct {
		description   string
		testFieldName string
		testWithValue string
		expectedError string
	}
	for _, scenario := range []errorTestCases{
		{description: "missing response type", testFieldName: "GrantType", testWithValue: "", expectedError: "missing_grant_type"},
		{description: "unsupported response type", testFieldName: "GrantType", testWithValue: "foo", expectedError: "unsupported_grant_type"},
		{description: "missing code", testFieldName: "Code", testWithValue: "", expectedError: "missing_code"},
		{description: "missing redirect uri", testFieldName: "RedirectUri", testWithValue: "", expectedError: "missing_redirect_uri"},
		{description: "invalid redirect uri", testFieldName: "RedirectUri", testWithValue: "wallet.example.com/oauth2", expectedError: "invalid_redirect_uri"},
		{description: "missing client id", testFieldName: "ClientId", testWithValue: "", expectedError: "missing_client_id"},
		{description: "missing code verifier", testFieldName: "CodeVerifier", testWithValue: "", expectedError: "missing_code_verifier"},
	} {
		t.Run(scenario.description, func(t *testing.T) {
			tokenRequest := openidvc.TokenRequest{
				GrantType:    "authorization_code",
				Code:         "examplecode",
				ClientId:     "https://wallet.example.com",
				RedirectUri:  "https://wallet.example.com/oauth2",
				CodeVerifier: s256Challenge,
			}
			v := reflect.ValueOf(&tokenRequest).Elem().FieldByName(scenario.testFieldName)
			require.True(t, v.IsValid())
			v.SetString(scenario.testWithValue)

			err := tokenRequest.Validate()
			require.Error(t, err)
			assert.Equal(t, scenario.expectedError, err.Error())
		})
	}
}

func TestNewTokenRequestWithCodeChallenge(t *testing.T) {
	for scenario, fn := range map[string]func(t *testing.T){
		"succesful plain": testSuccesfulTokenRequestPlain,
		"succesful S256":  testSuccesfulTokenRequestS256,
		"invalid S256":    testInvalidTokenRequestS256,
	} {
		t.Run(scenario, func(t *testing.T) {
			fn(t)
		})
	}
}

func testSuccesfulTokenRequestPlain(t *testing.T) {
	authReq := openidvc.AuthorizationRequest{
		ResponseType:         "code",
		Scope:                "openid",
		ClientId:             "https://holder.example.com",
		RedirectUri:          "https://holder.example.com/redirect",
		State:                "123",
		AuthorizationDetails: string(`[{"format":"jwt_vc_json","type":"openid_credential","types":["VerifiableCredential","UniversityDegreeCredential"]}]`),
		CodeChallenge:        plainChallenge,
		CodeChallengeMethod:  "plain",
	}
	require.NoError(t, authReq.StoreClientRedirectUri())

	authResponse := openidvc.AuthorizationResponse{
		Code:  base64.RawURLEncoding.EncodeToString([]byte("msHyXWOZNxvsFcK87Sm8yqdcxn4TOWTKz7rPhzvr")),
		State: authReq.State,
	}
	require.NoError(t, authResponse.StoreCodeGranted())

	tokenRequest := openidvc.TokenRequest{
		GrantType:    "authorization_code",
		Code:         base64.RawURLEncoding.EncodeToString([]byte("msHyXWOZNxvsFcK87Sm8yqdcxn4TOWTKz7rPhzvr")),
		ClientId:     "https://holder.example.com",
		RedirectUri:  "https://holder.example.com/redirect",
		CodeVerifier: plainChallenge,
	}
	params := url.Values{}
	decoder := schema.NewEncoder()
	err := decoder.Encode(tokenRequest, params)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "https://issuer.example.com/token", strings.NewReader(params.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	_, err = openidvc.NewOpenIdProvider().NewTokenRequest(req)
	assert.NoError(t, err)
}

func testSuccesfulTokenRequestS256(t *testing.T) {
	authReq := openidvc.AuthorizationRequest{
		ResponseType:         "code",
		Scope:                "openid",
		ClientId:             "https://holder.example.com",
		RedirectUri:          "https://holder.example.com/redirect",
		State:                "123",
		AuthorizationDetails: string(`[{"format":"jwt_vc_json","type":"openid_credential","types":["VerifiableCredential","UniversityDegreeCredential"]}]`),
		CodeChallenge:        s256ChallengeHash,
		CodeChallengeMethod:  "S256",
	}
	require.NoError(t, authReq.StoreClientRedirectUri())

	authResponse := openidvc.AuthorizationResponse{
		Code:  base64.RawURLEncoding.EncodeToString([]byte("msHyXWOZNxvsFcK87Sm8yqdcxn4TOWTKz7rPhzvr")),
		State: authReq.State,
	}
	require.NoError(t, authResponse.StoreCodeGranted())

	tokenRequest := openidvc.TokenRequest{
		GrantType:    "authorization_code",
		Code:         base64.RawURLEncoding.EncodeToString([]byte("msHyXWOZNxvsFcK87Sm8yqdcxn4TOWTKz7rPhzvr")),
		ClientId:     "https://holder.example.com",
		RedirectUri:  "https://holder.example.com/redirect",
		CodeVerifier: s256Challenge,
	}
	params := url.Values{}
	decoder := schema.NewEncoder()
	err := decoder.Encode(tokenRequest, params)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "https://issuer.example.com/token", strings.NewReader(params.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	_, err = openidvc.NewOpenIdProvider().NewTokenRequest(req)
	assert.NoError(t, err)
}

func testInvalidTokenRequestS256(t *testing.T) {
	authReq := openidvc.AuthorizationRequest{
		ResponseType:         "code",
		Scope:                "openid",
		ClientId:             "https://holder.example.com",
		RedirectUri:          "https://holder.example.com/redirect",
		State:                "123",
		AuthorizationDetails: string(`[{"format":"jwt_vc_json","type":"openid_credential","types":["VerifiableCredential","UniversityDegreeCredential"]}]`),
		CodeChallenge:        s256ChallengeHash,
		CodeChallengeMethod:  "S256",
	}
	require.NoError(t, authReq.StoreClientRedirectUri())

	authResponse := openidvc.AuthorizationResponse{
		Code:  base64.RawURLEncoding.EncodeToString([]byte("msHyXWOZNxvsFcK87Sm8yqdcxn4TOWTKz7rPhzvr")),
		State: authReq.State,
	}
	require.NoError(t, authResponse.StoreCodeGranted())

	tokenRequest := openidvc.TokenRequest{
		GrantType:    "authorization_code",
		Code:         base64.RawURLEncoding.EncodeToString([]byte("msHyXWOZNxvsFcK87Sm8yqdcxn4TOWTKz7rPhzvr")),
		ClientId:     "https://holder.example.com",
		RedirectUri:  "https://holder.example.com/redirect",
		CodeVerifier: "somethingelse",
	}
	params := url.Values{}
	decoder := schema.NewEncoder()
	err := decoder.Encode(tokenRequest, params)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "https://issuer.example.com/token", strings.NewReader(params.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	_, err = openidvc.NewOpenIdProvider().NewTokenRequest(req)
	assert.ErrorContains(t, err, "invalid_code_verifier")
}

func TestNewTokenRequest(t *testing.T) {
	for scenario, fn := range map[string]func(t *testing.T){
		"succesful plain":              testSuccesfulTokenRequest,
		"succesful S256":               testSuccesfulTokenRequestS256,
		"invalid content header":       testInvalidContentHeader,
		"invalid authorization header": testInvalidAuthorizationHeader, // reject when the code is communicated through the header
		"invalid client redirect uri":  testInvalidClientRedirectUri,
		"invalid coder":                testInvalidCode,
		//"invalid code verifierr":       testInvalidCodeVerifier,
	} {
		t.Run(scenario, func(t *testing.T) {
			authReq := openidvc.AuthorizationRequest{
				ResponseType:         "code",
				Scope:                "openid",
				ClientId:             "https://holder.example.com",
				RedirectUri:          "https://holder.example.com/redirect",
				State:                "123",
				AuthorizationDetails: string(`[{"format":"jwt_vc_json","type":"openid_credential","types":["VerifiableCredential","UniversityDegreeCredential"]}]`),
				CodeChallenge:        plainChallenge,
				CodeChallengeMethod:  "plain",
			}
			require.NoError(t, authReq.StoreClientRedirectUri())

			authResponse := openidvc.AuthorizationResponse{
				Code:  base64.RawURLEncoding.EncodeToString([]byte("msHyXWOZNxvsFcK87Sm8yqdcxn4TOWTKz7rPhzvr")),
				State: authReq.State,
			}
			require.NoError(t, authResponse.StoreCodeGranted())

			fn(t)
		})
	}
}

func testSuccesfulTokenRequest(t *testing.T) {
	tokenRequest := openidvc.TokenRequest{
		GrantType:    "authorization_code",
		Code:         base64.RawURLEncoding.EncodeToString([]byte("msHyXWOZNxvsFcK87Sm8yqdcxn4TOWTKz7rPhzvr")),
		ClientId:     "https://holder.example.com",
		RedirectUri:  "https://holder.example.com/redirect",
		CodeVerifier: plainChallenge,
	}
	params := url.Values{}
	decoder := schema.NewEncoder()
	err := decoder.Encode(tokenRequest, params)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "https://issuer.example.com/token", strings.NewReader(params.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	_, err = openidvc.NewOpenIdProvider().NewTokenRequest(req)
	assert.NoError(t, err)
}

func testInvalidContentHeader(t *testing.T) {
	tokenRequest := openidvc.TokenRequest{
		GrantType:    "authorization_code",
		Code:         base64.RawURLEncoding.EncodeToString([]byte("msHyXWOZNxvsFcK87Sm8yqdcxn4TOWTKz7rPhzvr")),
		ClientId:     "https://holder.example.com",
		RedirectUri:  "https://holder.example.com/redirect",
		CodeVerifier: plainChallenge,
	}
	params := url.Values{}
	decoder := schema.NewEncoder()
	err := decoder.Encode(tokenRequest, params)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "https://issuer.example.com/token", strings.NewReader(params.Encode()))
	req.Header.Set("Content-Type", "application/json")

	_, err = openidvc.NewOpenIdProvider().NewTokenRequest(req)
	assert.ErrorContains(t, err, "invalid_content_type")
}

func testInvalidAuthorizationHeader(t *testing.T) {
	tokenRequest := openidvc.TokenRequest{
		GrantType:    "authorization_code",
		Code:         base64.RawURLEncoding.EncodeToString([]byte("msHyXWOZNxvsFcK87Sm8yqdcxn4TOWTKz7rPhzvr")),
		ClientId:     "https://holder.example.com",
		RedirectUri:  "https://holder.example.com/redirect",
		CodeVerifier: plainChallenge,
	}
	params := url.Values{}
	decoder := schema.NewEncoder()
	err := decoder.Encode(tokenRequest, params)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "https://issuer.example.com/token", strings.NewReader(params.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+base64.RawURLEncoding.EncodeToString([]byte("msHyXWOZNxvsFcK87Sm8yqdcxn4TOWTKz7rPhzvr")))

	_, err = openidvc.NewOpenIdProvider().NewTokenRequest(req)
	assert.ErrorContains(t, err, "invalid_request")
}

func testInvalidClientRedirectUri(t *testing.T) {
	tokenRequest := openidvc.TokenRequest{
		GrantType:    "authorization_code",
		Code:         base64.RawURLEncoding.EncodeToString([]byte("msHyXWOZNxvsFcK87Sm8yqdcxn4TOWTKz7rPhzvr")),
		ClientId:     "https://holder.example.com",
		RedirectUri:  "https://holder.example.com/wrongredirect",
		CodeVerifier: plainChallenge,
	}
	params := url.Values{}
	decoder := schema.NewEncoder()
	err := decoder.Encode(tokenRequest, params)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "https://issuer.example.com/token", strings.NewReader(params.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	_, err = openidvc.NewOpenIdProvider().NewTokenRequest(req)
	assert.ErrorContains(t, err, "invalid_client_redirect_uri")
}

func testInvalidCode(t *testing.T) {
	tokenRequest := openidvc.TokenRequest{
		GrantType:    "authorization_code",
		Code:         "msHyXWOZNxvsFcK87Sm8yqdcxn4TOWTKz7rPhzvr",
		ClientId:     "https://holder.example.com",
		RedirectUri:  "https://holder.example.com/redirect",
		CodeVerifier: plainChallenge,
	}
	params := url.Values{}
	decoder := schema.NewEncoder()
	err := decoder.Encode(tokenRequest, params)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "https://issuer.example.com/token", strings.NewReader(params.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	_, err = openidvc.NewOpenIdProvider().NewTokenRequest(req)
	assert.ErrorContains(t, err, "invalid_code")
}

func TestTokenResponse(t *testing.T) {
	for scenario, fn := range map[string]func(t *testing.T){
		"succesful":         testSuccesfulTokenResponse,
		"missing algorithm": testTokenResponseMMissingAlgorithm,
		"invalid algorithm": testTokenResponseMInvalidAlgorithm,
		"missing key":       testTokenResponseMissingKey,
	} {
		t.Run(scenario, func(t *testing.T) {
			authReq := openidvc.AuthorizationRequest{
				ResponseType:         "code",
				Scope:                "openid",
				ClientId:             "https://holder.example.com",
				RedirectUri:          "https://holder.example.com/redirect",
				State:                "123",
				AuthorizationDetails: string(`[{"format":"jwt_vc_json","type":"openid_credential","types":["VerifiableCredential","UniversityDegreeCredential"]}]`),
				CodeChallenge:        plainChallenge,
				CodeChallengeMethod:  "plain",
			}
			require.NoError(t, authReq.StoreClientRedirectUri())

			fn(t)
		})
	}
}

func testSuccesfulTokenResponse(t *testing.T) {
	tokenRequest := openidvc.TokenRequest{
		GrantType:    "authorization_code",
		Code:         base64.RawURLEncoding.EncodeToString([]byte("msHyXWOZNxvsFcK87Sm8yqdcxn4TOWTKz7rPhzvr")),
		ClientId:     "https://holder.example.com",
		RedirectUri:  "https://holder.example.com/redirect",
		CodeVerifier: plainChallenge,
	}
	rsaPrivateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	tokenResponse, err := tokenRequest.CreateTokenResponse(openidvc.WithAccessTokenSigningKey(jwa.RS256, rsaPrivateKey))
	assert.NoError(t, err)

	assert.NotEmpty(t, tokenResponse.AccessToken)
	assert.Equal(t, "Bearer", tokenResponse.TokenType)
	assert.NotEmpty(t, tokenResponse.ExpiresIn)
	assert.NotEmpty(t, tokenResponse.CNonce)
	assert.NotEmpty(t, tokenResponse.CNonceExpiresIn)
}

func testTokenResponseMMissingAlgorithm(t *testing.T) {
	tokenRequest := openidvc.TokenRequest{
		GrantType:    "authorization_code",
		Code:         base64.RawURLEncoding.EncodeToString([]byte("msHyXWOZNxvsFcK87Sm8yqdcxn4TOWTKz7rPhzvr")),
		ClientId:     "https://holder.example.com",
		RedirectUri:  "https://holder.example.com/redirect",
		CodeVerifier: plainChallenge,
	}
	rsaPrivateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, err := tokenRequest.CreateTokenResponse(openidvc.WithAccessTokenSigningKey(nil, rsaPrivateKey))
	assert.ErrorContains(t, err, "expected algorithm to be of type jwa.SignatureAlgorithm but got")
}

func testTokenResponseMInvalidAlgorithm(t *testing.T) {
	tokenRequest := openidvc.TokenRequest{
		GrantType:    "authorization_code",
		Code:         base64.RawURLEncoding.EncodeToString([]byte("msHyXWOZNxvsFcK87Sm8yqdcxn4TOWTKz7rPhzvr")),
		ClientId:     "https://holder.example.com",
		RedirectUri:  "https://holder.example.com/redirect",
		CodeVerifier: plainChallenge,
	}
	rsaPrivateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, err := tokenRequest.CreateTokenResponse(openidvc.WithAccessTokenSigningKey(jwa.HS256, rsaPrivateKey))
	assert.ErrorContains(t, err, "failed to sign payload: invalid key")
}

func testTokenResponseMissingKey(t *testing.T) {
	tokenRequest := openidvc.TokenRequest{
		GrantType:    "authorization_code",
		Code:         base64.RawURLEncoding.EncodeToString([]byte("msHyXWOZNxvsFcK87Sm8yqdcxn4TOWTKz7rPhzvr")),
		ClientId:     "https://holder.example.com",
		RedirectUri:  "https://holder.example.com/redirect",
		CodeVerifier: plainChallenge,
	}
	_, err := tokenRequest.CreateTokenResponse(openidvc.WithAccessTokenSigningKey(jwa.RS256, nil))
	assert.ErrorContains(t, err, "failed to sign payload: missing private key while signing payload")
}
