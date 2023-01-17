package openidvc_test

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"

	"github.com/gossif/openidvc"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

var (
	issuerClientId string
	holderClientId string
	rsaPrivateKey  *rsa.PrivateKey
	rsaPublicKey   rsa.PublicKey
)

var NewUnstartedIssuanceServer = func() *httptest.Server {
	var (
		expectedJwt     string = "eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6ZXhhbXBsZTo3NmUxMmVjNzEyZWJjNmYxYzIyMWViZmViMWYjNWYzMTRmNTcwYWU2NGVhYmE4MGVkYTljNDY1YTJiMjUiLCJ0eXAiOiJKV1QifQ.eyJleHAiOjE3NTE5Njk0MjIsImlhdCI6MTY2NTU2OTQyMiwiaXNzIjoiZGlkOmV4YW1wbGU6NzZlMTJlYzcxMmViYzZmMWMyMjFlYmZlYjFmIiwianRpIjoiOTY1YWQwYTgtMTE4My00OGFmLWJlZjAtNTNmMDc3YWM3NDNkIiwibmJmIjoxNjY1NTY5NDIyLCJub25jZSI6IjZ2STU1Wk03aS1NQ2tSVE5yTXY1SjVIOGVXV3lGY3ZTSUVOX3podG5tUHM9Iiwic3ViIjoiZGlkOmV4YW1wbGU6ZWJmZWIxZjcxMmViYzZmMWMyNzZlMTJlYzIxIiwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy9leGFtcGxlcy92MSJdLCJjcmVkZW50aWFsU3RhdHVzIjp7ImlkIjoiaHR0cHM6Ly9leGFtcGxlLmVkdS9zdGF0dXMvMjQiLCJ0eXBlIjoiQ3JlZGVudGlhbFN0YXR1c0xpc3QyMDE3In0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImRlZ3JlZSI6eyJuYW1lIjoiQmFjaGVsb3Igb2YgU2NpZW5jZSBhbmQgQXJ0cyIsInR5cGUiOiJCYWNoZWxvckRlZ3JlZSJ9LCJpZCI6ImRpZDpleGFtcGxlOmViZmViMWY3MTJlYmM2ZjFjMjc2ZTEyZWMyMSJ9LCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiVW5pdmVyc2l0eURlZ3JlZUNyZWRlbnRpYWwiXX19.g0uhpBGf6-isF2IUGT_8hs2Iw-Cj5Ov0Y9A2VPPnHOs2NGNKzEMSpMLOSGXuqgrSBZ9sWgK41ss49u38xRf8OA"
		expectedVJsonLd string = `{"@context":["https://www.w3.org/2018/credentials/v1","https://www.w3.org/2018/credentials/examples/v1"],"credentialStatus":{"id":"https://example.edu/status/24","type":"CredentialStatusList2017"},"credentialSubject":{"degree":{"name":"Bachelor of Science and Arts","type":"BachelorDegree"},"id":"did:example:ebfeb1f712ebc6f1c276e12ec21"},"expirationDate":"2025-07-08T12:10:22+02:00","id":"c8c05ffd-d808-421a-966b-1d89be7283eb","issuanceDate":"2022-10-12T12:10:22+02:00","issuer":"did:example:76e12ec712ebc6f1c221ebfeb1f","proof":{"created": "2022-11-22T09:18:57Z","jws":"eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6ZXhhbXBsZTo3NmUxMmVjNzEyZWJjNmYxYzIyMWViZmViMWYjYTJlMzJhOWM3ZWMxNDIyYTlmMTM0MGU3ZmY3YjFkOTgifQ..qdYq_owWeD3FN-COSFyu-YJ3Lb-Cdp9S7pwsPecLANpUm7Vy63f-l-kBUxsuuF-fQF13okfnyhuV4BI-3MP3hA","nonce":"MU_V5D57VkfeejZ_dmegM0UWb2GxgmtqkaTwwriBEic=","proofPurpose":"assertionMethod","type":"EcdsaSecp256k1Signature2019","verificationMethod":"did:example:76e12ec712ebc6f1c221ebfeb1f#a2e32a9c7ec1422a9f1340e7ff7b1d98"},"type":["VerifiableCredential", "UniversityDegreeCredential"]}`
	)
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/par":
			openidvc.PushedAutorizationRequestHandler(w, r)

		case "/authorize":
			openidvc.AutorizationRequestHandler(w, r)

		case "/token":
			tokenRequest, err := openidvc.NewOpenIdProvider().NewTokenRequest(r)
			if err != nil {
				openidvc.ResponseError(w, err)
				return
			}
			response, err := tokenRequest.CreateTokenResponse(openidvc.WithAccessTokenSigningKey(jwa.RS256, rsaPrivateKey))
			if err != nil {
				openidvc.ResponseError(w, err)
				return
			}
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			json.NewEncoder(w).Encode(response)

		case "/credential":
			var (
				response openidvc.CredentialResponse
			)
			// NewCredentialRequest validates also the access_code
			credRequest, err := openidvc.NewIssuer().NewCredentialRequest(r, openidvc.WithAccessTokenSigningKey(jwa.RS256, rsaPublicKey))
			if err != nil {
				openidvc.CredentialResponseError(w, err)
				return
			}
			switch credRequest.Format {
			case openidvc.VCJsonldFormat:
				response, err = credRequest.CreateCredentialResponse(
					openidvc.WithVerifiableCredentialn(expectedVJsonLd, credRequest.Format),
				)
			case openidvc.VCJwtJsonldFormat, openidvc.VCJwtFormat:
				// when the jwt format is wanted, then defer the credential issuance
				response, err = credRequest.CreateCredentialResponse(
					openidvc.WithCredentialDeferred(),
					openidvc.WithAcceptanceTokenSigningKey(jwa.RS256, rsaPrivateKey),
				)
			}
			if err != nil {
				openidvc.CredentialResponseError(w, err)
				return
			}
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			json.NewEncoder(w).Encode(response)

		case "/deferred":
			credRequest, err := openidvc.NewIssuer().NewDeferredCredentialRequest(r, openidvc.WithAccessTokenSigningKey(jwa.RS256, rsaPublicKey))
			if err != nil {
				openidvc.CredentialResponseError(w, err)
				return
			}
			response, err := credRequest.CreateCredentialResponse(openidvc.WithVerifiableCredentialn(expectedJwt, openidvc.VCJwtJsonldFormat))
			if err != nil {
				openidvc.CredentialResponseError(w, err)
				return
			}
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			json.NewEncoder(w).Encode(response)
		}
	}))
	ts.EnableHTTP2 = true
	return ts
}

var NewUnstartedWalletServer = func(issuanceServer *httptest.Server) *httptest.Server {
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			authRequest := openidvc.AuthorizationRequest{
				ClientId:      holderClientId,
				RedirectUri:   holderClientId + "/redirect",
				State:         "123",
				CodeChallenge: plainChallenge,
			}
			url, _ := url.ParseRequestURI(issuerClientId + "/token")
			tokenResponse, err := authRequest.PostFormTokenRequest(r, *url)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			json.NewEncoder(w).Encode(tokenResponse)

		case "/postcredential":
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "invalid_body", http.StatusBadRequest)
				return
			}
			var tokenResponse openidvc.TokenResponse
			if err := json.Unmarshal(bodyBytes, &tokenResponse); err != nil {
				http.Error(w, "invalid_body", http.StatusBadRequest)
				return
			}
			proofJwt, err := generateProof(holderClientId, issuanceServer.URL, tokenResponse.CNonce)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			proofOfPossession := map[string]interface{}{"proof_type": "jwt", "jwt": string(proofJwt)}
			credentialRequest := map[string]interface{}{"format": "jwt_vc_json", "types": []string{"VerifiableCredential", "UniversityDegreeCredential"}, "proof": proofOfPossession}
			jsonCredentialRequest, _ := json.Marshal(credentialRequest)
			fmt.Println(string(jsonCredentialRequest))
			tr := &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
			client := &http.Client{Transport: tr}
			req := httptest.NewRequest(http.MethodPost, issuerClientId+"/credential", strings.NewReader(string(jsonCredentialRequest)))
			req.Header.Set("Authorization", "Bearer "+tokenResponse.AccessToken)
			req.Header.Set("Content-Type", "application/json; charset=utf-8")
			response, err := client.Do(req)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			json.NewEncoder(w).Encode(response)
		}

	}))
	ts.EnableHTTP2 = true
	return ts
}

func generateProof(clientId string, credentialIssuer string, nonce string) ([]byte, error) {
	var signatureSecp256r1KeyRaw string = `{
		"crv": "P-256",
		"d": "7m0EWsfIVozLS2O0tc_QrGEEeVWL_wbPoePtWijz7K0",
		"kid": "did:ebsi:zyCxHufy7JuGtpap7KezmeY#4d98ef1d2c5947a586b2226b200ade72",
		"kty": "EC",
		"x": "nAyQZC6WAvSqnttlft7YOJrqmJx47t3-6l97XQfAGlU",
		"y": "OWcile-qNKOsmXUsUDdYTwn39lvA_Qiml5gFMGaFraQ"
	}`
	var privateKey ecdsa.PrivateKey
	err := jwk.ParseRawKey([]byte(signatureSecp256r1KeyRaw), &privateKey)
	if err != nil {
		fmt.Println(err)
	}

	publicKey := privateKey.PublicKey
	publicKeyJwk, _ := jwk.FromRaw(publicKey)
	publicKeyBytes, _ := json.Marshal(publicKeyJwk)

	audience := []string{credentialIssuer}

	token, _ := jwt.NewBuilder().
		Issuer(clientId).
		Audience(audience).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Hour*24*365*100)).
		Claim("nonce", nonce).
		Claim("jwk", string(publicKeyBytes)).
		Build()

	return jwt.Sign(token, jwt.WithKey(jwa.ES256, privateKey))
}

func generateProofLegalEntity(clientId string, credentialIssuer string, nonce string) ([]byte, error) {
	var signatureSecp256r1KeyRaw string = `{
		"crv": "P-256",
		"d": "7m0EWsfIVozLS2O0tc_QrGEEeVWL_wbPoePtWijz7K0",
		"kid": "did:ebsi:zyCxHufy7JuGtpap7KezmeY#4d98ef1d2c5947a586b2226b200ade72",
		"kty": "EC",
		"x": "nAyQZC6WAvSqnttlft7YOJrqmJx47t3-6l97XQfAGlU",
		"y": "OWcile-qNKOsmXUsUDdYTwn39lvA_Qiml5gFMGaFraQ"
	}`
	var privateKey jwk.Key
	privateKey, err := jwk.ParseKey([]byte(signatureSecp256r1KeyRaw))
	if err != nil {
		fmt.Println(err)
	}
	audience := []string{credentialIssuer}

	token, _ := jwt.NewBuilder().
		Issuer(clientId).
		Audience(audience).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Hour*24*365*100)).
		Claim("nonce", nonce).
		Build()

	return jwt.Sign(token, jwt.WithKey(jwa.ES256, privateKey))
}
