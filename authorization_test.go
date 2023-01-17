package openidvc_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/gorilla/schema"
	"github.com/gossif/openidvc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	plainChallenge = "ThisIsAFourtyThreeCharactersLongStringThing"
	s256Challenge  = "s256test"
	// echo s256test | sha256 | base64 | tr '/+' '_-'
	s256ChallengeHash = "W6YWc_4yHwYN-cGDgGmOMHF3l7KDy7VcRjf7q2FVF-o="
)

var (
	expPresentationSubmission string = `{"definition_id":"example_ldp_vc","id":"example_ldp_vc_presentation_submission","descriptor_map":[{"id":"id_credential","path":"$","format":"ldp_vp","path_nested":{"format":"ldp_vc","path":"$.verifiableCredential[0]"}}]}`
	expPresentations          string = `{"@context":["https://www.w3.org/2018/credentials/v1"],"holder":"did:example:holder","id":"ebc6f1c2","proof":{"challenge":"n-0S6_WzA2Mj","created":"2021-03-19T15:30:15Z","domain":"https://client.example.org/cb","jws":"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..GF5Z6TamgNE8QjE3RbiDOj3n_t25_1K7NVWMUASe_OEzQV63GaKdu235MCS3hIYvepcNdQ_ZOKpGNCf0vIAoDA","proofPurpose":"authentication","type":"Ed25519Signature2018","verificationMethod":"did:example:holder#key-1"},"type":["VerifiablePresentation"],"verifiableCredential":[{"@context":["https://www.w3.org/2018/credentials/v1","https://www.w3.org/2018/credentials/examples/v1"],"credentialSubject":{"address":{"country":"DE","locality":"Musterstadt","postal_code":"123456","street_address":"Sandanger 25"},"birthdate":"1998-01-11","family_name":"Mustermann","given_name":"Max"},"id":"https://example.com/credentials/1872","issuanceDate":"2010-01-01T19:23:24Z","op":{"id":"did:example:op"},"proof":{"created":"2021-03-19T15:30:15Z","jws":"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..PT8yCqVjj5ZHD0W36zsBQ47oc3El07WGPWaLUuBTOT48IgKI5HDoiFUt9idChT_Zh5s8cF_2cSRWELuD8JQdBw","proofPurpose":"assertionMethod","type":"Ed25519Signature2018","verificationMethod":"did:example:op#keys-1"},"type":["VerifiableCredential","IDCredential"]}]}`
)

func TestAuthReqValidatorShouldError(t *testing.T) {
	type errorTestCases struct {
		description   string
		testFieldName string
		testWithValue string
		expectedError string
	}
	for _, scenario := range []errorTestCases{
		{description: "missing response type", testFieldName: "ResponseType", testWithValue: "", expectedError: "missing_response_type"},
		{description: "unsupported response type", testFieldName: "ResponseType", testWithValue: "foo", expectedError: "unsupported_response_type"},
		{description: "unsupported response type combination", testFieldName: "ResponseType", testWithValue: "id_token vp_token code", expectedError: "unsupported_response_type"},
		{description: "missing client id", testFieldName: "ClientId", testWithValue: "", expectedError: "missing_client_id"},
		{description: "missing redirect uru", testFieldName: "RedirectUri", testWithValue: "", expectedError: "missing_redirect_uri"},
		{description: "invalid redirect uri", testFieldName: "RedirectUri", testWithValue: "wallet.example.com/oauth2", expectedError: "invalid_redirect_uri"},
		{description: "missing code challenge", testFieldName: "CodeChallenge", testWithValue: "", expectedError: "missing_code_challenge"},
		{description: "invalid code challenge short", testFieldName: "CodeChallenge", testWithValue: "ThisIsAFourtyTwooCharactersLongStringThing", expectedError: "invalid_code_challenge"},
		{description: "invalid code challenge long", testFieldName: "CodeChallenge", testWithValue: "ThisIsNotAFourtyThreeCharactersLongStringThingButMuchMuchMuchMuchMuchMuchMuchMuchMuchMuchMuchMuchMuchMuchMuchLongerThanItShouldBe", expectedError: "invalid_code_challenge"},
		{description: "unsupported code challenge method", testFieldName: "CodeChallengeMethod", testWithValue: "", expectedError: "unsupported_code_challenge"},
		{description: "invalid request uri", testFieldName: "RequestUri", testWithValue: "ThisIsARequestUri", expectedError: "invalid_request_uri"},
	} {
		t.Run(scenario.description, func(t *testing.T) {
			expIssuanceRequest := openidvc.AuthorizationRequest{
				ResponseType:         "code",
				Scope:                "openid",
				ClientId:             "https://wallet.example.com",
				RedirectUri:          "https://wallet.example.com/oauth2",
				State:                "123",
				AuthorizationDetails: string(`[{"format":"jwt_vc_json","type":"openid_credential","types":["VerifiableCredential","UniversityDegreeCredential"]}]`),
				CodeChallenge:        plainChallenge,
				CodeChallengeMethod:  "plain",
				RequestUri:           "",
			}
			v := reflect.ValueOf(&expIssuanceRequest).Elem().FieldByName(scenario.testFieldName)
			require.True(t, v.IsValid())
			v.SetString(scenario.testWithValue)

			err := expIssuanceRequest.Validate()
			require.Error(t, err)
			assert.Equal(t, scenario.expectedError, err.Error())
		})
	}
}

func TestSuccesfulAuthReq(t *testing.T) {
	for scenario, fn := range map[string]func(t *testing.T){
		"receive request":  testSuccesfulAuthReq,
		"postform request": testSuccesfulPostFormAuthReq,
	} {
		t.Run(scenario, func(t *testing.T) {
			fn(t)
		})
	}
}

func testSuccesfulAuthReq(t *testing.T) {
	expIssuanceRequest := openidvc.AuthorizationRequest{
		ResponseType:         "code",
		Scope:                "openid",
		ClientId:             "https://wallet.example.com",
		RedirectUri:          "https://wallet.example.com/oauth2",
		State:                "123",
		AuthorizationDetails: string(`[{"format":"jwt_vc_json","type":"openid_credential","types":["VerifiableCredential","UniversityDegreeCredential"]}]`),
		CodeChallenge:        plainChallenge,
		CodeChallengeMethod:  "plain",
	}
	expAuthorizationResponse := url.Values{
		"state": []string{"123"},
	}
	params := url.Values{}
	decoder := schema.NewEncoder()
	err := decoder.Encode(expIssuanceRequest, params)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "https://issuer.example.com/authorize", strings.NewReader(params.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// the open id provider must be the same for the request as for the response, no new initialization
	op := openidvc.NewOpenIdProvider()
	actualAuthorizationRequest, err := op.NewAuthorizationRequest(req)

	assert.NoError(t, err)
	assert.True(t, reflect.DeepEqual(expIssuanceRequest, actualAuthorizationRequest))

	actualAuthorizationResponse, err := actualAuthorizationRequest.CreateAuthorizationResponse()
	assert.NoError(t, err)

	// we have to cheat bij adding the code to the expected values
	expAuthorizationResponse.Set("code", actualAuthorizationResponse.Query().Get("code"))
	assert.True(t, reflect.DeepEqual(expAuthorizationResponse, actualAuthorizationResponse.Query()))
}

func testSuccesfulPostFormAuthReq(t *testing.T) {
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()

	expIssuanceRequest := openidvc.AuthorizationRequest{
		ResponseType:         "code",
		Scope:                "openid",
		ClientId:             "https://verifier.example.com",
		RedirectUri:          ts.URL,
		State:                "123",
		AuthorizationDetails: string(`[{"format":"jwt_vc_json","type":"openid_credential","types":["VerifiableCredential","UniversityDegreeCredential"]}]`),
		CodeChallenge:        plainChallenge,
		CodeChallengeMethod:  "plain",
	}
	url, _ := url.ParseRequestURI(ts.URL)
	assert.NoError(t, expIssuanceRequest.PostFormAuthorizationRequest(*url))
}

func TestSuccesfulPresentations(t *testing.T) {
	for scenario, fn := range map[string]func(t *testing.T){
		// the order of the loop is not guaranteed in go
		"receive with vp token":       testPresentations,
		"receive with definition uri": testPresentationsWithDefUri,
		"receive with id token":       testPresentationsWithIdToken,
		"initiation":                  testPresentationInitiation,
		"post form request":           testPostFormPresentation,
	} {
		t.Run(scenario, func(t *testing.T) {
			fn(t)
		})
	}
}

func testPresentations(t *testing.T) {
	expPresentationRequest := openidvc.AuthorizationRequest{
		ResponseType: "vp_token",
		Scope:        "openid",
		ClientId:     "https://wallet.example.com",
		RedirectUri:  "https://wallet.example.com/oauth2",
		State:        "123",
		PresentDef:   `{"id":"example_jwt_vc","input_descriptors":[{"id": "id_credential","format":{"jwt_vc":{"proof_type":["JsonWebSignature2020"]}},"constraints":{"fields":[{"path":["$.vc.type"],"filter":{"type":"array","contains": {"const": "IDCredential"}}}]}}]}`,
		Nonce:        "n-0S6_WzA2Mj",
	}
	params := url.Values{}
	decoder := schema.NewEncoder()
	err := decoder.Encode(expPresentationRequest, params)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "https://issuer.example.com/authorize", strings.NewReader(params.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	op := openidvc.NewOpenIdProvider()
	actualAuthorizationRequest, err := op.NewAuthorizationRequest(req)

	assert.NoError(t, err)
	assert.True(t, reflect.DeepEqual(expPresentationRequest, actualAuthorizationRequest))

	expPresentationResponse := url.Values{
		"state":                   []string{"123"},
		"vp_token":                []string{expPresentations},
		"presentation_submission": []string{expPresentationSubmission},
	}
	actualAuthorizationResponse, err := actualAuthorizationRequest.CreateAuthorizationResponse(openidvc.WithVerifiablePresentation(expPresentations), openidvc.WithPresentationSubmission(expPresentationSubmission))

	assert.NoError(t, err)
	assert.True(t, reflect.DeepEqual(expPresentationResponse, actualAuthorizationResponse.Query()))
}

func testPresentationsWithDefUri(t *testing.T) {
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Write([]byte(`{"id":"example_jwt_vc","input_descriptors":[{"id": "id_credential","format":{"jwt_vc":{"proof_type":["JsonWebSignature2020"]}},"constraints":{"fields":[{"path":["$.vc.type"],"filter":{"type":"array","contains": {"const": "IDCredential"}}}]}}]}`))
	}))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()

	expPresentationRequest := openidvc.AuthorizationRequest{
		ResponseType: "vp_token",
		Scope:        "openid",
		ClientId:     "https://wallet.example.com",
		RedirectUri:  "https://wallet.example.com/oauth2",
		State:        "123",
		PresentDef:   ts.URL,
		Nonce:        "n-0S6_WzA2Mj",
	}
	params := url.Values{}
	decoder := schema.NewEncoder()
	err := decoder.Encode(expPresentationRequest, params)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "https://issuer.example.com/authorize", strings.NewReader(params.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	op := openidvc.NewOpenIdProvider()
	actualAuthorizationRequest, err := op.NewAuthorizationRequest(req)
	fmt.Println(actualAuthorizationRequest)
	assert.NoError(t, err)
	assert.True(t, reflect.DeepEqual(expPresentationRequest, actualAuthorizationRequest))
}

func testPresentationsWithIdToken(t *testing.T) {
	expPresentationRequest := openidvc.AuthorizationRequest{
		ResponseType: "vp_token id_token",
		Scope:        "openid",
		ClientId:     "https://wallet.example.com",
		RedirectUri:  "https://wallet.example.com/oauth2",
		State:        "123",
		PresentDef:   `{"id":"example_jwt_vc","input_descriptors":[{"id": "id_credential","format":{"jwt_vc":{"proof_type":["JsonWebSignature2020"]}},"constraints":{"fields":[{"path":["$.vc.type"],"filter":{"type":"array","contains": {"const": "IDCredential"}}}]}}]}`,
		Nonce:        "n-0S6_WzA2Mj",
	}
	params := url.Values{}
	decoder := schema.NewEncoder()
	err := decoder.Encode(expPresentationRequest, params)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "https://issuer.example.com/authorize", strings.NewReader(params.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	op := openidvc.NewOpenIdProvider()
	actualAuthorizationRequest, err := op.NewAuthorizationRequest(req)

	assert.NoError(t, err)
	assert.True(t, reflect.DeepEqual(expPresentationRequest, actualAuthorizationRequest))

	expPresentationResponseWithIdToken := url.Values{
		"state":                   []string{"123"},
		"vp_token":                []string{expPresentations},
		"id_token":                []string{"eyJraWQiOiIxZTlnZGs3IiwiYWxnIjoiUlMyNTYifQ"},
		"presentation_submission": []string{expPresentationSubmission},
	}
	actualAuthorizationResponse, err := actualAuthorizationRequest.CreateAuthorizationResponse(openidvc.WithVerifiablePresentation(expPresentations), openidvc.WithPresentationSubmission(expPresentationSubmission), openidvc.WithIdentityToken("eyJraWQiOiIxZTlnZGs3IiwiYWxnIjoiUlMyNTYifQ"))

	assert.NoError(t, err)
	assert.True(t, reflect.DeepEqual(expPresentationResponseWithIdToken, actualAuthorizationResponse.Query()))
}

func testPresentationInitiation(t *testing.T) {
	expPresentationRequest := openidvc.AuthorizationRequest{
		ResponseType: "vp_token",
		Scope:        "openid",
		ClientId:     "https://wallet.example.com",
		RedirectUri:  "https://wallet.example.com/oauth2",
		State:        "123",
		PresentDef:   `{"id":"example_jwt_vc","input_descriptors":[{"id": "id_credential","format":{"jwt_vc":{"proof_type":["JsonWebSignature2020"]}},"constraints":{"fields":[{"path":["$.vc.type"],"filter":{"type":"array","contains": {"const": "IDCredential"}}}]}}]}`,
		Nonce:        "n-0S6_WzA2Mj",
	}
	url, err := expPresentationRequest.InitiatePresentationRequest()
	assert.NoError(t, err)
	assert.Equal(t, `openid:?client_id=https%3A%2F%2Fwallet.example.com&nonce=n-0S6_WzA2Mj&presentation_definition=%7B%22id%22%3A%22example_jwt_vc%22%2C%22input_descriptors%22%3A%5B%7B%22id%22%3A+%22id_credential%22%2C%22format%22%3A%7B%22jwt_vc%22%3A%7B%22proof_type%22%3A%5B%22JsonWebSignature2020%22%5D%7D%7D%2C%22constraints%22%3A%7B%22fields%22%3A%5B%7B%22path%22%3A%5B%22%24.vc.type%22%5D%2C%22filter%22%3A%7B%22type%22%3A%22array%22%2C%22contains%22%3A+%7B%22const%22%3A+%22IDCredential%22%7D%7D%7D%5D%7D%7D%5D%7D&redirect_uri=https%3A%2F%2Fwallet.example.com%2Foauth2&response_type=vp_token&scope=openid&state=123`, url)
}

func testPostFormPresentation(t *testing.T) {
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()

	expPresentationRequest := openidvc.AuthorizationRequest{
		ResponseType: "vp_token",
		Scope:        "openid",
		ClientId:     "https://wallet.example.com",
		RedirectUri:  "https://wallet.example.com/oauth2",
		State:        "123",
		PresentDef:   `{"id":"example_jwt_vc","input_descriptors":[{"id": "id_credential","format":{"jwt_vc":{"proof_type":["JsonWebSignature2020"]}},"constraints":{"fields":[{"path":["$.vc.type"],"filter":{"type":"array","contains": {"const": "IDCredential"}}}]}}]}`,
		Nonce:        "n-0S6_WzA2Mj",
	}
	url, _ := url.ParseRequestURI(ts.URL)
	err := expPresentationRequest.PostFormAuthorizationRequest(*url)
	assert.NoError(t, err)
}
