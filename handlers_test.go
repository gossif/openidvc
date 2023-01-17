package openidvc_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gossif/openidvc"
	"github.com/stretchr/testify/assert"
)

func TestAuthorizationRequestHandler(t *testing.T) {
	for scenario, fn := range map[string]func(t *testing.T){
		"succesful":         testSuccesfulRequestHandling,
		"token not allowed": testTokenNotAllowd,
	} {
		t.Run(scenario, func(t *testing.T) {
			fn(t)
		})
	}
}

func testSuccesfulRequestHandling(t *testing.T) {
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			r.ParseForm()
			code, state := r.Form.Get("code"), r.Form.Get("state")
			assert.NotEmpty(t, code)
			assert.Equal(t, "123", state)

			w.WriteHeader(http.StatusOK)
		default:
			openidvc.AutorizationRequestHandler(w, r)
		}
	}))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()

	authRequest := openidvc.AuthorizationRequest{
		ResponseType:         "code",
		Scope:                "openid",
		ClientId:             "https://verifier.example.com",
		RedirectUri:          ts.URL + "/redirect",
		State:                "123",
		AuthorizationDetails: string(`[{"format":"jwt_vc_json","type":"openid_credential","types":["VerifiableCredential","UniversityDegreeCredential"]}]`),
		CodeChallenge:        plainChallenge,
		CodeChallengeMethod:  "plain",
	}
	url, _ := url.ParseRequestURI(ts.URL)
	assert.NoError(t, authRequest.PostFormAuthorizationRequest(*url))
}

func testTokenNotAllowd(t *testing.T) {
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			r.ParseForm()
			code, state := r.Form.Get("code"), r.Form.Get("state")
			assert.NotEmpty(t, code)
			assert.Equal(t, "123", state)

			w.WriteHeader(http.StatusOK)
		default:
			openidvc.AutorizationRequestHandler(w, r)
		}
	}))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()

	expIssuanceRequest := openidvc.AuthorizationRequest{
		ResponseType:         "vp_token",
		Scope:                "openid",
		ClientId:             "https://verifier.example.com",
		RedirectUri:          ts.URL + "/redirect",
		State:                "123",
		AuthorizationDetails: string(`[{"format":"jwt_vc_json","type":"openid_credential","types":["VerifiableCredential","UniversityDegreeCredential"]}]`),
		CodeChallenge:        plainChallenge,
		CodeChallengeMethod:  "plain",
		PresentDef:           `{"id":"example_jwt_vc","input_descriptors":[{"id": "id_credential","format":{"jwt_vc":{"proof_type":["JsonWebSignature2020"]}},"constraints":{"fields":[{"path":["$.vc.type"],"filter":{"type":"array","contains": {"const": "IDCredential"}}}]}}]}`,
		Nonce:                "n-0S6_WzA2Mj",
	}
	url, _ := url.ParseRequestURI(ts.URL)
	assert.ErrorContains(t, expIssuanceRequest.PostFormAuthorizationRequest(*url), "invalid_request")
}
