package openidvc_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gossif/openidvc"
	"github.com/stretchr/testify/assert"
)

func TestPushedAuthorizationRequest(t *testing.T) {
	for scenario, fn := range map[string]func(t *testing.T){
		"succesful": testSuccesfulPAR,
	} {
		t.Run(scenario, func(t *testing.T) {
			fn(t)
		})
	}
}

func testSuccesfulPAR(t *testing.T) {
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/par":
			openidvc.PushedAutorizationRequestHandler(w, r)

		case "/authorize":
			_, err := openidvc.NewOpenIdProvider().NewAuthorizationRequest(r)

			assert.NoError(t, err)
		}
	}))
	ts.EnableHTTP2 = true

	ts.StartTLS()
	defer ts.Close()

	pushedAuthRequest := openidvc.AuthorizationRequest{
		ResponseType:         "code",
		Scope:                "openid",
		ClientId:             "https://holder.example.com",
		RedirectUri:          ts.URL + "/redirect",
		State:                "123",
		AuthorizationDetails: string(`[{"format":"jwt_vc_json","type":"openid_credential","types":["VerifiableCredential","UniversityDegreeCredential"]}]`),
		CodeChallenge:        plainChallenge,
		CodeChallengeMethod:  "plain",
	}
	parUri, _ := url.ParseRequestURI(ts.URL + "/par")
	pushedAuthorizationResponse, err := pushedAuthRequest.PostFormPushedAuthorizationRequest(*parUri)
	assert.NoError(t, err)

	authRequest := openidvc.AuthorizationRequest{
		ClientId:   "https://holder.example.com",
		RequestUri: pushedAuthorizationResponse.RequestUri,
	}
	authUri, _ := url.ParseRequestURI(ts.URL + "/authorize")
	assert.NoError(t, authRequest.PostFormAuthorizationRequest(*authUri))
}
