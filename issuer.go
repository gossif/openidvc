package openidvc

import (
	"net/http"

	"github.com/lestrrat-go/jwx/v2/jwa"
)

type OpenIdProvider interface {
	InitiateIssuance()
	// NewPushedAuthorizationRequest receives the pushed authorization request
	NewPushedAuthorizationRequest(r *http.Request) (AuthorizationRequest, error)
	// NewValidatedAuthorizationRequest receives an open id for credential issuance authorization request and validates it
	NewAuthorizationRequest(r *http.Request) (AuthorizationRequest, error)
	// NewTokenRequest receives an open id token request
	NewTokenRequest(r *http.Request) (TokenRequest, error)
}

type Issuer interface {
	// NewCredentialRequest receives an open id for credential issuance request
	// the options must contain the signing key of the access token
	NewCredentialRequest(r *http.Request, options ...TokenResponseOption) (CredentialRequest, error)
	// NewDeferredCredentialRequest receives a issuance request for a deferred credential
	NewDeferredCredentialRequest(r *http.Request, options ...TokenResponseOption) (CredentialRequest, error)
}

type oauth2Request struct{}
type credentialIssuance struct{}

// optionalParamaters can be used to pass options to functions
type optionalParameters struct {
	verifiableCredential string
	format               CredentialFormat
	deferred             bool
	signingKey           interface{}
	algorithm            jwa.KeyAlgorithm
}

// NewAuthorizationRequest creates a new open id provider interface
func NewOpenIdProvider() OpenIdProvider {
	o := oauth2Request{}
	return &o
}

// NewCredentialRequest creates a new issuer interface for credential issuance
func NewIssuer() Issuer {
	c := credentialIssuance{}
	return &c
}

// InitiateIssuance returns a openid for credential issuance initiation that can be used in a qr code
func (o *oauth2Request) InitiateIssuance() {

}
