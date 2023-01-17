package openidvc

import (
	"crypto/sha512"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/schema"
	"github.com/lestrrat-go/jwx/v2/jwa"
)

// OpenId4VCAuthResponse is an open id connect authorizarion response
type TokenRequest struct {
	// grant_type is required
	GrantType GrantType `schema:"grant_type,omitempty"`
	// code is required
	Code string `schema:"code,omitempty"`
	// client_id is required
	ClientId string `schema:"client_id,omitempty"`
	// redirect_uri is required
	RedirectUri string `schema:"redirect_uri,omitempty"`
	// code_verifier is required
	CodeVerifier string `schema:"code_verifier,omitempty"`
}

type TokenResponse struct {
	AccessToken     string        `json:"access_token,omitempty"`
	TokenType       string        `json:"token_type,omitempty"`
	ExpiresIn       time.Duration `json:"expires_in,omitempty"`
	CNonce          string        `json:"c_nonce,omitempty"`
	CNonceExpiresIn time.Duration `json:"c_nonce_expires_in,omitempty"`
}

type TokenResponseOption func(*optionalParameters)

// WithAccessTokenSigningKey is the option for the algorithm and signing key
func WithAccessTokenSigningKey(alg jwa.KeyAlgorithm, sigKey interface{}) TokenResponseOption {
	return func(t *optionalParameters) {
		t.signingKey = sigKey
		t.algorithm = alg
	}
}

// NewTokenRequest receives an open id token request
func (o *oauth2Request) NewTokenRequest(r *http.Request) (TokenRequest, error) {
	var (
		tokenRequest TokenRequest
	)
	if !strings.Contains(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		return TokenRequest{}, errors.New("invalid_content_type")
	}
	err := r.ParseForm()
	if err != nil {
		return TokenRequest{}, errInternalServerError
	}
	decoder := schema.NewDecoder()
	err = decoder.Decode(&tokenRequest, r.Form)
	if err != nil {
		return TokenRequest{}, errInternalServerError
	}
	// Communicating the client secret is done differently per authorization server.
	// RFC 6749 says:
	// Clients in possession of a client password MAY use the HTTP Basic authentication scheme as defined in [RFC2617] to authenticate with the authorization server.
	// Alternatively, the authorization server MAY support including the client credentials in the request-body using parameters
	// This authorization server will only accept params, no header value
	// Clients such as https://github.com/golang/oauth2 will try both ways, thats why you see 2 incoming requests
	// In header style is not accepted
	authInHeader := r.Header.Get("Authorization")
	if authInHeader != "" {
		return TokenRequest{}, errInvalidRequest
	}
	if err = tokenRequest.Validate(); err != nil {
		return TokenRequest{}, err
	}
	return tokenRequest, nil
}

// Validate validates the token request against rfc6749 and open id connect
func (tr *TokenRequest) Validate() error {
	// response_type is required
	if tr.GrantType.String() == "" {
		return errors.New("missing_grant_type")
	} else if !contains([]string{AuthorizationCode_en.String(), AuthorizationCode_en_us.String()}, tr.GrantType.String()) {
		return errors.New("unsupported_grant_type")
	}
	if tr.Code == "" {
		return errors.New("missing_code")
	}
	if tr.RedirectUri == "" {
		return errors.New("missing_redirect_uri")
	}
	// redirect_uri must be a fully qualified domain name (fqdn)
	if _, err := url.ParseRequestURI(tr.RedirectUri); err != nil {
		return errors.New("invalid_redirect_uri")
	}
	if tr.ClientId == "" {
		return errors.New("missing_client_id")
	}
	// code_verifier is required
	if tr.CodeVerifier == "" {
		return errors.New("missing_code_verifier")
	}
	// verify that the authorization code is valid.
	// retrieve the code from the database, its invalid or expired when its not found
	if _, err := GetByCodeGranted(tr.Code); err != nil {
		return errors.New("invalid_code")
	}
	// ensure that the redirect_uri parameter value is identical to the redirect_uri parameter value that
	// was included in the initial authorization request.
	// this test also include that the client id is equal
	authRequest, err := GetByClientRedirectUri(tr.ClientId, tr.RedirectUri)
	if err != nil {
		return errors.New("invalid_client_redirect_uri")
	}
	// Validate the code verifiers with the earlier received code challenge
	if !authRequest.CodeChallengeMethod.Validate(authRequest.CodeChallenge, tr.CodeVerifier) {
		return errors.New("invalid_code_verifier")
	}
	return nil
}

// CreateTokenResponse returns a json token response
// With the options, the signing key, algorithm, and issuer are passed
func (tr *TokenRequest) CreateTokenResponse(options ...TokenResponseOption) (TokenResponse, error) {
	authRequest, err := GetByClientRedirectUri(tr.ClientId, tr.RedirectUri)
	if err != nil {
		return TokenResponse{}, errors.New("invalid_redirect_uri")
	}
	authorizedCredentialRequest := CredentialRequest{
		ClientId:             tr.ClientId,
		AuthorizationDetails: authRequest.AuthorizationDetails,
		CNonceExpiresIn:      GetServerConfig().ExpirationTime,
		BearerTokenExpiresIn: GetServerConfig().ExpirationTime,
	}
	authorizedCredentialRequest.CNonce, _ = generateNonce()

	accessToken, err := authorizedCredentialRequest.createBearerToken(options...)
	if err != nil {
		return TokenResponse{}, err
	}
	authorizedCredentialRequest.BearerTokenSHA512 = sha512.Sum512(accessToken)

	// Store the bearer token, so we can verify it up when the credential requests arrives
	if err := authorizedCredentialRequest.StoreCredentialRequest(); err != nil {
		return TokenResponse{}, err
	}
	// return the request_uri and expiration time
	return TokenResponse{
		AccessToken:     string(accessToken),
		TokenType:       "Bearer",
		ExpiresIn:       authorizedCredentialRequest.BearerTokenExpiresIn,
		CNonce:          authorizedCredentialRequest.CNonce,
		CNonceExpiresIn: authorizedCredentialRequest.CNonceExpiresIn,
	}, nil
}
