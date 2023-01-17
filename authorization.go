package openidvc

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/schema"
)

// AuthorizationRequest is an open id connect authorizarion request
type AuthorizationRequest struct {
	// scope is required
	Scope string `schema:"scope"`
	// response_type is required
	ResponseType ResponseType `schema:"response_type"`
	//client_id is required
	ClientId string `schema:"client_id"`
	// redirect_uri is required
	RedirectUri string `schema:"redirect_uri"`
	// state is recommended
	State string `schema:"state,omitempty"`
	// code_challenge is required, rfc 7636
	CodeChallenge       string              `schema:"code_challenge,omitempty"`
	CodeChallengeMethod CodeChallengeMethod `schema:"code_challenge_method,omitempty"`
	// not required because authorization_details is one way to request a credential, the other one is to use scope
	AuthorizationDetails string `schema:"authorization_details,omitempty"`
	// rfc 9126, OAuth 2.0 Pushed Authorization Requests
	RequestUri string `schema:"request_uri,omitempty"`
	// open id for presentations
	PresentDef    string `schema:"presentation_definition,omitempty"`
	PresentDefUri string `schema:"presentation_definition_uri,omitempty"`
	// nonce is required for presentation of the credential
	Nonce string `schema:"nonce,omitempty"`
}

// AuthorizationResponse is an open id connect authorizarion response
type AuthorizationResponse struct {
	// code is required when response type is token
	Code  string `schema:"code,omitempty"`
	State string `schema:"state,omitempty"`
	// parameters for the presentation response
	PresentationToken string `schema:"vp_token,omitempty"`
	IdentityToken     string `schema:"id_token,omitempty"`
	PresentSubmission string `schema:"presentation_submission,omitempty"`
}

type presentation struct {
	vpToken    string
	idToken    string
	presentSub string
}

type VPTokenOption func(*presentation)

// WithVerifiablePresentation is the option to return a vp_token
func WithVerifiablePresentation(vp string) VPTokenOption {
	return func(p *presentation) {
		p.vpToken = vp
	}
}

// WithVerifiablePresentation is the option to return a presentation submission with the vp_token
func WithPresentationSubmission(ps string) VPTokenOption {
	return func(p *presentation) {
		p.presentSub = ps
	}
}

// WithIdentityToken is the option to return an is_token
func WithIdentityToken(id string) VPTokenOption {
	return func(p *presentation) {
		p.idToken = id
	}
}

// receiveAuthorizationRequest receives an open id for credential issuance authorization request
func receiveAuthorizationRequest(r *http.Request) (AuthorizationRequest, error) {
	var (
		authRequest AuthorizationRequest
	)
	if !strings.Contains(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		return AuthorizationRequest{}, errors.New("invalid_content_type")
	}
	err := r.ParseForm()
	if err != nil {
		return AuthorizationRequest{}, errInvalidRequest
	}
	decoder := schema.NewDecoder()
	err = decoder.Decode(&authRequest, r.Form)
	if err != nil {
		return AuthorizationRequest{}, errInvalidRequest
	}
	// apply rfc 9126, OAuth 2.0 Pushed Authorization Requests
	if authRequest.RequestUri != "" {
		pushedAuthReq, err := GetByClientRequestUri(authRequest.ClientId, authRequest.RequestUri)
		if err != nil {
			return AuthorizationRequest{}, errors.New("invalid_request_uri")
		}
		// request_uri served its purpose, remove the value to enable validation of the request
		pushedAuthReq.RequestUri = ""

		return *pushedAuthReq, nil
	}
	return authRequest, nil
}

// NewValidatedAuthorizationRequest receives an open id for credential issuance authorization request and validates it
func (o *oauth2Request) NewAuthorizationRequest(r *http.Request) (AuthorizationRequest, error) {
	authRequest, err := receiveAuthorizationRequest(r)
	if err != nil {
		return AuthorizationRequest{}, err
	}
	if err = authRequest.Validate(); err != nil {
		return AuthorizationRequest{}, err
	}
	return authRequest, nil
}

// CreateAuthorizationRequestForm creates an url encoded form for the authorizaion request
func (ar *AuthorizationRequest) CreateAuthorizationRequestForm() (url.Values, error) {
	if ar.RequestUri == "" {
		if err := ar.Validate(); err != nil {
			return nil, err
		}
	}
	params := url.Values{}
	encoder := schema.NewEncoder()
	err := encoder.Encode(ar, params)
	if err != nil {
		return nil, errInternalServerError
	}
	if err := ar.StoreClientState(); err != nil {
		return nil, err
	}
	return params, nil
}

// PostFormIssuanceRequest posts an authorization request for credential issuance from the holder to the issuer
func (ar *AuthorizationRequest) PostFormAuthorizationRequest(uri url.URL) error {
	params, err := ar.CreateAuthorizationRequestForm()
	if err != nil {
		return err
	}
	uri.RawQuery = params.Encode()
	responseBody, err := httpPostForm(uri)

	if err != nil {
		var errorResponse ErrorResponse
		if err = json.Unmarshal(responseBody, &errorResponse); err != nil {
			return errInternalServerError
		}
		return errors.New(string(errorResponse.Error))
	}
	return nil
}

// PostFormTokenRequest take the received request and posts the request to get the token
func (ar *AuthorizationRequest) PostFormTokenRequest(r *http.Request, uri url.URL) (TokenResponse, error) {
	var (
		tokenResponse TokenResponse
	)
	r.ParseForm()
	code, state := r.Form.Get("code"), r.Form.Get("state")
	if state != ar.State {
		return TokenResponse{}, errors.New("invalid_state")
	}
	tokenRequest := TokenRequest{
		RedirectUri:  ar.RedirectUri,
		Code:         code,
		GrantType:    AuthorizationCode_en_us,
		ClientId:     ar.ClientId,
		CodeVerifier: ar.CodeChallenge,
	}
	params := url.Values{}
	encoder := schema.NewEncoder()
	err := encoder.Encode(tokenRequest, params)
	if err != nil {
		return TokenResponse{}, errInternalServerError
	}
	uri.RawQuery = params.Encode()
	responseBody, err := httpPostForm(uri)
	if err != nil {
		var errorResponse ErrorResponse
		if err = json.Unmarshal(responseBody, &errorResponse); err != nil {
			return TokenResponse{}, errInternalServerError
		}
		return TokenResponse{}, errors.New(string(errorResponse.Error))
	}
	if err = json.Unmarshal(responseBody, &tokenResponse); err != nil {
		return TokenResponse{}, errInternalServerError
	}
	return tokenResponse, nil
}

// InitPresentationRequest generates a url which can be used to generate a qr-code
func (ar *AuthorizationRequest) InitiatePresentationRequest() (string, error) {
	params, err := ar.CreateAuthorizationRequestForm()
	if err != nil {
		return "", err
	}
	response := &url.URL{Scheme: "openid", Host: "", Path: ""}
	response.RawQuery = params.Encode()
	return response.String(), nil
}

// RedirectPresentationRequest redirects to an initiate request
func (ar *AuthorizationRequest) RedirectPresentationRequest(w http.ResponseWriter, r *http.Request) {
	response, err := ar.InitiatePresentationRequest()
	if err != nil {
		ResponseError(w, err)
	}
	w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
	http.Redirect(w, r, response, http.StatusFound)
}

// ReceiveAuthorizationResponse receives the authorization response
func (ar *AuthorizationRequest) ReceiveAuthorizationResponse(r *http.Request) (AuthorizationResponse, error) {
	var (
		authResponse AuthorizationResponse
	)
	err := r.ParseForm()
	if err != nil {
		return AuthorizationResponse{}, err
	}
	decoder := schema.NewDecoder()
	err = decoder.Decode(&authResponse, r.Form)
	if err != nil {
		return AuthorizationResponse{}, err
	}
	_, err = GetByClientState(ar.ClientId, authResponse.State)
	if err != nil {
		return AuthorizationResponse{}, err
	}
	return authResponse, nil
}

// CreateAuthorizationResponse returns a url for the openid authorization response
func (ar *AuthorizationRequest) CreateAuthorizationResponse(options ...VPTokenOption) (*url.URL, error) {
	var (
		params       url.Values
		authResponse AuthorizationResponse
	)
	p := presentation{}
	// Push the options into the config
	for _, opt := range options {
		opt(&p)
	}
	response, _ := url.Parse(ar.RedirectUri)
	params = response.Query()

	responseTypes := strings.Split(ar.ResponseType.String(), " ")
	for _, v := range responseTypes {
		// Validate depending on response_type
		switch v {
		case Code.String(): // The authorization request is a open id request for credential issuance
			// generate an authorization code for the token request
			randomBytes, _ := generateRandomBytes(32)
			authResponse.Code = base64.RawURLEncoding.EncodeToString(randomBytes)
			authResponse.State = ar.State

			if err := authResponse.StoreCodeGranted(); err != nil {
				return nil, errInternalServerError
			}

		case VPToken.String(): // The authorization request is a open id request for credential presentation
			if strings.TrimSpace(p.vpToken) == "" {
				return nil, errors.New("missing_vp_token")
			}
			if strings.TrimSpace(p.presentSub) == "" {
				return nil, errors.New("missing_presentation_submission")
			}
			authResponse.PresentationToken = p.vpToken
			authResponse.PresentSubmission = p.presentSub
			authResponse.State = ar.State

		case IdToken.String(): // The authorization request includes a request for an id token
			if strings.TrimSpace(p.idToken) == "" {
				return nil, errors.New("missing_id_token")
			}
			// Section A5.1 states
			// response_type is set to id_token.
			// If the request also includes a presentation_definition parameter, the wallet is supposed to return
			// the presentation_submission and vp_token parameters in the same response as the id_token parameter.
			if strings.TrimSpace(ar.PresentDef)+strings.TrimSpace(ar.PresentDefUri) != "" {
				if strings.TrimSpace(p.vpToken) == "" {
					return nil, errors.New("missing_vp_token")
				}
				if strings.TrimSpace(p.presentSub) == "" {
					return nil, errors.New("missing_presentation_submission")
				}
				authResponse.PresentationToken = p.vpToken
				authResponse.PresentSubmission = p.presentSub
			}
			authResponse.IdentityToken = p.idToken
			authResponse.State = ar.State
		}
	}
	// store the authorization request for the next episode of the issuance saga
	if err := ar.StoreClientRedirectUri(); err != nil {
		return nil, errInternalServerError
	}
	encoder := schema.NewEncoder()
	err := encoder.Encode(authResponse, params)
	if err != nil {
		return nil, errInternalServerError
	}
	response.RawQuery = params.Encode()
	return response, nil
}

// Validate validates the content of the authorization request
func (ar *AuthorizationRequest) Validate() error {
	// Validate the standard oauth2 values
	if err := ar.validateRFC6749(); err != nil {
		return err
	}
	// Vailidate par request
	if err := ar.validateRFC9126(); err != nil {
		return err
	}

	responseTypes := strings.Split(ar.ResponseType.String(), " ")
	for _, v := range responseTypes {
		// Validate depending on response_type
		switch v {
		case Code.String(): // The authorization request is a open id request for credential issuance
			// Validate pkce values
			if err := ar.validateRFC7636(); err != nil {
				return err
			}
			// The credential issuance is an OAuth 2.0 Rich Authorization Requests
			// See https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rar-11
			if strings.TrimSpace(ar.AuthorizationDetails) != "" {
				if err := ar.validateRichAuthorizationDetails(); err != nil {
					return err
				}
			}
		case VPToken.String(): // The authorization request is a open id request for credential presentation
			if err := ar.validatePresentDef(); err != nil {
				return err
			}
		case IdToken.String():
			// no additional validations
		}
	}
	return nil
}

// validateRFC6749 validates the authorization request against rfc 6749
func (ar *AuthorizationRequest) validateRFC6749() error {
	// response_type is required
	if strings.TrimSpace(ar.ResponseType.String()) == "" {
		return errors.New("missing_response_type")
	} else {
		responseTypes := strings.Split(ar.ResponseType.String(), " ")
		switch len(responseTypes) {
		case 1:
			// check if the response type is supported, can be code or vp_token
			if !contains([]string{Code.String(), VPToken.String()}, responseTypes[0]) {
				return errUnsupportedResponseType
			}
		case 2:
			// when multiple response types, vp_token must be part of it
			if !contains(responseTypes, VPToken.String()) {
				return errUnsupportedResponseType
			}
			// the other response_type must be id_token
			if !contains(responseTypes, IdToken.String()) {
				return errUnsupportedResponseType
			}
		default:
			// not accepted
			return errUnsupportedResponseType
		}
	}

	//client_id is required
	if strings.TrimSpace(ar.ClientId) == "" {
		return errors.New("missing_client_id")
	}
	// redirect_uri is required
	if strings.TrimSpace(ar.RedirectUri) == "" {
		return errors.New("missing_redirect_uri")
	}
	// redirect_uri must be a fully qualified domain name (fqdn)
	if _, err := url.ParseRequestURI(ar.RedirectUri); err != nil {
		return errors.New("invalid_redirect_uri")
	}
	scope := strings.Split(ar.Scope, ",")
	// Request parameter scope MUST contain openid
	if !contains(scope, "openid") {
		return errInvalidScope
	}
	return nil
}

// validateRFC9126 validates the authorization request against rfc 9126 Pushed Authorization Request
func (ar *AuthorizationRequest) validateRFC9126() error {
	if strings.TrimSpace(ar.RequestUri) != "" {
		return errors.New("invalid_request_uri")
	}
	return nil
}

// validateRFC7636 validates the authorization request against rfc 7636
func (ar *AuthorizationRequest) validateRFC7636() error {
	if strings.TrimSpace(ar.CodeChallenge) == "" {
		return errors.New("missing_code_challenge")
	}
	if strings.TrimSpace(ar.CodeChallenge) != "" && (len(ar.CodeChallenge) < 43 || len(ar.CodeChallenge) > 128) {
		return errors.New("invalid_code_challenge")
	}
	if !contains([]string{CodeChallengePlain.String(), CodeChallengeS256.String()}, ar.CodeChallengeMethod.String()) {
		return errors.New("unsupported_code_challenge")
	}
	return nil
}

// validateRichAuthorizationDetails validates the authorization request against the rich authorization details specifications
func (ar *AuthorizationRequest) validateRichAuthorizationDetails() error {
	// verify the uthorization_details request parameter
	authorizationDetails := []AuthorizationDetails{}
	err := json.Unmarshal([]byte(ar.AuthorizationDetails), &authorizationDetails)
	if err != nil {
		return errInternalServerError
	}
	for _, element := range authorizationDetails {
		if element.Type != "openid_credential" {
			return errors.New("unsupported_type")
		}
		// types and credential_definition are conditional, one of both must be present
		if len(element.CredentialTypes) > 0 {
			if strings.TrimSpace(element.CredentialTypes[0].String()) == "" {
				return errors.New("missing_credential_types")
			}
		} else {
			if strings.TrimSpace(element.CredentialDefinition) == "" {
				return errors.New("missing_credential_type_or_definition")
			}
		}
		// Openid specificies three Credential formats for W3C Verifiable Credentials
		// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-w3c-verifiable-credentials
		if !contains([]string{VCJwtFormat.String(), VCJwtJsonldFormat.String(), VCJsonldFormat.String()}, element.Format) {
			return errors.New("unsupported_format")
		}
	}
	return nil
}

// validatePresentDef validates the presentation definition json schema
// presentation defintion is required when the response_type is vp_token
func (ar *AuthorizationRequest) validatePresentDef() error {
	var (
		presentdef string
	)
	// The authorization request is a open id for presentations request
	if strings.TrimSpace(ar.PresentDefUri) != "" {
		if _, err := url.ParseRequestURI(ar.PresentDefUri); err != nil {
			return errors.New("invalid_presentation_definition_uri")
		}
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr}
		response, err := client.Get(ar.PresentDef)
		if err != nil {
			return errors.New("unresolvable_presentation_definition_uri")
		}
		defer response.Body.Close()

		switch response.StatusCode {
		case http.StatusOK, http.StatusFound:
			bodyBytes, err := io.ReadAll(response.Body)
			if err != nil {
				return errInternalServerError
			}
			presentdef = string(bodyBytes)
		default:
			return errors.New("unresolvable_presentation_definition_uri")
		}
	} else {
		// presentation definition uri is empty, check if presentation defintion is valid
		presentdef, _ = url.QueryUnescape(ar.PresentDef)
	}
	if strings.TrimSpace(presentdef) == "" {
		return errors.New("missing_presentation_definition")
	}
	// compile the presentation definiton to check if its a valid json schema
	// requires import of "github.com/santhosh-tekuri/jsonschema/v5"
	//compiler := jsonschema.NewCompiler()
	//compiler.Draft = jsonschema.Draft2020
	//compiler.AssertContent = true
	//if err := compiler.AddResource("schema.json", strings.NewReader(presentdef)); err != nil {
	//	return errors.New("the presentation definition is not valid")
	//}
	//_, err := compiler.Compile("presentation.json")
	//if err != nil {
	//	return errors.New("the presentation definition is not valid")
	//}

	if strings.TrimSpace(ar.Nonce) == "" {
		return errors.New("missing_nonce")
	}
	return nil
}
