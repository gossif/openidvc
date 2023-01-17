package openidvc

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

// OpenId4VCPushedAuthResponse is an oauth2 pushed authorizarion response
type PushedAuthorizationResponse struct {
	RequestUri string        `json:"request_uri"`
	ExpiresIn  time.Duration `json:"expires_in"`
}

// PushedAutorizationRequestHandler is a http handler to handle the pushed authorization request
func PushedAutorizationRequestHandler(w http.ResponseWriter, r *http.Request) {
	authRequest, err := NewOpenIdProvider().NewPushedAuthorizationRequest(r)
	if err != nil {
		ResponseError(w, err)
		return
	}
	if err = authRequest.Validate(); err != nil {
		ResponseError(w, err)
		return
	}
	response, err := authRequest.CreatePushedAuthorizationResponse()
	if err != nil {
		ResponseError(w, err)
		return
	}
	// setting the content type in the header must be first, before writing the status to the header
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// NewPushedAuthorizationRequest receives the pushed authorization request
func (o *oauth2Request) NewPushedAuthorizationRequest(r *http.Request) (AuthorizationRequest, error) {
	// pushed authorization request is the same as the authorization requast
	// rfc 9126, OAuth 2.0 Pushed Authorization Requests
	authhRequest, err := o.NewAuthorizationRequest(r)
	if err != nil {
		return AuthorizationRequest{}, err
	}
	if strings.TrimSpace(authhRequest.RequestUri) != "" {
		return AuthorizationRequest{}, errors.New("invalid_request_uri")
	}
	return authhRequest, nil
}

// PostFormPushedAuthorizationRequest posts an pushed authorization request for credential issuance from the holder to the issuer
func (ar *AuthorizationRequest) PostFormPushedAuthorizationRequest(uri url.URL) (PushedAuthorizationResponse, error) {
	params, err := ar.CreateAuthorizationRequestForm()
	if err != nil {
		return PushedAuthorizationResponse{}, err
	}
	uri.RawQuery = params.Encode()
	responseBody, err := httpPostForm(uri)
	if err != nil {
		var errorResponse ErrorResponse
		if err = json.Unmarshal(responseBody, &errorResponse); err != nil {
			return PushedAuthorizationResponse{}, errInternalServerError
		}
		return PushedAuthorizationResponse{}, errors.New(string(errorResponse.Error))
	}
	var pushedAuthorizationResponse PushedAuthorizationResponse
	if err = json.Unmarshal(responseBody, &pushedAuthorizationResponse); err != nil {
		return PushedAuthorizationResponse{}, errInternalServerError
	}
	return pushedAuthorizationResponse, nil
}

// CreatePushedAuthorizationResponse returns a json pushed authorization response
func (ar *AuthorizationRequest) CreatePushedAuthorizationResponse() (PushedAuthorizationResponse, error) {
	ar.RequestUri = "urn:ietf:params:oauth:request_uri:" + strings.Replace(uuid.NewString(), "-", "", -1)

	// Store the pushed request, so we can pick it up when the authorization requests arrives
	if err := ar.StoreRequestUri(); err != nil {
		return PushedAuthorizationResponse{}, errInternalServerError
	}

	// return the request_uri and expiration time
	return PushedAuthorizationResponse{
		RequestUri: ar.RequestUri,
		ExpiresIn:  GetServerConfig().ExpirationTime,
	}, nil
}
