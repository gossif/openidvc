package openidvc

import (
	"net/http"
	"strings"
)

// AutorizationRequestHandler is a http handler to handle the authorization request
// the autorization qequest handler can only handle a single authorization code flow
// it can not handle multiple repsonse_types
func AutorizationRequestHandler(w http.ResponseWriter, r *http.Request) {
	op := NewOpenIdProvider()
	authRequest, err := op.NewAuthorizationRequest(r)
	if err != nil {
		ResponseError(w, err)
		return
	}
	// the autorization qequest handler can only handle the single authorization code flow
	// the vp_token flow requires a verifiable presentation in the response, which is not available in this function
	responseTypes := strings.Split(authRequest.ResponseType.String(), " ")
	if len(responseTypes) > 1 {
		// multiple response_types can not be handled with this handler
		ResponseError(w, errInvalidRequest)
		return
	}
	if !contains(responseTypes, Code.String()) {
		ResponseError(w, errInvalidRequest)
		return
	}
	response, err := authRequest.CreateAuthorizationResponse()
	if err != nil {
		ResponseError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
	http.Redirect(w, r, response.String(), http.StatusFound)
}
