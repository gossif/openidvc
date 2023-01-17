package openidvc

import (
	"encoding/json"
	"errors"
	"net/http"
)

var (
	Rfc6749Errors map[string]int = map[string]int{
		"invalid_request":           http.StatusBadRequest,
		"unauthorized_client":       http.StatusUnauthorized,
		"access_denied":             http.StatusForbidden,
		"unsupported_response_type": http.StatusBadRequest,
		"invalid_scope":             http.StatusBadRequest,
		"server_error":              http.StatusInternalServerError,
		"temporarily_unavailable":   http.StatusServiceUnavailable,
	}
	OpenidIssuanceErrors map[string]int = map[string]int{
		"invalid_request":               http.StatusBadRequest,
		"invalid_token":                 http.StatusForbidden,
		"unsupported_credential_type":   http.StatusBadRequest,
		"unsupported_credential_format": http.StatusBadRequest,
		"invalid_or_missing_proof":      http.StatusBadRequest,
	}
)

// The errors specified in rfc6749
var (
	errInvalidRequest          = errors.New("invalid_request")
	errUnauthorizedClient      = errors.New("unauthorized_client")
	errAccessDenied            = errors.New("access_denied")
	errUnsupportedResponseType = errors.New("unsupported_response_type")
	errInvalidScope            = errors.New("invalid_scope")
	errInternalServerError     = errors.New("server_error")
	errTemporarilyUnavailable  = errors.New("temporarily_unavailable")

	// Extensions from open id for credential issuance
	errInvalidToken          = errors.New("invalid_token")
	errUnsupportedCredType   = errors.New("unsupported_credential_type")
	errUnsupportedCredFormat = errors.New("unsupported_credential_format")
	errInvalidProof          = errors.New("invalid_or_missing_proof")
)

// ErrorResponse is the oauth2 error response format
type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorUri         string `json:"error_uri,omitempty"`
}

// CreateErrorResponse returns the oauth2 error response for an authorization request
func createErrorResponse(err error) (ErrorResponse, int) {

	switch err {
	case errUnauthorizedClient,
		errAccessDenied,
		errUnsupportedResponseType,
		errInvalidScope,
		errInternalServerError,
		errTemporarilyUnavailable:

		return ErrorResponse{Error: err.Error()}, Rfc6749Errors[err.Error()]

	default:
		// default to invalid request
		return ErrorResponse{Error: errInvalidRequest.Error()}, Rfc6749Errors[errInvalidRequest.Error()]
	}
}

// createCredentialErrorResponse returns the openid credential error response for an credential request
func createCredentialErrorResponse(err error) (ErrorResponse, int) {

	switch err {
	case errInvalidToken,
		errUnsupportedCredType,
		errUnsupportedCredFormat,
		errInvalidProof:
		// Extensions from open id for credential issuance
		return ErrorResponse{Error: err.Error()}, OpenidIssuanceErrors[err.Error()]

	default:
		// default to invalid request
		return ErrorResponse{Error: errInvalidRequest.Error()}, OpenidIssuanceErrors[errInvalidRequest.Error()]
	}
}

func ResponseError(w http.ResponseWriter, err error) {
	response, httpStatus := createErrorResponse(err)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(httpStatus)
	json.NewEncoder(w).Encode(response)
}

func CredentialResponseError(w http.ResponseWriter, err error) {
	response, httpStatus := createCredentialErrorResponse(err)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(httpStatus)
	json.NewEncoder(w).Encode(response)
}
