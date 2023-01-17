package openidvc

import (
	"crypto/ecdsa"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gossif/diddoc"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type ProofOfPossession struct {
	ProofType ProofType `json:"proof_type"`
	Jwt       string    `json:"jwt"`
}

type CredentialRequest struct {
	ClientId             string           `json:"client_id"`
	AuthorizationDetails string           `json:"authorization_details"`
	CNonce               string           `json:"c_nonce"`
	CNonceExpiresIn      time.Duration    `json:"c_nonce_expires_in"`
	BearerTokenSHA512    [64]byte         `json:"token_hash"`
	BearerTokenExpiresIn time.Duration    `json:"token_type"`
	Deferred             bool             `json:"deferred"`
	Format               CredentialFormat `json:"format"`
	// object containing the proof of posession of the did
	Proof ProofOfPossession `json:"proof"`
	// the following two attriutes are according to appendix E of the open id specification
	CredentialTypes      []string        `json:"types"`
	CredentialDefinition json.RawMessage `json:"credential_definition"`
}

type CredentialResponse struct {
	Format          CredentialFormat `json:"format"`
	Credential      string           `json:"credential"`
	AcceptanceToken string           `json:"acceptance_token"`
	CNonce          string           `json:"c_nonce"`
	CNonceExpiresIn time.Duration    `json:"c_nonce_expires_in"`
}

type CredentialResponseOption func(*optionalParameters)

// WithVerifiableCredentialn is the option to pass the credential for issuance
func WithVerifiableCredentialn(vc string, f CredentialFormat) CredentialResponseOption {
	return func(o *optionalParameters) {
		o.verifiableCredential = vc
		o.format = f
	}
}

// WithCredentialDeferred is the option to defer the issuance of the credential
func WithCredentialDeferred() CredentialResponseOption {
	return func(o *optionalParameters) {
		o.deferred = true
	}
}

// WithAcceptanceTokenSigningKey is the option for the algorithm and signing key
func WithAcceptanceTokenSigningKey(alg jwa.KeyAlgorithm, sigKey interface{}) CredentialResponseOption {
	return func(o *optionalParameters) {
		o.signingKey = sigKey
		o.algorithm = alg
	}
}

// NewCredentialRequest receives an open id for credential issuance request
// the options must contain the signing key of the access token
func (i *credentialIssuance) NewCredentialRequest(r *http.Request, options ...TokenResponseOption) (CredentialRequest, error) {
	authorizationHeader := r.Header.Get("Authorization")
	authorizedCredentialRequest, err := validateBearerToken(authorizationHeader, options...)
	if err != nil {
		return CredentialRequest{}, errInvalidToken
	}
	contentType := r.Header.Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		// Deferred credential request has application/x-www-form-urlencoded
		if !strings.Contains(contentType, "application/x-www-form-urlencoded") {
			return CredentialRequest{}, errors.New("invalid_content_type")
		}
	}
	credRequest := CredentialRequest{}
	decoder := json.NewDecoder(r.Body)
	// the json must match the known attributes in the struct
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&credRequest)
	if err != nil {
		return CredentialRequest{}, errInternalServerError
	}
	if err = credRequest.Validate(); err != nil {
		return CredentialRequest{}, err
	}
	credRequest.AuthorizationDetails = authorizedCredentialRequest.AuthorizationDetails
	return credRequest, nil
}

// NewDeferredCredentialRequest receives a issuance request for a deferred credential
func (i *credentialIssuance) NewDeferredCredentialRequest(r *http.Request, options ...TokenResponseOption) (CredentialRequest, error) {
	authorizationHeader := r.Header.Get("Authorization")
	authorizedCredentialRequest, err := validateBearerToken(authorizationHeader, options...)
	if err != nil {
		return CredentialRequest{}, errInvalidToken
	}
	contentType := r.Header.Get("Content-Type")
	// Deferred credential request has application/x-www-form-urlencoded
	if !strings.Contains(contentType, "application/x-www-form-urlencoded") {
		return CredentialRequest{}, errors.New("invalid_content_type")
	}
	return authorizedCredentialRequest, nil
}

// Validate validates the credential request (only content)
// The client id should be the host of the
func (c *CredentialRequest) Validate() error {
	// openid specificies three Credential formats for W3C Verifiable Credentials
	// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-w3c-verifiable-credentials
	if !contains([]string{VCJwtFormat.String(), VCJwtJsonldFormat.String(), VCJsonldFormat.String()}, c.Format.String()) {
		return errUnsupportedCredFormat
	}
	if c.Proof != (ProofOfPossession{}) {
		if c.Proof.ProofType != JwtProofType {
			return errInvalidProof
		}
		// parse the jwt
		proofOfPossession, err := jwt.Parse([]byte(c.Proof.Jwt), jwt.WithVerify(false), jwt.WithValidate(false))
		if err != nil {
			return errInternalServerError
		}
		privateClaims := proofOfPossession.PrivateClaims()
		if nonceValue, ok := privateClaims["nonce"].(string); ok {
			// validate if the proof of possession is issued with the same c_nonce of the credential request authorized
			// when the c_nonce is expired, the authorized credential request is not found
			authorizedCredentialRequest, err := GetCredentialIssuanceByCNonce(nonceValue)
			if err != nil {
				return errors.New("invalid_nonce")
			}
			// check if the client is the samen as in the authorization request
			if proofOfPossession.Issuer() != authorizedCredentialRequest.ClientId {
				return errors.New("invalid_client_id")
			}
		} else {
			// if nonce not in the jwt, then invalid request
			return errInvalidProof
		}
		if jwkValue, ok := privateClaims["jwk"]; ok {
			switch jwkValue := jwkValue.(type) {
			case map[string]interface{}:
				jwkBytes, err := json.Marshal(jwkValue)
				if err != nil {
					return err
				}
				err = c.validateNaturalPerson(string(jwkBytes))
				if err != nil {
					return err
				}
			case string:
				err = c.validateNaturalPerson(jwkValue)
				if err != nil {
					return errInvalidProof
				}
			}
		} else {
			// proof of possession for legal entity
			return c.validateLegalEntity()
			//return errors.New("legal entity not supported")
		}
	}
	return nil
}

// ValidateNaturalPerson validates the proof of possession for a natural person
func (c *CredentialRequest) validateNaturalPerson(key string) error {
	var publicKey interface{}
	if err := jwk.ParseRawKey([]byte(key), &publicKey); err != nil {
		return errInternalServerError
	}
	switch publicKey.(type) {
	case *ecdsa.PublicKey:
		_, err := jwt.Parse([]byte(c.Proof.Jwt), jwt.WithKey(jwa.ES256, publicKey), jwt.WithAudience(GetProviderMetadata().Issuer))
		if err != nil {
			return err
		}
	default:
		return errors.New("unsupported_key_type")
	}
	return nil
}

// ValidateLegalEntity validates the proof of possession for a legal entity
func (c *CredentialRequest) validateLegalEntity() error {
	token, err := jws.Parse([]byte(c.Proof.Jwt))
	if err != nil {
		return err
	}
	// While JWT enveloped with JWS in compact format only has 1 signature,
	// a generic JWS message may have multiple signatures. Therefore we
	// need to access the first element
	keyId := token.Signatures()[0].ProtectedHeaders().KeyID()
	if keyId == "" {
		return errors.New("missing_key_id")
	}
	jwkKey, err := c.getJWKKeyFromDid(keyId)
	if err != nil {
		return err
	}
	_, err = jwt.Parse([]byte(c.Proof.Jwt), jwt.WithAudience(GetProviderMetadata().Issuer), jwt.WithKey(jwa.ES256, jwkKey))
	if err != nil {
		return err
	}
	return nil
}

func (c *CredentialRequest) getJWKKeyFromDid(keyId string) (jwk.Key, error) {
	// get the did from the key id
	arrKeyId := strings.Split(keyId, "#")
	if len(arrKeyId) == 0 {
		return nil, errors.New("invalid_key_id")
	}
	// Proof posession for legal entity
	diddoc, err := c.ResolveDid(arrKeyId[0])
	if err != nil {
		return nil, err
	}
	verificationMethod, err := diddoc.GetVerificationMethodById(keyId)
	if err != nil {
		return nil, err
	}
	// Serialize the key to json
	jsonbuf, err := json.Marshal(verificationMethod.PubicKeyJWK)
	if err != nil {
		return nil, err
	}
	// Parse the json to jwk.Key
	return jwk.ParseKey(jsonbuf)
}

// ResolveDid resolves a did from ebsi
func (c *CredentialRequest) ResolveDid(didString string) (diddoc.Document, error) {
	// requester must be a legal entity, as natural person are not registered on ebsi
	registry := NewDecetralizedIdentifierRegistry()
	rawdoc, err := registry.ResolveDid(didString)
	if err != nil {
		return diddoc.Document{}, err
	}
	var inputjson []byte
	switch r := rawdoc.(type) {
	case string:
		inputjson = []byte(r)
	case []byte:
		inputjson = r
	case map[string]interface{}:
		inputjson, _ = json.Marshal(r)
	}
	var doc diddoc.Document
	json.Unmarshal(inputjson, &doc)
	if err != nil {
		return diddoc.Document{}, err
	}
	return doc, nil
}

// CreateCredentialResponse creates the credential response that can be used in the http response
// the function uses the verifiableCredential and deferred parameters to indicate a direct issuance or a deferred issuance
func (c *CredentialRequest) CreateCredentialResponse(options ...CredentialResponseOption) (CredentialResponse, error) {
	o := optionalParameters{}
	// Push the options into the config
	for _, opt := range options {
		opt(&o)
	}
	if o.deferred {
		if err := o.checkRequired([]string{"signingKey", "algorithm"}); err != nil {
			return CredentialResponse{}, err
		}
		authorizedCredentialRequest := CredentialRequest{
			ClientId:             c.ClientId,
			AuthorizationDetails: c.AuthorizationDetails,
			CNonceExpiresIn:      GetServerConfig().ExpirationTime,
			BearerTokenExpiresIn: GetServerConfig().ExpirationTime,
			Deferred:             true,
		}
		authorizedCredentialRequest.CNonce, _ = generateNonce()

		acceptanceToken, err := authorizedCredentialRequest.createBearerToken(WithAccessTokenSigningKey(o.algorithm, o.signingKey))
		if err != nil {
			return CredentialResponse{}, err
		}
		authorizedCredentialRequest.BearerTokenSHA512 = sha512.Sum512(acceptanceToken)

		// Store the bearer token, so we can verify it up when the credential requests arrives
		if err := authorizedCredentialRequest.StoreCredentialRequest(); err != nil {
			return CredentialResponse{}, err
		}
		return CredentialResponse{
			AcceptanceToken: string(acceptanceToken),
			CNonce:          authorizedCredentialRequest.CNonce,
			CNonceExpiresIn: authorizedCredentialRequest.CNonceExpiresIn,
		}, nil
	}
	if err := o.checkRequired([]string{"verifiableCredential"}); err != nil {
		return CredentialResponse{}, err
	}
	if !contains([]string{VCJsonldFormat.String(), VCJwtFormat.String(), string(VCJwtJsonldFormat)}, o.format.String()) {
		return CredentialResponse{}, errors.New("invalid_format")
	}
	// return the request_uri and expiration time
	return CredentialResponse{
		Format:     o.format,
		Credential: o.verifiableCredential,
	}, nil
}

// generateAccessToken generates the access token for the token response
// but also the acceptance token for a deferred credential request, acceptance token is used as access token
func (c *CredentialRequest) createBearerToken(options ...TokenResponseOption) ([]byte, error) {
	o := optionalParameters{}
	// Push the options into the config
	for _, opt := range options {
		opt(&o)
	}
	issuer := GetProviderMetadata().Issuer
	if err := o.checkRequired([]string{"signingKey", "algorithm"}); err != nil {
		return nil, err
	}
	accessToken, err := jwt.NewBuilder().
		Issuer(issuer).
		Audience([]string{issuer}).
		Subject(c.ClientId).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(GetServerConfig().ExpirationTime)).
		Claim("nonce", c.CNonce).
		Claim("scope", "credential_issuance").
		Build()
	if err != nil {
		return nil, err
	}
	serialized, err := jwt.Sign(accessToken, jwt.WithKey(o.algorithm, o.signingKey))
	if err != nil {
		return nil, err
	}
	return serialized, nil
}

// ValidateAuthorization validates the access token
func validateBearerToken(authorizationHeader string, options ...TokenResponseOption) (CredentialRequest, error) {
	// Remove the prefix from the authorization header
	bearerToken := strings.TrimPrefix(authorizationHeader, "Bearer ")
	if len(bearerToken) <= 0 {
		return CredentialRequest{}, errors.New("invalid_authorization_header")
	}
	// Check if the authorization header has bearer as prefix
	if !strings.HasPrefix(authorizationHeader, "Bearer ") {
		return CredentialRequest{}, errors.New("bearer_not_found")
	}
	credRequest, err := GetCredentialRequestSecure(bearerToken)
	if err != nil {
		return CredentialRequest{}, errors.New("invalid_token")
	}
	// Verify the validity of the token
	o := optionalParameters{}
	// Push the options into the config
	for _, opt := range options {
		opt(&o)
	}
	issuer := GetProviderMetadata().Issuer
	if err = o.checkRequired([]string{"signingKey", "algorithm"}); err != nil {
		return CredentialRequest{}, err
	}
	verifiedToken, err := jwt.Parse([]byte(bearerToken), jwt.WithKey(o.algorithm, o.signingKey), jwt.WithValidate(true), jwt.WithAudience(issuer))
	if err != nil {
		return CredentialRequest{}, err
	}
	privateClaims := verifiedToken.PrivateClaims()
	// check if the nonce is equal as issued with the token respnse
	nonce, ok := privateClaims["nonce"].(string)
	if !ok {
		return CredentialRequest{}, errors.New("missing_nonce")
	}
	if nonce != credRequest.CNonce {
		return CredentialRequest{}, errors.New("invalid_nonce")
	}
	return *credRequest, nil
}
