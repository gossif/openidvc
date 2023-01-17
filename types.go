package openidvc

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

type (
	ProofType           string
	GrantType           string
	ResponseType        string
	CodeChallengeMethod string
	SubjectType         string
)

const (
	// VC signed as a JWT, not using JSON-LD (jwt_vc_json)
	VCJwtFormat CredentialFormat = "jwt_vc_json"
	// VC signed as a JWT, using JSON-LD (jwt_vc_json-ld)
	VCJwtJsonldFormat CredentialFormat = "jwt_vc_json-ld"
	// VC secured using Data Integrity, using JSON-LD, with proof suite requiring Linked Data canonicalization (ldp_vc)
	VCJsonldFormat CredentialFormat = "ldp_vc"
	// proof type for the proof of possession
	JwtProofType ProofType = "jwt"
	// The rfc6749 specifies us english, ebsi and https://github.com/golang/oauth2 are using british english
	// This authorization server supports both
	AuthorizationCode_en    GrantType = "authorisation_code"
	AuthorizationCode_en_us GrantType = "authorization_code"
	// PreAuthorizationCode flow not supported yet
	//PreAuthorizationCode GrantType = "pre-authorised_code"

	Code    ResponseType = "code"
	VPToken ResponseType = "vp_token"
	IdToken ResponseType = "id_token"

	CodeChallengeS256  CodeChallengeMethod = "S256"
	CodeChallengePlain CodeChallengeMethod = "plain"

	Public SubjectType = "public"
)

type Proof struct {
	ProofType ProofType `json:"proof_type"`
	Jwt       string    `json:"jwt"`
}

type (
	CredentialFormat  string
	CredentialType    string
	CredentialSubject interface{}
)

type AuthorizationDetails struct {
	Type                 string           `json:"type"`
	Format               string           `json:"format"`
	CredentialTypes      []CredentialType `json:"types"`
	CredentialDefinition string           `json:"credential_definition"`
}

type PresentDef map[string]interface{}

type PathNested struct {
	Format string `json:"format"`
	Path   string `json:"path"`
}

type DescriptorMap struct {
	Id         string     `json:"id"`
	Format     string     `json:"format"`
	Path       string     `json:"path"`
	PathNested PathNested `json:"path_nested"`
}

type PresentationSubmission struct {
	Id            string          `json:"id"`
	DefinitionId  string          `json:"definition_id"`
	DescriptorMap []DescriptorMap `json:"descriptor_map"`
}

func (gt GrantType) String() string {
	return string(gt)
}

func (rt ResponseType) String() string {
	return string(rt)
}

func (rt CredentialFormat) String() string {
	return string(rt)
}

func (cc CodeChallengeMethod) String() string {
	return string(cc)
}

func (cc CredentialType) String() string {
	return string(cc)
}

func (ccm CodeChallengeMethod) Validate(cc, cv string) bool {
	switch ccm {
	case CodeChallengePlain:
		return cc == cv
	case CodeChallengeS256:
		s256 := sha256.Sum256([]byte(cv))
		// trim padding
		a := strings.TrimRight(base64.URLEncoding.EncodeToString(s256[:]), "=")
		b := strings.TrimRight(cc, "=")
		return a == b
	default:
		return false
	}
}

func (cf SubjectType) String() string {
	return string(cf)
}
