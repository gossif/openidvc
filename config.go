package openidvc

import (
	"errors"
	"strings"
	"time"

	"github.com/spf13/viper"
)

type ServerConfig struct {
	ExpirationTime time.Duration `mapstructure:"expiration_time"`
}

// Metadata implements rfc8414 Authorization Server Metadata (only required parameters)
type ProviderMetadata struct {
	// OpenID Connect Discovery 1.0 incorporating errata set 1
	Issuer                     string         `json:"issuer" mapstructure:"issuer"`
	AuthorizationEndpoint      string         `json:"authorization_endpoint" mapstructure:"authorization_endpoint"`
	TokenEndpoint              string         `json:"token_endpoint" mapstructure:"token_endpoint"`
	JwksUri                    string         `json:"jwks_uri" mapstructure:"jwks_uri"`
	ResponseTypesSupported     []ResponseType `json:"response_types_supported" mapstructure:"response_types_supported"`
	SubjectTypesSupported      []SubjectType  `json:"subject_types_supported" mapstructure:"subject_types_supported"`
	IdTokenSigningAlgSupported []string       `json:"id_token_signing_alg_values_supported" mapstructure:"id_token_signing_alg_values_supported"`

	// RFC9126 Pushed Authorization Requests
	PushedEndpoint string `json:"pushed_authorization_request_endpoint" mapstructure:"pushed_authorization_request_endpoint"`
	RequirePushed  bool   `json:"require_pushed_authorization_requests" mapstructure:"require_pushed_authorization_requests"`

	// OpenID for Verifiable Credential Issuance
	CredentialEndpoint   string                   `json:"credential_endpoint" mapstructure:"credential_endpoint"`
	CredentialsSupported []map[string]interface{} `json:"credentials_supported" mapstructure:"credentials_supported"`

	// OpenID for Verifiable Presentations
	PresentationFormats map[string]interface{} `json:"vp_formats_supported" mapstructure:"vp_formats_supported"`
}

type ClientMetadata map[string]interface{}

type Metadata struct {
	Versions         map[string]float32 `mapstructure:"versions"`
	ServerConfig     ServerConfig       `mapstructure:"config"`
	ProviderMetadata ProviderMetadata   `mapstructure:"provider"`
	ClientMetadata   ClientMetadata     `mapstructure:"client"`
}

var (
	metadata *Metadata
)

func init() {
	viper.SetConfigName("metadata") // config file name without extension
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./config/") // config file path
	if err := viper.ReadInConfig(); err != nil {
		panic(err)
	}
	metadata = &Metadata{}
	metadata.ServerConfig.ExpirationTime = (time.Minute * 5)
	// When a config file is present, use it
	if err := viper.ReadInConfig(); err == nil {
		_ = viper.Unmarshal(&metadata)
	}
	if strings.TrimSpace(metadata.ProviderMetadata.Issuer) == "" {
		panic(errors.New("issuer is required"))
	}
}

func GetServerConfig() *ServerConfig {
	return &metadata.ServerConfig
}

func GetProviderMetadata() *ProviderMetadata {
	return &metadata.ProviderMetadata
}

func SetIssuer(issuer string) {
	metadata.ProviderMetadata.Issuer = issuer
}

func SetExpirationTime(expirationTime time.Duration) {
	metadata.ServerConfig.ExpirationTime = expirationTime
}
