package config

import "github.com/fiware/VCVerifier/logging"

// CONFIGURATION STRUCTURE FOR THE VERIFIER CONFIG

// general structure of the configuration file
type Configuration struct {
	Server     Server                `mapstructure:"server"`
	Verifier   Verifier              `mapstructure:"verifier"`
	Logging    logging.LoggingConfig `mapstructure:"logging"`
	ConfigRepo ConfigRepo            `mapstructure:"configRepo"`
	M2M        M2M                   `mapstructure:"m2m"`
	Elsi       Elsi                  `mapstructure:"elsi"`
}

// general configuration to run the application
type Server struct {
	// host name of the verifier
	Host string `mapstructure:"host"`
	// port to bind the server
	Port int `mapstructure:"port" default:"8080"`
	// directory to read the template(s) from
	TemplateDir string `mapstructure:"templateDir" default:"views/"`
	// directory of static files to be provided, f.e. to be used inside the templates
	StaticDir string `mapstructure:"staticDir" default:"views/static/"`

	// ReadTimeout is the maximum duration for reading the entire request, including the body.
	ReadTimeout int `mapstructure:"readTimeout" default:"5"`
	// WriteTimeout is the maximum duration before timing out writes of the response.
	WriteTimeout int `mapstructure:"writeTimeout" default:"10"`
	// IdleTimeout is the maximum amount of time to wait for the next request when keep-alives are enabled.
	IdleTimeout int `mapstructure:"idleTimeout" default:"120"`
	// ShutdownTimeout is the time allowed for active requests to finish during shutdown.
	ShutdownTimeout int `mapstructure:"shutdownTimeout" default:"5"`
}

// configuration for M2M interaction
type M2M struct {
	// auth enabled for M2M interactions
	AuthEnabled bool `mapstructure:"authEnabled"`
	// path to the signing key(in pem format)
	KeyPath string `mapstructure:"keyPath"`
	// path to the credential to be used for auth
	CredentialPath string `mapstructure:"credentialPath"`
	// id of the verifier when retrieving tokens
	ClientId string `mapstructure:"clientId"`
	// verification method to be provided for the ld-proof
	VerificationMethod string `mapstructure:"verificationMethod" default:"JsonWebKey2020"`
	// signature type to be provided for the ld-proof
	SignatureType string `mapstructure:"signatureType" default:"JsonWebSignature2020"`
	// type of the provided key
	KeyType string `mapstructure:"keyType" default:"RSAPS256"`
}

// configuration specific to the functionality of the verifier
type Verifier struct {
	// did to be used by the verifier
	Did string `mapstructure:"did"`
	// Identification to be used for the verifier
	ClientIdentification ClientIdentification `mapstructure:"clientIdentification"`
	// supported request modes - currently 'urlEncoded', 'byValue' and 'byReference' are available. In case of byValue, the keyPath has to be set.
	SupportedModes []string `mapstructure:"supportedModes" default:"urlEncoded"`
	// address of the (ebsi-compatible) trusted-issuers-registry for verifying the issuer
	TirAddress string `mapstructure:"tirAddress"`
	// expiry of the tir-cache entries
	TirCacheExpiry int `mapstructure:"tirCacheExpiry" default:"30"`
	// expiry of the til-cache entries
	TilCacheExpiry int `mapstructure:"tilCacheExpiry" default:"30"`
	// expiry of auth sessions
	SessionExpiry int `mapstructure:"sessionExpiry" default:"30"`
	// policies that shall be checked
	PolicyConfig Policies `mapstructure:"policies"`
	// path of the authorizationEndpoint to be provided in the .well-known/openid-configuration
	AuthorizationEndpoint string `mapstructure:"authorizationEndpoint"`
	// Validation mode for validating the vcs. Does not touch verification, just content validation.
	// applicable modes:
	// * `none`: No validation, just swallow everything
	// * `combined`: ld and schema validation
	// * `jsonLd`: uses JSON-LD parser for validation
	// * `baseContext`: validates that only the fields and values (when applicable)are present in the document. No extra fields are allowed (outside of credentialSubject).
	// Default is set to `none` to ensure backwards compatibility
	ValidationMode string `mapstructure:"validationMode" default:"none"`
	// algorithm to be used for the jwt signatures - currently supported: RS256 and ES256
	KeyAlgorithm string `mapstructure:"keyAlgorithm" default:"RS256"`
	// when set to true, the private key is generated on startup. Its not persisted and just kept in memory.
	GenerateKey bool `mapstructure:"generateKey" default:"true"`
	// path to the private key for jwt signatures
	KeyPath string `mapstructure:"keyPath"`
	// expiration time in minutes for JWT tokens
	JwtExpiration int `mapstructure:"jwtExpiration" default:"30"`
}

type ClientIdentification struct {
	// path to the did signing key(in pem format) for request object mode
	KeyPath string `mapstructure:"keyPath"`
	// algorithm used for the request signing key
	KeyAlgorithm string `mapstructure:"requestKeyAlgorithm"`
	// identification used by the verifier when requesting authorization. Can be a did, but also methods like x509_san_dns
	Id string `mapstructure:"id"`
	// optional path to the certifcate to embed in the jwt header
	CertificatePath string `mapstructure:"certificatePath"`
	// Kid used when key certificate does not include it. If both are missing, id is used
	Kid string `mapstructure:"kid"`
}

type Elsi struct {
	// should the support for did:elsi be enabled
	Enabled bool `mapstructure:"enabled" default:"false"`
	// endpoint of the validation service to be used for JAdES signatures
	ValidationEndpoint *ValidationEndpoint `mapstructure:"validationEndpoint"`
}

type ValidationEndpoint struct {
	Host           string `mapstructure:"host"`
	ValidationPath string `mapstructure:"validationPath" default:"/validateSignature"`
	HealthPath     string `mapstructure:"healthPath" default:"/q/health/ready"`
}

type Policies struct {
	// policies that all credentials are checked against
	DefaultPolicies PolicyMap `mapstructure:"default"`
	// policies that used to check specific credential types. Key maps to the "credentialSubject.type" of the credential
	CredentialTypeSpecificPolicies map[string]PolicyMap `mapstructure:"credentialTypeSpecific"`
}

type ConfigRepo struct {
	// url of the configuration service to be used
	ConfigEndpoint string `mapstructure:"configEndpoint"`
	// statically configured services with their trust anchors and scopes.
	Services       []ConfiguredService `mapstructure:"services"`
	UpdateInterval int64               `mapstructure:"updateInterval" default:"30"`
}

type PolicyMap map[string]PolicyConfigParameters

type PolicyConfigParameters map[string]interface{}
