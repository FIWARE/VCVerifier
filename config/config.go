package config

// CONFIGURATION STRUCTURE FOR THE VERIFIER CONFIG

// general structure of the configuration file
type Configuration struct {
	Server     Server     `mapstructure:"server"`
	Verifier   Verifier   `mapstructure:"verifier"`
	Logging    Logging    `mapstructure:"logging"`
	ConfigRepo ConfigRepo `mapstructure:"configRepo"`
	M2M        M2M        `mapstructure:"m2m"`
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

// logging config
type Logging struct {
	// loglevel to be used - can be DEBUG, INFO, WARN or ERROR
	Level string `mapstructure:"level" default:"INFO"`
	// should the logging in a structured json format
	JsonLogging bool `mapstructure:"jsonLogging" default:"true"`
	// should requests be logged
	LogRequests bool `mapstructure:"logRequests" default:"true"`
	// list of paths to be ignored on request logging(could be often called operational endpoints like f.e. metrics)
	PathsToSkip []string `mapstructure:"pathsToSkip"`
}

// configuration specific to the functionality of the verifier
type Verifier struct {
	// did to be used by the verifier
	Did string `mapstructure:"did"`
	// address of the (ebsi-compatible) trusted-issuers-registry for verifying the issuer
	TirAddress string `mapstructure:"tirAddress"`
	// expiry of auth sessions
	SessionExpiry int `mapstructure:"sessionExpiry" default:"30"`
	// policies that shall be checked
	PolicyConfig Policies `mapstructure:"policies"`
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
