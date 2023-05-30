package config

// CONFIGURATION STRUCTURE FOR THE VERIFIER CONFIG

// general structure of the configuration file
type Configuration struct {
	Server     Server     `mapstructure:"server"`
	Verifier   Verifier   `mapstructure:"verifier"`
	SSIKit     SSIKit     `mapstructure:"ssiKit"`
	Logging    Logging    `mapstructure:"logging"`
	ConfigRepo ConfigRepo `mapstructure:"configRepo"`
}

// configuration to be used by the ssiKit configuration
type SSIKit struct {
	// address of waltIDs auditor-endpoint
	AuditorURL string `mapstructure:"auditorURL"`
}

// general configuration to run the application
type Server struct {
	// port to bind the server
	Port int `mapstructure:"port" default:"8080"`
	// directory to read the template(s) from
	TemplateDir string `mapstructure:"templateDir" default:"views/"`
	// directory of static files to be provided, f.e. to be used inside the templates
	StaticDir string `mapstructure:"staticDir" default:"views/static/"`
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
	Services map[string]Service `mapstructure:"services"`
}

type PolicyMap map[string]PolicyConfigParameters

type PolicyConfigParameters map[string]interface{}

type Service struct {
	Scope               []string            `mapstructure:"scope"`
	TrustedParticipants map[string][]string `mapstructure:"trustedParticipants"`
	TrustedIssuers      map[string][]string `mapstructure:"trustedIssuers"`
}
