package helpers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DCQLConfig represents a DCQL query configuration for service scopes.
type DCQLConfig struct {
	Credentials    []CredentialQuery    `json:"credentials"`
	CredentialSets []CredentialSetQuery `json:"credential_sets,omitempty"`
}

// CredentialQuery defines a single credential query within DCQL.
type CredentialQuery struct {
	Id     string     `json:"id"`
	Format string     `json:"format"`
	Meta   *MetaQuery `json:"meta,omitempty"`
	Claims []ClaimDef `json:"claims,omitempty"`
}

// MetaQuery defines metadata constraints for a credential query.
type MetaQuery struct {
	VctValues []string `json:"vct_values,omitempty"`
}

// ClaimDef defines a claim to be requested in a DCQL query.
type ClaimDef struct {
	Path []string `json:"path"`
}

// CredentialSetQuery defines additional constraints on which credentials to return.
type CredentialSetQuery struct {
	Options [][]string `json:"options"`
	Purpose string     `json:"purpose,omitempty"`
}

// NewJWTVCQuery creates a CredentialQuery for a JWT-VC credential type.
func NewJWTVCQuery(id, credType string) CredentialQuery {
	return CredentialQuery{
		Id:     id,
		Format: "jwt_vc_json",
		Meta:   &MetaQuery{VctValues: []string{credType}},
	}
}

// NewSDJWTQuery creates a CredentialQuery for an SD-JWT credential type.
func NewSDJWTQuery(id, vctValue string) CredentialQuery {
	return CredentialQuery{
		Id:     id,
		Format: "dc+sd-jwt",
		Meta:   &MetaQuery{VctValues: []string{vctValue}},
	}
}

// ServiceConfig holds the configuration for a single service within the config builder.
type ServiceConfig struct {
	ID                string
	DefaultScope      string
	AuthorizationType string
	Scopes            map[string]*ScopeConfig
}

// ScopeConfig holds configuration for a single scope within a service.
type ScopeConfig struct {
	Credentials []CredentialConfig
	DCQL        *DCQLConfig
}

// CredentialConfig holds configuration for a single credential type within a scope.
type CredentialConfig struct {
	Type                string
	TrustedIssuersLists []string
	HolderVerification  *HolderVerificationConfig
	TrustedParticipants []TrustedParticipantsListConfig
	JwtInclusion        *JwtInclusionConfig
}

// JwtInclusionConfig defines JWT inclusion settings for a credential type.
type JwtInclusionConfig struct {
	Enabled       bool
	FullInclusion bool
}

// HolderVerificationConfig defines holder verification settings.
type HolderVerificationConfig struct {
	Enabled bool
	Claim   string
}

// TrustedParticipantsListConfig defines a trusted participants list entry.
type TrustedParticipantsListConfig struct {
	Type string
	URL  string
}

// ConfigBuilder provides a fluent API for constructing VCVerifier YAML configs.
type ConfigBuilder struct {
	verifierPort int
	tirURL       string
	signingKey   string
	services     map[string]*ServiceConfig
}

// NewConfigBuilder creates a new ConfigBuilder with the verifier port and default TIR URL.
func NewConfigBuilder(verifierPort int, tirURL string) *ConfigBuilder {
	return &ConfigBuilder{
		verifierPort: verifierPort,
		tirURL:       tirURL,
		services:     make(map[string]*ServiceConfig),
	}
}

// WithService adds or updates a service configuration.
func (cb *ConfigBuilder) WithService(id, defaultScope, authzType string) *ConfigBuilder {
	if _, exists := cb.services[id]; !exists {
		cb.services[id] = &ServiceConfig{
			ID:                id,
			DefaultScope:      defaultScope,
			AuthorizationType: authzType,
			Scopes:            make(map[string]*ScopeConfig),
		}
	} else {
		cb.services[id].DefaultScope = defaultScope
		cb.services[id].AuthorizationType = authzType
	}
	return cb
}

// WithCredential adds a credential type to a service scope.
func (cb *ConfigBuilder) WithCredential(serviceID, scope, credType, tirURL string) *ConfigBuilder {
	svc := cb.ensureService(serviceID)
	sc := cb.ensureScope(svc, scope)
	sc.Credentials = append(sc.Credentials, CredentialConfig{
		Type:                credType,
		TrustedIssuersLists: []string{tirURL},
	})
	return cb
}

// WithHolderVerification enables holder verification for a credential in a scope.
func (cb *ConfigBuilder) WithHolderVerification(serviceID, scope, credType, claim string) *ConfigBuilder {
	svc := cb.ensureService(serviceID)
	sc := cb.ensureScope(svc, scope)
	for i := range sc.Credentials {
		if sc.Credentials[i].Type == credType {
			sc.Credentials[i].HolderVerification = &HolderVerificationConfig{
				Enabled: true,
				Claim:   claim,
			}
			return cb
		}
	}
	return cb
}

// WithJwtInclusion enables JWT inclusion for a credential type in a scope.
func (cb *ConfigBuilder) WithJwtInclusion(serviceID, scope, credType string, fullInclusion bool) *ConfigBuilder {
	svc := cb.ensureService(serviceID)
	sc := cb.ensureScope(svc, scope)
	for i := range sc.Credentials {
		if sc.Credentials[i].Type == credType {
			sc.Credentials[i].JwtInclusion = &JwtInclusionConfig{
				Enabled:       true,
				FullInclusion: fullInclusion,
			}
			return cb
		}
	}
	return cb
}

// WithTrustedParticipantsList adds a trusted participants list to a credential in a scope.
func (cb *ConfigBuilder) WithTrustedParticipantsList(serviceID, scope, credType, listType, listURL string) *ConfigBuilder {
	svc := cb.ensureService(serviceID)
	sc := cb.ensureScope(svc, scope)
	for i := range sc.Credentials {
		if sc.Credentials[i].Type == credType {
			sc.Credentials[i].TrustedParticipants = append(sc.Credentials[i].TrustedParticipants, TrustedParticipantsListConfig{
				Type: listType,
				URL:  listURL,
			})
			return cb
		}
	}
	return cb
}

// WithDCQL sets the DCQL query for a service scope.
func (cb *ConfigBuilder) WithDCQL(serviceID, scope string, dcql DCQLConfig) *ConfigBuilder {
	svc := cb.ensureService(serviceID)
	sc := cb.ensureScope(svc, scope)
	sc.DCQL = &dcql
	return cb
}

// WithSigningKey sets the path to the verifier's signing key PEM file.
func (cb *ConfigBuilder) WithSigningKey(keyPath string) *ConfigBuilder {
	cb.signingKey = keyPath
	return cb
}

// Build generates the YAML configuration string.
func (cb *ConfigBuilder) Build() string {
	var b strings.Builder

	b.WriteString("server:\n")
	b.WriteString(fmt.Sprintf("  port: %d\n", cb.verifierPort))
	b.WriteString(fmt.Sprintf("  host: \"http://localhost:%d\"\n", cb.verifierPort))
	b.WriteString("  templateDir: \"views/\"\n")
	b.WriteString("  staticDir: \"views/static/\"\n")

	b.WriteString("logging:\n")
	b.WriteString("  level: \"DEBUG\"\n")
	b.WriteString("  jsonLogging: true\n")
	b.WriteString("  logRequests: true\n")

	b.WriteString("verifier:\n")
	b.WriteString("  did: \"did:key:test-verifier\"\n")
	b.WriteString(fmt.Sprintf("  tirAddress: \"%s\"\n", cb.tirURL))
	b.WriteString("  validationMode: \"none\"\n")
	b.WriteString("  keyAlgorithm: \"ES256\"\n")
	b.WriteString("  generateKey: true\n")
	b.WriteString("  sessionExpiry: 30\n")
	b.WriteString("  jwtExpiration: 30\n")
	b.WriteString("  supportedModes: [\"byValue\", \"byReference\"]\n")

	if cb.signingKey != "" {
		b.WriteString("  clientIdentification:\n")
		b.WriteString("    id: \"did:key:test-verifier\"\n")
		b.WriteString(fmt.Sprintf("    keyPath: \"%s\"\n", cb.signingKey))
		b.WriteString("    requestKeyAlgorithm: \"ES256\"\n")
	}

	b.WriteString("m2m:\n")
	b.WriteString("  authEnabled: false\n")

	if len(cb.services) > 0 {
		b.WriteString("configRepo:\n")
		b.WriteString("  services:\n")
		for _, svc := range cb.services {
			cb.writeService(&b, svc)
		}
	}

	return b.String()
}

func (cb *ConfigBuilder) writeService(b *strings.Builder, svc *ServiceConfig) {
	b.WriteString(fmt.Sprintf("    - id: \"%s\"\n", svc.ID))
	b.WriteString(fmt.Sprintf("      defaultOidcScope: \"%s\"\n", svc.DefaultScope))
	if svc.AuthorizationType != "" {
		b.WriteString(fmt.Sprintf("      authorizationType: \"%s\"\n", svc.AuthorizationType))
	}

	if len(svc.Scopes) > 0 {
		b.WriteString("      oidcScopes:\n")
		for scopeName, sc := range svc.Scopes {
			b.WriteString(fmt.Sprintf("        \"%s\":\n", scopeName))
			cb.writeScope(b, sc)
		}
	}
}

func (cb *ConfigBuilder) writeScope(b *strings.Builder, sc *ScopeConfig) {
	if len(sc.Credentials) > 0 {
		b.WriteString("          credentials:\n")
		for _, cred := range sc.Credentials {
			cb.writeCredential(b, &cred)
		}
	}

	if sc.DCQL != nil {
		b.WriteString("          dcql:\n")
		cb.writeDCQL(b, sc.DCQL)
	}
}

func (cb *ConfigBuilder) writeCredential(b *strings.Builder, cred *CredentialConfig) {
	b.WriteString(fmt.Sprintf("            - type: \"%s\"\n", cred.Type))

	if len(cred.TrustedParticipants) > 0 {
		b.WriteString("              trustedParticipantsLists:\n")
		for _, tp := range cred.TrustedParticipants {
			b.WriteString(fmt.Sprintf("                - type: \"%s\"\n", tp.Type))
			b.WriteString(fmt.Sprintf("                  url: \"%s\"\n", tp.URL))
		}
	}

	if len(cred.TrustedIssuersLists) > 0 {
		b.WriteString("              trustedIssuersLists:\n")
		for _, til := range cred.TrustedIssuersLists {
			b.WriteString(fmt.Sprintf("                - \"%s\"\n", til))
		}
	}

	if cred.HolderVerification != nil {
		b.WriteString("              holderVerification:\n")
		b.WriteString(fmt.Sprintf("                enabled: %t\n", cred.HolderVerification.Enabled))
		if cred.HolderVerification.Claim != "" {
			b.WriteString(fmt.Sprintf("                claim: \"%s\"\n", cred.HolderVerification.Claim))
		}
	}

	if cred.JwtInclusion != nil {
		b.WriteString("              jwtInclusion:\n")
		b.WriteString(fmt.Sprintf("                enabled: %t\n", cred.JwtInclusion.Enabled))
		b.WriteString(fmt.Sprintf("                fullInclusion: %t\n", cred.JwtInclusion.FullInclusion))
	}
}

func (cb *ConfigBuilder) writeDCQL(b *strings.Builder, dcql *DCQLConfig) {
	if len(dcql.Credentials) > 0 {
		b.WriteString("            credentials:\n")
		for _, cq := range dcql.Credentials {
			b.WriteString(fmt.Sprintf("              - id: \"%s\"\n", cq.Id))
			b.WriteString(fmt.Sprintf("                format: \"%s\"\n", cq.Format))
			if cq.Meta != nil && len(cq.Meta.VctValues) > 0 {
				b.WriteString("                meta:\n")
				b.WriteString("                  vct_values:\n")
				for _, v := range cq.Meta.VctValues {
					b.WriteString(fmt.Sprintf("                    - \"%s\"\n", v))
				}
			}
			if len(cq.Claims) > 0 {
				b.WriteString("                claims:\n")
				for _, cl := range cq.Claims {
					b.WriteString("                  - path:\n")
					for _, p := range cl.Path {
						b.WriteString(fmt.Sprintf("                      - \"%s\"\n", p))
					}
				}
			}
		}
	}

	if len(dcql.CredentialSets) > 0 {
		b.WriteString("            credential_sets:\n")
		for _, cs := range dcql.CredentialSets {
			b.WriteString("              - options:\n")
			for _, opt := range cs.Options {
				b.WriteString("                  - [")
				for i, o := range opt {
					if i > 0 {
						b.WriteString(", ")
					}
					b.WriteString(fmt.Sprintf("\"%s\"", o))
				}
				b.WriteString("]\n")
			}
			if cs.Purpose != "" {
				b.WriteString(fmt.Sprintf("                purpose: \"%s\"\n", cs.Purpose))
			}
		}
	}
}

func (cb *ConfigBuilder) ensureService(serviceID string) *ServiceConfig {
	svc, exists := cb.services[serviceID]
	if !exists {
		svc = &ServiceConfig{
			ID:     serviceID,
			Scopes: make(map[string]*ScopeConfig),
		}
		cb.services[serviceID] = svc
	}
	return svc
}

func (cb *ConfigBuilder) ensureScope(svc *ServiceConfig, scope string) *ScopeConfig {
	sc, exists := svc.Scopes[scope]
	if !exists {
		sc = &ScopeConfig{}
		svc.Scopes[scope] = sc
	}
	return sc
}

// GenerateSigningKeyPEM generates an ECDSA P-256 private key and writes it as PEM to a file in dir.
// Returns the file path to the PEM file.
func GenerateSigningKeyPEM(dir string) (string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generating ECDSA key: %w", err)
	}

	derBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("marshaling ECDSA key: %w", err)
	}

	pemBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: derBytes,
	}

	keyPath := filepath.Join(dir, "signing-key.pem")
	f, err := os.Create(keyPath)
	if err != nil {
		return "", fmt.Errorf("creating key file: %w", err)
	}
	defer f.Close()

	if err := pem.Encode(f, pemBlock); err != nil {
		return "", fmt.Errorf("encoding PEM: %w", err)
	}

	return keyPath, nil
}
