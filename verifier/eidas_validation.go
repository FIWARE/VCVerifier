package verifier

import (
	"crypto/x509"
	"errors"
	"time"

	configModel "github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/common"
	"github.com/fiware/VCVerifier/eidas"
	"github.com/fiware/VCVerifier/logging"
)

// --- Error variables for eIDAS validation ---

// ErrorEidasSDJWTRequired is returned when a credential type with eIDAS
// validation enabled was not presented in SD-JWT format.
var ErrorEidasSDJWTRequired = errors.New("eidas_validation_requires_sd_jwt_format")

// ErrorEidasNoCertificates is returned when the credential does not carry
// parsed x5c certificates needed for trust list validation.
var ErrorEidasNoCertificates = errors.New("eidas_no_x5c_certificates_available")

// ErrorEidasUntrustedIssuer is returned when the issuer's certificate does
// not chain up to any trusted service in the eIDAS trust list.
var ErrorEidasUntrustedIssuer = errors.New("eidas_issuer_not_trusted_by_trust_list")

// ErrorEidasCertificateNotQualified is returned when requireQualified is set
// but the issuer's certificate does not declare itself a qualified certificate
// through a QcCompliance statement (ETSI EN 319 412-5).
var ErrorEidasCertificateNotQualified = errors.New("eidas_certificate_not_qualified")

// --- Qualified and non-qualified service type sets ---

// qualifiedServiceTypes are the ETSI service type URIs for qualified trust
// services that issue certificates. Used when RequireQualified is true.
var qualifiedServiceTypes = []string{
	eidas.ServiceTypeCAQC,
	eidas.ServiceTypeNationalRootCAQC,
}

// allCertificateServiceTypes includes both qualified and non-qualified CA
// service types. Used when RequireQualified is false.
var allCertificateServiceTypes = []string{
	eidas.ServiceTypeCAQC,
	eidas.ServiceTypeNationalRootCAQC,
	eidas.ServiceTypeCA,
}

// EidasValidationContext carries per-credential-type eIDAS configuration into
// the EidasValidationService. It mirrors the pattern used by
// CredentialStatusValidationContext, keying the config by credential type.
type EidasValidationContext struct {
	// PerType maps a credential type string to its per-credential eIDAS
	// configuration. A nil entry means eIDAS validation is not configured
	// for that type.
	PerType map[string]*configModel.EidasConfig
	// GlobalCountries holds the global eIDAS country filter from the
	// server configuration. Used as a fallback when a per-credential config
	// has an empty AllowedCountries list.
	GlobalCountries []string
	// EvaluateStatusAtIssuance selects the point in time at which a trust
	// service's status is evaluated. When true, the status that applied when
	// the credential was issued is used; when false, the current status is.
	EvaluateStatusAtIssuance bool
}

// EidasValidationService validates SD-JWT credentials against the cached ETSI
// trust lists. It runs as an independent, additional validation step alongside
// the trusted participants / trusted issuers checks.
//
// When a credential type has eIDAS validation enabled (via eidasConfig in the
// credentials configuration), this service:
//   - Enforces that the credential was presented in SD-JWT format.
//   - Extracts the issuer's X.509 certificate from the SD-JWT's x5c header.
//   - Verifies the certificate chains up to a trusted CA listed in the EU
//     Trusted Lists, using PKIX chain building (x509.Certificate.Verify).
//
// For credential types without eIDAS configuration, the service is a no-op
// (returns true, nil).
type EidasValidationService struct {
	trustStore *eidas.TrustStore
}

// ValidateVC validates a Verifiable Credential against the eIDAS trust lists.
//
// The method performs the following steps:
//  1. Looks up the eIDAS configuration for each credential type. If no type
//     has eIDAS enabled, returns true (pass-through).
//  2. Enforces SD-JWT format — rejects credentials not in SD-JWT format.
//  3. Extracts the issuer's X.509 certificate chain from the SD-JWT x5c header.
//  4. Queries the TrustStore for matching trusted services filtered by country
//     and service type (qualified vs. all).
//  5. Verifies the issuer certificate chains up to a trusted CA using PKIX
//     chain building.
func (evs *EidasValidationService) ValidateVC(verifiableCredential *common.Credential, verificationContext ValidationContext) (result bool, err error) {
	logging.Log().Debugf("EidasValidationService: validate credential %s", logging.PrettyPrintObject(verifiableCredential))

	// Recover from context type assertion panics (same pattern as other services).
	defer func() {
		if recErr := recover(); recErr != nil {
			logging.Log().Warnf("EidasValidationService: failed to convert context. Err: %v", recErr)
			err = ErrorCannotConverContext
		}
	}()

	eidasContext := verificationContext.(EidasValidationContext)

	// Determine whether any of the credential's types has eIDAS enabled.
	var activeConfig *configModel.EidasConfig
	for _, credType := range verifiableCredential.Contents().Types {
		cfg, ok := eidasContext.PerType[credType]
		if ok && cfg != nil && cfg.Enabled {
			activeConfig = cfg
			break
		}
	}

	if activeConfig == nil {
		logging.Log().Debug("EidasValidationService: no eIDAS config enabled for credential types, pass-through")
		return true, nil
	}

	// --- Enforce SD-JWT format ---
	if verifiableCredential.Format() != common.FormatSDJWT {
		logging.Log().Warnf("EidasValidationService: credential format is %q but eIDAS requires %q",
			verifiableCredential.Format(), common.FormatSDJWT)
		return false, ErrorEidasSDJWTRequired
	}

	// --- Use pre-parsed x5c certificates from SD-JWT header ---
	// The certificates are extracted and parsed during SD-JWT parsing in the
	// presentation parser, so we use them directly here instead of
	// re-parsing the raw token.
	x5cCerts := verifiableCredential.X5CCertificates()
	if len(x5cCerts) == 0 {
		logging.Log().Warn("EidasValidationService: credential has no x5c certificates")
		return false, ErrorEidasNoCertificates
	}

	leafCert := x5cCerts[0]
	intermediates := x5cCerts[1:]

	// --- Determine service type filter and check the leaf's own QC status ---
	//
	// The service type filter constrains the issuing CA; being listed under a
	// qualified service type does not make every certificate that CA issues a
	// qualified one. "Qualified" is a property of the certificate itself, so
	// requireQualified additionally requires the leaf to declare it.
	var serviceTypes []string
	if activeConfig.IsRequireQualified() {
		serviceTypes = qualifiedServiceTypes
		if err := requireQualifiedCertificate(leafCert); err != nil {
			return false, err
		}
	} else {
		serviceTypes = allCertificateServiceTypes
	}

	// --- Determine country filter ---
	countries := activeConfig.AllowedCountries
	if len(countries) == 0 {
		countries = eidasContext.GlobalCountries
	}

	// --- Determine the point in time the trust status is evaluated at ---
	statusEvaluationTime := eidasContext.statusEvaluationTime(verifiableCredential)

	// --- Verify certificate against trust store ---
	if len(countries) > 0 {
		// Check each allowed country.
		for _, country := range countries {
			if evs.verifyCertificateAgainstTrustStore(leafCert, intermediates, country, serviceTypes, statusEvaluationTime) {
				logging.Log().Debugf("EidasValidationService: credential trusted via country %s", country)
				return true, nil
			}
		}
	} else {
		// No country filter — search all countries.
		if evs.verifyCertificateAgainstTrustStore(leafCert, intermediates, "", serviceTypes, statusEvaluationTime) {
			logging.Log().Debug("EidasValidationService: credential trusted (all countries)")
			return true, nil
		}
	}

	logging.Log().Warnf("EidasValidationService: issuer certificate does not chain to any trusted service")
	return false, ErrorEidasUntrustedIssuer
}

// verifyCertificateAgainstTrustStore queries the trust store for matching
// services and attempts PKIX chain validation of the leaf certificate against
// each trusted service's certificates as root CAs.
//
// The intermediates slice, if non-empty, is included in the verification
// options so that multi-level chains can be validated.
//
// Returns true if the leaf certificate successfully verifies against any
// trusted service's certificates.
//
// Delegates to the shared eidas.VerifyCertificateChain function.
func (evs *EidasValidationService) verifyCertificateAgainstTrustStore(
	leafCert *x509.Certificate,
	intermediates []*x509.Certificate,
	countryCode string,
	serviceTypes []string,
	statusEvaluationTime time.Time,
) bool {
	err := eidas.VerifyCertificateChainAt(leafCert, intermediates, evs.trustStore, countryCode, serviceTypes, statusEvaluationTime)
	return err == nil
}

// requireQualifiedCertificate checks that the given certificate declares itself
// a qualified certificate through a QcCompliance statement (ETSI EN 319 412-5
// §4.2.1). A certificate that carries no qcStatements extension, or one that
// cannot be parsed, is not qualified.
func requireQualifiedCertificate(leafCert *x509.Certificate) error {
	statements, err := eidas.ParseQCStatements(leafCert)
	if err != nil {
		logging.Log().Warnf("EidasValidationService: requireQualified is set but the issuer certificate carries no usable qcStatements: %v", err)
		return ErrorEidasCertificateNotQualified
	}
	if !statements.Compliant {
		logging.Log().Warn("EidasValidationService: requireQualified is set but the issuer certificate declares no QcCompliance statement")
		return ErrorEidasCertificateNotQualified
	}

	logging.Log().Debugf("EidasValidationService: issuer certificate is a qualified certificate (SSCD: %t, types: %v)",
		statements.SSCD, statements.Types)
	return nil
}

// statusEvaluationTime returns the point in time at which trust service status
// is evaluated for the given credential.
//
// In the default (current) mode this is the zero time, which makes the trust
// store evaluate the current status. In issuance mode it is the credential's
// ValidFrom / issuanceDate, so that the credential is checked against the trust
// status that applied when it was issued (ETSI TS 119 612 §5.5.5). A credential
// carrying no issuance date falls back to the current status: an unknown
// issuance time must not become a free pass to a withdrawn service.
func (ctx EidasValidationContext) statusEvaluationTime(verifiableCredential *common.Credential) time.Time {
	if !ctx.EvaluateStatusAtIssuance {
		return time.Time{}
	}
	validFrom := verifiableCredential.Contents().ValidFrom
	if validFrom == nil {
		logging.Log().Warn("EidasValidationService: credential carries no issuance date, evaluating trust status against the current time")
		return time.Time{}
	}
	return *validFrom
}

// getEidasValidationContext builds an EidasValidationContext for the given
// service/scope and credential types. It looks up the per-credential eIDAS
// config via the CredentialsConfig interface.
func (v *CredentialVerifier) getEidasValidationContext(clientId string, scope string, credentialTypes []string, globalConfig configModel.Eidas) (EidasValidationContext, error) {
	logging.Log().Debugf("Create eIDAS validation context for client '%s', scope '%s' and credential types %s", clientId, scope, credentialTypes)
	perType := map[string]*configModel.EidasConfig{}
	for _, credentialType := range credentialTypes {
		eidasCfg, err := v.credentialsConfig.GetEidasConfig(clientId, scope, credentialType)
		if err != nil {
			logging.Log().Warnf("Was not able to get eIDAS config for client %s, scope %s and type %s. Err: %v", clientId, scope, credentialType, err)
			return EidasValidationContext{}, err
		}
		perType[credentialType] = eidasCfg
	}
	return EidasValidationContext{
		PerType:                  perType,
		GlobalCountries:          globalConfig.Countries,
		EvaluateStatusAtIssuance: globalConfig.EvaluatesAtIssuance(),
	}, nil
}

