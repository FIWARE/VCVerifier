package verifier

import (
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/fiware/VCVerifier/common"
	"github.com/fiware/VCVerifier/eidas"
	"github.com/fiware/VCVerifier/logging"

	configModel "github.com/fiware/VCVerifier/config"
)

// --- Error variables for eIDAS validation ---

// ErrorEidasSDJWTRequired is returned when a credential type with eIDAS
// validation enabled was not presented in SD-JWT format.
var ErrorEidasSDJWTRequired = errors.New("eidas_validation_requires_sd_jwt_format")

// ErrorEidasNoX5CHeader is returned when an SD-JWT credential does not
// contain an x5c header with the issuer's certificate.
var ErrorEidasNoX5CHeader = errors.New("eidas_no_x5c_certificate_in_header")

// ErrorEidasCertificateParseFailed is returned when the x5c certificate in
// the SD-JWT header cannot be parsed.
var ErrorEidasCertificateParseFailed = errors.New("eidas_certificate_parse_failed")

// ErrorEidasNoRawToken is returned when the credential does not carry raw
// token bytes needed for x5c extraction.
var ErrorEidasNoRawToken = errors.New("eidas_no_raw_token_available")

// ErrorEidasUntrustedIssuer is returned when the issuer's certificate does
// not chain up to any trusted service in the eIDAS trust list.
var ErrorEidasUntrustedIssuer = errors.New("eidas_issuer_not_trusted_by_trust_list")

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

	// --- Extract x5c certificates from raw SD-JWT ---
	rawToken := verifiableCredential.RawToken()
	if len(rawToken) == 0 {
		logging.Log().Warn("EidasValidationService: credential has no raw token for x5c extraction")
		return false, ErrorEidasNoRawToken
	}

	x5cStrings, err := extractX5CFromToken(rawToken)
	if err != nil {
		logging.Log().Warnf("EidasValidationService: failed to extract x5c from token: %v", err)
		return false, ErrorEidasNoX5CHeader
	}

	if len(x5cStrings) == 0 {
		logging.Log().Warn("EidasValidationService: x5c header is empty")
		return false, ErrorEidasNoX5CHeader
	}

	// Parse the leaf certificate (first entry in x5c).
	leafCert, err := parseCertificate(x5cStrings[0])
	if err != nil {
		logging.Log().Warnf("EidasValidationService: failed to parse leaf certificate: %v", err)
		return false, ErrorEidasCertificateParseFailed
	}

	// Parse intermediate certificates (remaining x5c entries), if any.
	var intermediates []*x509.Certificate
	for i := 1; i < len(x5cStrings); i++ {
		intermCert, err := parseCertificate(x5cStrings[i])
		if err != nil {
			logging.Log().Warnf("EidasValidationService: failed to parse intermediate certificate at index %d: %v", i, err)
			return false, ErrorEidasCertificateParseFailed
		}
		intermediates = append(intermediates, intermCert)
	}

	// --- Determine service type filter ---
	var serviceTypes []string
	if activeConfig.IsRequireQualified() {
		serviceTypes = qualifiedServiceTypes
	} else {
		serviceTypes = allCertificateServiceTypes
	}

	// --- Determine country filter ---
	countries := activeConfig.AllowedCountries
	if len(countries) == 0 {
		countries = eidasContext.GlobalCountries
	}

	// --- Verify certificate against trust store ---
	if len(countries) > 0 {
		// Check each allowed country.
		for _, country := range countries {
			if evs.verifyCertificateAgainstTrustStore(leafCert, intermediates, country, serviceTypes) {
				logging.Log().Debugf("EidasValidationService: credential trusted via country %s", country)
				return true, nil
			}
		}
	} else {
		// No country filter — search all countries.
		if evs.verifyCertificateAgainstTrustStore(leafCert, intermediates, "", serviceTypes) {
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
func (evs *EidasValidationService) verifyCertificateAgainstTrustStore(
	leafCert *x509.Certificate,
	intermediates []*x509.Certificate,
	countryCode string,
	serviceTypes []string,
) bool {
	trustedServices := evs.trustStore.GetTrustedServices(countryCode, serviceTypes, true)
	if len(trustedServices) == 0 {
		logging.Log().Debugf("EidasValidationService: no trusted services found for country %q, types %v", countryCode, serviceTypes)
		return false
	}

	// Build an intermediate certificate pool if we have any.
	var intermediatePool *x509.CertPool
	if len(intermediates) > 0 {
		intermediatePool = x509.NewCertPool()
		for _, ic := range intermediates {
			intermediatePool.AddCert(ic)
		}
	}

	for _, svc := range trustedServices {
		if len(svc.Certificates) == 0 {
			continue
		}

		roots := x509.NewCertPool()
		for _, cert := range svc.Certificates {
			roots.AddCert(cert)
		}

		opts := x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediatePool,
			// We only care about chain validity, not specific key usages,
			// because eIDAS trust list certificates are CA certificates that
			// may not have ExtKeyUsage set. An empty KeyUsages slice means
			// x509.ExtKeyUsageServerAuth is checked by default in Go, so we
			// explicitly set it to x509.ExtKeyUsageAny to accept any usage.
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}

		if _, err := leafCert.Verify(opts); err == nil {
			logging.Log().Debugf("EidasValidationService: certificate chains to trusted service %q (TSP: %s, country: %s)",
				svc.ServiceName, svc.TSPName, svc.CountryCode)
			return true
		}
	}

	return false
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
		PerType:         perType,
		GlobalCountries: globalConfig.Countries,
	}, nil
}

// serviceTypeNames returns a human-readable summary of the service types used
// for eIDAS validation. Useful for error messages and logging.
func serviceTypeNames(requireQualified bool) string {
	if requireQualified {
		return fmt.Sprintf("qualified CA types (%v)", qualifiedServiceTypes)
	}
	return fmt.Sprintf("all CA types (%v)", allCertificateServiceTypes)
}
