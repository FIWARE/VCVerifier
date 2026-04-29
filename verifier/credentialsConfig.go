package verifier

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/fiware/VCVerifier/database"
	"github.com/fiware/VCVerifier/tir"
	"github.com/procyon-projects/chrono"

	"github.com/fiware/VCVerifier/common"
	"github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/logging"
	"github.com/patrickmn/go-cache"
	"golang.org/x/exp/maps"
)

// ErrorNoDefaultScope is returned when no default OIDC scope is configured for a service.
var ErrorNoDefaultScope = errors.New("no_default_scope_configured")

// CacheExpiry is the default cache expiry time in seconds for service configuration entries.
const CacheExpiry = 60

// Deprecated: Use CacheExpiry instead. Kept for backward compatibility.
const CACHE_EXPIRY = CacheExpiry

// CredentialsConfig provides information about credentialTypes associated with services
// and their trust anchors. Implementations read from a global cache that is populated
// by a background refresh mechanism (HTTP client, database, or static config).
type CredentialsConfig interface {
	// GetScope returns the list of scopes to be requested via the scope parameter.
	GetScope(serviceIdentifier string) (scopes []string, err error)
	// GetDefaultScope returns the configured default scope.
	GetDefaultScope(serviceIdentifier string) (scope string, err error)
	// GetAuthorizationType returns the authorization type to be provided in the redirect.
	GetAuthorizationType(serviceIdentifier string) (path string, err error)
	// GetAuthorizationPath returns the authorization path to be provided in the redirect.
	GetAuthorizationPath(serviceIdentifier string) (path string)
	// GetPresentationDefinition returns the presentationDefinition be requested via the scope parameter.
	GetPresentationDefinition(serviceIdentifier string, scope string) (presentationDefinition *config.PresentationDefinition, err error)
	// GetDcqlQuery returns the DCQL query to be requested via the scope parameter.
	GetDcqlQuery(serviceIdentifier string, scope string) (dcql *config.DCQL, err error)
	// GetTrustedParticipantLists returns (EBSI TrustedIssuersRegistry compliant) endpoints for the
	// given service/credential combination, to check it's issued by a trusted participant.
	GetTrustedParticipantLists(serviceIdentifier string, scope string, credentialType string) (trustedIssuersRegistryUrl []config.TrustedParticipantsList, err error)
	// GetTrustedIssuersLists returns (EBSI TrustedIssuersRegistry compliant) endpoints for the
	// given service/credential combination, to check that credentials are issued by trusted issuers
	// and that the issuer has permission to issue such claims.
	GetTrustedIssuersLists(serviceIdentifier string, scope string, credentialType string) (trustedIssuersRegistryUrl []string, err error)
	// RequiredCredentialTypes returns the credential types that are required for the given service and scope.
	RequiredCredentialTypes(serviceIdentifier string, scope string) (credentialTypes []string, err error)
	// GetHolderVerification returns holder verification configuration.
	GetHolderVerification(serviceIdentifier string, scope string, credentialType string) (isEnabled bool, holderClaim string, err error)
	// GetComplianceRequired returns whether compliance is required for the credential.
	GetComplianceRequired(serviceIdentifier string, scope string, credentialType string) (isRequired bool, err error)
	// GetJwtInclusion returns JWT inclusion configuration for the credential.
	GetJwtInclusion(serviceIdentifier string, scope string, credentialType string) (jwtInclusion config.JwtInclusion, err error)
	// GetFlatClaims returns whether flatClaims should be used.
	GetFlatClaims(serviceIdentifier string, scope string) (flatClaims bool, err error)
}

// cacheBasedCredentialsConfig is a base implementation of CredentialsConfig that reads
// all service configuration from the global service cache. Both ServiceBackedCredentialsConfig
// and DbBackedCredentialsConfig embed this type to share the cache-reading logic.
type cacheBasedCredentialsConfig struct{}

// ServiceBackedCredentialsConfig is a CredentialsConfig implementation that fetches
// service configurations from an external HTTP-based CCS endpoint and caches them locally.
type ServiceBackedCredentialsConfig struct {
	cacheBasedCredentialsConfig
	initialConfig *config.ConfigRepo
	configClient  *config.ConfigClient
}

// InitCredentialsConfig creates the appropriate CredentialsConfig implementation based on
// the provided configuration. When repo is non-nil, a DbBackedCredentialsConfig is used
// (database mode). When repo is nil but ConfigEndpoint is set, the existing HTTP-based
// ServiceBackedCredentialsConfig is used. When neither is available, static-only mode
// is used (services from ConfigRepo.Services with no expiration).
func InitCredentialsConfig(repoConfig *config.ConfigRepo, repo database.ServiceRepository) (CredentialsConfig, error) {
	if repo != nil {
		logging.Log().Info("Using database-backed credentials configuration.")
		return InitDbBackedCredentialsConfig(repoConfig, repo)
	}
	logging.Log().Info("Using HTTP/static-backed credentials configuration.")
	return InitServiceBackedCredentialsConfig(repoConfig)
}

// InitServiceBackedCredentialsConfig creates a CredentialsConfig that fetches service
// configurations from an external HTTP CCS endpoint. If no endpoint is configured,
// only static configuration from ConfigRepo.Services is used.
func InitServiceBackedCredentialsConfig(repoConfig *config.ConfigRepo) (credentialsConfig CredentialsConfig, err error) {
	var configClient config.ConfigClient
	var static = repoConfig.ConfigEndpoint == ""
	if repoConfig.ConfigEndpoint == "" {
		logging.Log().Warn("No endpoint for the configuration service is configured. Only static configuration will be provided.")
	} else {

		_, err = url.Parse(repoConfig.ConfigEndpoint)
		if err != nil {
			logging.Log().Errorf("The service endpoint %s is not a valid url. Err: %v", repoConfig.ConfigEndpoint, err)
			return
		}
		configClient, err = config.NewCCSHttpClient(repoConfig.ConfigEndpoint)
		if err != nil {
			logging.Log().Warnf("Was not able to instantiate the config client.")
		}
	}

	scb := ServiceBackedCredentialsConfig{configClient: &configClient, initialConfig: repoConfig}

	err = fillStaticValues(repoConfig, static)
	if err != nil {
		return nil, err
	}

	if repoConfig.ConfigEndpoint != "" {

		_, err := chrono.NewDefaultTaskScheduler().ScheduleAtFixedRate(scb.fillCache, time.Duration(repoConfig.UpdateInterval)*time.Second)
		if err != nil {
			logging.Log().Errorf("failed scheduling task: %v", err)
			return nil, err
		}
	}

	return scb, err
}

// fillStaticValues populates the global service cache with services from the static
// configuration. When static is true, cache entries never expire; otherwise they use
// the default expiration so that the background refresh can update them.
func fillStaticValues(repoConfig *config.ConfigRepo, static bool) error {
	var exipiration = cache.DefaultExpiration
	if static {
		exipiration = cache.NoExpiration
	}
	for _, configuredService := range repoConfig.Services {
		logging.Log().Debugf("Add service %s to cache.", logging.PrettyPrintObject(configuredService))
		common.GlobalCache.ServiceCache.Set(configuredService.Id, configuredService, exipiration)
	}
	return nil
}

// fillCache fetches all services from the external HTTP CCS endpoint and refreshes
// the global service cache. Also updates the TIR endpoints cache.
func (cc ServiceBackedCredentialsConfig) fillCache(context.Context) {
	configClient := *(cc.configClient)
	services, err := configClient.GetServices()
	if err != nil {
		logging.Log().Warnf("Was not able to update the credentials config from the external service. Will try again. Err: %v.", err)
		return
	}
	updateCacheFromServices(services)
}

// updateCacheFromServices updates the global service cache and TIR endpoints cache
// with the given list of services. This is shared between the HTTP-based and DB-based
// credentials config implementations.
func updateCacheFromServices(services []config.ConfiguredService) {
	base := cacheBasedCredentialsConfig{}
	for _, configuredService := range services {
		common.GlobalCache.ServiceCache.Set(configuredService.Id, configuredService, cache.DefaultExpiration)

		var tirEndpoints []string

		for serviceScope, scopeEntry := range configuredService.ServiceScopes {
			for _, credential := range scopeEntry.Credentials {
				serviceIssuersLists, err := base.GetTrustedIssuersLists(configuredService.Id, serviceScope, credential.Type)
				if err != nil {
					logging.Log().Errorf("failed caching issuers lists in fillCache(): %v", err)
				} else {
					tirEndpoints = append(tirEndpoints, serviceIssuersLists...)
				}
			}
		}
		common.GlobalCache.TirEndpoints.Set(tir.TirEndpointsCache, tirEndpoints, cache.NoExpiration)
	}
}

// RequiredCredentialTypes returns the credential types that are required for the given service and scope.
func (cc cacheBasedCredentialsConfig) RequiredCredentialTypes(serviceIdentifier string, scope string) (credentialTypes []string, err error) {
	cacheEntry, hit := common.GlobalCache.ServiceCache.Get(serviceIdentifier)
	if hit {
		logging.Log().Debugf("Found service for %s", serviceIdentifier)
		configuredService := cacheEntry.(config.ConfiguredService)
		return configuredService.GetRequiredCredentialTypes(scope)
	}
	logging.Log().Errorf("No service entry for %s", serviceIdentifier)
	return []string{}, fmt.Errorf("no service %s configured", serviceIdentifier)
}

// GetDefaultScope returns the configured default OIDC scope for the given service.
func (cc cacheBasedCredentialsConfig) GetDefaultScope(serviceIdentifier string) (scope string, err error) {
	cacheEntry, hit := common.GlobalCache.ServiceCache.Get(serviceIdentifier)
	if hit {
		configuredService := cacheEntry.(config.ConfiguredService)
		logging.Log().Debugf("Found scope %s for %s", logging.PrettyPrintObject(configuredService.ServiceScopes), serviceIdentifier)
		return configuredService.DefaultOidcScope, nil
	}
	logging.Log().Debugf("No scope entry for %s", serviceIdentifier)
	return "", ErrorNoDefaultScope
}

// GetScope returns all configured scope names for the given service.
func (cc cacheBasedCredentialsConfig) GetScope(serviceIdentifier string) (scopes []string, err error) {
	cacheEntry, hit := common.GlobalCache.ServiceCache.Get(serviceIdentifier)
	if hit {
		configuredService := cacheEntry.(config.ConfiguredService)
		logging.Log().Debugf("Found scope %s for %s", logging.PrettyPrintObject(configuredService.ServiceScopes), serviceIdentifier)
		return maps.Keys(configuredService.ServiceScopes), nil
	}
	logging.Log().Debugf("No scope entry for %s", serviceIdentifier)
	return []string{}, nil
}

// GetAuthorizationType returns the authorization type for the given service.
func (cc cacheBasedCredentialsConfig) GetAuthorizationType(serviceIdentifier string) (path string, err error) {
	cacheEntry, hit := common.GlobalCache.ServiceCache.Get(serviceIdentifier)
	if hit {
		logging.Log().Debugf("Found authorization-type for %s", serviceIdentifier)
		configuredService := cacheEntry.(config.ConfiguredService)
		return configuredService.AuthorizationType, nil
	}
	logging.Log().Debugf("No authorization-type entry for %s", serviceIdentifier)
	return "", nil
}

// GetAuthorizationPath returns the authorization endpoint path for the given service.
func (cc cacheBasedCredentialsConfig) GetAuthorizationPath(serviceIdentifier string) (path string) {
	cacheEntry, hit := common.GlobalCache.ServiceCache.Get(serviceIdentifier)
	if hit {
		logging.Log().Debugf("Found authorization-endpoint for %s", serviceIdentifier)
		configuredService := cacheEntry.(config.ConfiguredService)
		return configuredService.AuthorizationPath
	}
	logging.Log().Debugf("No authorization-path entry for %s", serviceIdentifier)
	return ""
}

// GetPresentationDefinition returns the presentation definition for the given service and scope.
func (cc cacheBasedCredentialsConfig) GetPresentationDefinition(serviceIdentifier string, scope string) (presentationDefinition *config.PresentationDefinition, err error) {
	cacheEntry, hit := common.GlobalCache.ServiceCache.Get(serviceIdentifier)
	if hit {
		return cacheEntry.(config.ConfiguredService).GetPresentationDefinition(scope)

	}
	logging.Log().Debugf("No presentation definition for %s - %s", serviceIdentifier, scope)
	return presentationDefinition, nil
}

// GetDcqlQuery returns the DCQL query for the given service and scope.
func (cc cacheBasedCredentialsConfig) GetDcqlQuery(serviceIdentifier string, scope string) (dcql *config.DCQL, err error) {
	cacheEntry, hit := common.GlobalCache.ServiceCache.Get(serviceIdentifier)
	logging.Log().Debug("Get the dcql")
	if hit {
		return cacheEntry.(config.ConfiguredService).GetDcqlQuery(scope)

	}
	logging.Log().Debugf("No dcql for %s - %s", serviceIdentifier, scope)
	return dcql, nil
}

// GetTrustedParticipantLists returns trusted participant list endpoints for the given service, scope, and credential type.
func (cc cacheBasedCredentialsConfig) GetTrustedParticipantLists(serviceIdentifier string, scope string, credentialType string) (trustedIssuersRegistryUrl []config.TrustedParticipantsList, err error) {
	logging.Log().Debugf("Get participants list for %s - %s - %s.", serviceIdentifier, scope, credentialType)
	cacheEntry, hit := common.GlobalCache.ServiceCache.Get(serviceIdentifier)
	if hit {
		credential, ok := cacheEntry.(config.ConfiguredService).GetCredential(scope, credentialType)
		if ok {
			logging.Log().Debugf("Found trusted participants %s for %s - %s", credential.TrustedParticipantsLists, serviceIdentifier, credentialType)
			return credential.TrustedParticipantsLists, nil
		}
	}
	logging.Log().Debugf("No trusted participants for %s - %s", serviceIdentifier, credentialType)
	return []config.TrustedParticipantsList{}, nil
}

// GetTrustedIssuersLists returns trusted issuers list endpoints for the given service, scope, and credential type.
func (cc cacheBasedCredentialsConfig) GetTrustedIssuersLists(serviceIdentifier string, scope string, credentialType string) (trustedIssuersRegistryUrl []string, err error) {
	logging.Log().Debugf("Get issuers list for %s - %s - %s.", serviceIdentifier, scope, credentialType)
	cacheEntry, hit := common.GlobalCache.ServiceCache.Get(serviceIdentifier)
	if hit {
		credential, ok := cacheEntry.(config.ConfiguredService).GetCredential(scope, credentialType)
		if ok {
			logging.Log().Debugf("Found trusted issuers for %s for %s - %s", credential.TrustedIssuersLists, serviceIdentifier, credentialType)
			return credential.TrustedIssuersLists, nil
		}
	}
	logging.Log().Debugf("No trusted issuers for %s - %s", serviceIdentifier, credentialType)
	return []string{}, nil
}

// GetComplianceRequired returns whether compliance is required for the given credential type.
func (cc cacheBasedCredentialsConfig) GetComplianceRequired(serviceIdentifier string, scope string, credentialType string) (isRequired bool, err error) {
	logging.Log().Debugf("Get compliance requirement for %s - %s - %s.", serviceIdentifier, scope, credentialType)
	cacheEntry, hit := common.GlobalCache.ServiceCache.Get(serviceIdentifier)
	if hit {
		credential, ok := cacheEntry.(config.ConfiguredService).GetCredential(scope, credentialType)
		if ok {
			logging.Log().Debugf("Found compliance requirement for %s - %v", credentialType, credential.RequireCompliance)
			return credential.RequireCompliance, nil
		}
	}
	logging.Log().Debugf("No compliance requirement for %s - %s", serviceIdentifier, credentialType)
	return false, nil
}

// GetFlatClaims returns whether flat claims should be used for the given service and scope.
func (cc cacheBasedCredentialsConfig) GetFlatClaims(serviceIdentifier string, scope string) (flatClaims bool, err error) {
	cacheEntry, hit := common.GlobalCache.ServiceCache.Get(serviceIdentifier)
	if hit {
		logging.Log().Debugf("Found scope for %s", serviceIdentifier)
		configuredService := cacheEntry.(config.ConfiguredService)
		scope, ok := configuredService.ServiceScopes[scope]
		if ok {
			return scope.FlatClaims, nil
		}
	}
	logging.Log().Debugf("No scope entry and flatclaims config for %s - %s", serviceIdentifier, scope)
	return false, nil
}

// GetJwtInclusion returns the JWT inclusion configuration for the given credential type.
func (cc cacheBasedCredentialsConfig) GetJwtInclusion(serviceIdentifier string, scope string, credentialType string) (jwtInclusion config.JwtInclusion, err error) {
	logging.Log().Debugf("Get jwt inclusion for %s - %s - %s.", serviceIdentifier, scope, credentialType)
	cacheEntry, hit := common.GlobalCache.ServiceCache.Get(serviceIdentifier)
	if hit {
		credential, ok := cacheEntry.(config.ConfiguredService).GetCredential(scope, credentialType)
		if ok {
			logging.Log().Debugf("Found jwt inclusion for %s - %v", credentialType, credential.RequireCompliance)
			return credential.JwtInclusion, nil
		}
	}
	logging.Log().Debugf("No jwt inclusion for %s - %s", serviceIdentifier, credentialType)
	return jwtInclusion, nil
}

// GetHolderVerification returns holder verification settings for the given credential type.
func (cc cacheBasedCredentialsConfig) GetHolderVerification(serviceIdentifier string, scope string, credentialType string) (isEnabled bool, holderClaim string, err error) {
	logging.Log().Debugf("Get holder verification for %s - %s - %s.", serviceIdentifier, scope, credentialType)
	cacheEntry, hit := common.GlobalCache.ServiceCache.Get(serviceIdentifier)
	if hit {
		credential, ok := cacheEntry.(config.ConfiguredService).GetCredential(scope, credentialType)
		if ok {
			logging.Log().Debugf("Found holder verification %v:%s for %s - %s", credential.HolderVerification.Enabled, credential.HolderVerification.Claim, serviceIdentifier, credentialType)
			return credential.HolderVerification.Enabled, credential.HolderVerification.Claim, nil
		}
	}
	logging.Log().Debugf("No holder verification for %s - %s", serviceIdentifier, credentialType)
	return false, "", nil
}
