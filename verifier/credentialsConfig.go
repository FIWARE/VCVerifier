package verifier

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/fiware/VCVerifier/tir"
	"github.com/procyon-projects/chrono"

	"github.com/fiware/VCVerifier/common"
	"github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/logging"
	"github.com/patrickmn/go-cache"
	"golang.org/x/exp/maps"
)

const CACHE_EXPIRY = 60

var ErrorNoPresentationDefinition = errors.New("no_presentation_definition_configured")

/**
* Provides information about credentialTypes associated with services and there trust anchors.
 */
type CredentialsConfig interface {
	// should return the list of scopes to be requested via the scope parameter
	GetScope(serviceIdentifier string) (scopes []string, err error)
	// should return the presentationDefinition be requested via the scope parameter
	GetPresentationDefinition(serviceIdentifier string, scope string) (presentationDefinition config.PresentationDefinition, err error)
	// get (EBSI TrustedIssuersRegistry compliant) endpoints for the given service/credential combination, to check its issued by a trusted participant.
	GetTrustedParticipantLists(serviceIdentifier string, scope string, credentialType string) (trustedIssuersRegistryUrl []config.TrustedParticipantsList, err error)
	// get (EBSI TrustedIssuersRegistry compliant) endpoints for the given service/credential combination, to check that credentials are issued by trusted issuers
	// and that the issuer has permission to issue such claims.
	GetTrustedIssuersLists(serviceIdentifier string, scope string, credentialType string) (trustedIssuersRegistryUrl []string, err error)
	// The credential types that are required for the given service and scope
	RequiredCredentialTypes(serviceIdentifier string, scope string) (credentialTypes []string, err error)
	// Get holder verification
	GetHolderVerification(serviceIdentifier string, scope string, credentialType string) (isEnabled bool, holderClaim string, err error)
}

type ServiceBackedCredentialsConfig struct {
	initialConfig *config.ConfigRepo
	configClient  *config.ConfigClient
}

func InitServiceBackedCredentialsConfig(repoConfig *config.ConfigRepo) (credentialsConfig CredentialsConfig, err error) {
	var configClient config.ConfigClient
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

	err = scb.fillStaticValues()
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

func (cc ServiceBackedCredentialsConfig) fillStaticValues() error {
	for _, configuredService := range cc.initialConfig.Services {
		logging.Log().Debugf("Add to service cache: %s", configuredService.Id)
		common.GlobalCache.ServiceCache.Set(configuredService.Id, configuredService, cache.DefaultExpiration)
	}
	return nil
}

func (cc ServiceBackedCredentialsConfig) fillCache(context.Context) {
	configClient := *(cc.configClient)
	services, err := configClient.GetServices()
	if err != nil {
		logging.Log().Warnf("Was not able to update the credentials config from the external service. Will try again. Err: %v.", err)
		return
	}
	for _, configuredService := range services {
		common.GlobalCache.ServiceCache.Set(configuredService.Id, configuredService, cache.DefaultExpiration)

		var tirEndpoints []string

		for serviceScope, scopeEntry := range configuredService.ServiceScopes {
			for _, credential := range scopeEntry.Credentials {
				serviceIssuersLists, err := cc.GetTrustedIssuersLists(configuredService.Id, serviceScope, credential.Type)
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

func (cc ServiceBackedCredentialsConfig) RequiredCredentialTypes(serviceIdentifier string, scope string) (credentialTypes []string, err error) {
	cacheEntry, hit := common.GlobalCache.ServiceCache.Get(serviceIdentifier)
	if hit {
		logging.Log().Debugf("Found service for %s", serviceIdentifier)
		configuredService := cacheEntry.(config.ConfiguredService)
		return configuredService.GetRequiredCredentialTypes(scope), nil
	}
	logging.Log().Errorf("No service entry for %s", serviceIdentifier)
	return []string{}, fmt.Errorf("no service %s configured", serviceIdentifier)
}

func (cc ServiceBackedCredentialsConfig) GetScope(serviceIdentifier string) (scopes []string, err error) {
	cacheEntry, hit := common.GlobalCache.ServiceCache.Get(serviceIdentifier)
	if hit {
		logging.Log().Debugf("Found scope for %s", serviceIdentifier)
		configuredService := cacheEntry.(config.ConfiguredService)
		return maps.Keys(configuredService.ServiceScopes), nil
	}
	logging.Log().Debugf("No scope entry for %s", serviceIdentifier)
	return []string{}, nil
}

func (cc ServiceBackedCredentialsConfig) GetPresentationDefinition(serviceIdentifier string, scope string) (presentationDefinition config.PresentationDefinition, err error) {
	cacheEntry, hit := common.GlobalCache.ServiceCache.Get(serviceIdentifier)
	if hit {

		logging.Log().Warnf("The definition %s", logging.PrettyPrintObject(presentationDefinition))

		return cacheEntry.(config.ConfiguredService).GetPresentationDefinition(scope), nil

	}
	logging.Log().Debugf("No presentation definition for %s - %s", serviceIdentifier, scope)
	return presentationDefinition, ErrorNoPresentationDefinition
}

func (cc ServiceBackedCredentialsConfig) GetTrustedParticipantLists(serviceIdentifier string, scope string, credentialType string) (trustedIssuersRegistryUrl []config.TrustedParticipantsList, err error) {
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

func (cc ServiceBackedCredentialsConfig) GetTrustedIssuersLists(serviceIdentifier string, scope string, credentialType string) (trustedIssuersRegistryUrl []string, err error) {
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

func (cc ServiceBackedCredentialsConfig) GetHolderVerification(serviceIdentifier string, scope string, credentialType string) (isEnabled bool, holderClaim string, err error) {
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
