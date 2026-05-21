package verifier

import (
	"context"
	"errors"
	"fmt"

	"github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/database"
	"github.com/fiware/VCVerifier/logging"
	"golang.org/x/exp/maps"
)

// DbBackedCredentialsConfig is a CredentialsConfig implementation that reads
// service configurations directly from the database on every call. Static
// services from the initial configuration act as a fallback when a service is
// not found in the database.
type DbBackedCredentialsConfig struct {
	repo           database.ServiceRepository
	staticServices map[string]config.ConfiguredService
}

// InitDbBackedCredentialsConfig creates a CredentialsConfig that reads service
// configurations directly from the database via the given ServiceRepository.
// Static services from repoConfig.Services are kept as a fallback for services
// that are not (yet) stored in the database.
func InitDbBackedCredentialsConfig(repoConfig *config.ConfigRepo, repo database.ServiceRepository) (CredentialsConfig, error) {
	staticMap := make(map[string]config.ConfiguredService, len(repoConfig.Services))
	for _, svc := range repoConfig.Services {
		staticMap[svc.Id] = svc
	}

	dbc := DbBackedCredentialsConfig{
		repo:           repo,
		staticServices: staticMap,
	}

	logging.Log().Info("Database-backed credentials config initialized (direct DB reads)")
	return dbc, nil
}

// getService retrieves a ConfiguredService by ID, first from the database and
// falling back to static configuration. Returns database.ErrServiceNotFound
// when the service exists in neither.
func (dbc DbBackedCredentialsConfig) getService(serviceIdentifier string) (config.ConfiguredService, error) {
	svc, err := dbc.repo.GetService(context.Background(), serviceIdentifier)
	if err == nil {
		return svc, nil
	}
	if errors.Is(err, database.ErrServiceNotFound) {
		if staticSvc, ok := dbc.staticServices[serviceIdentifier]; ok {
			return staticSvc, nil
		}
		return config.ConfiguredService{}, database.ErrServiceNotFound
	}
	logging.Log().Warnf("Failed to read service %q from database: %v", serviceIdentifier, err)
	return config.ConfiguredService{}, err
}

// RequiredCredentialTypes returns the credential types required for the given service and scope.
func (dbc DbBackedCredentialsConfig) RequiredCredentialTypes(serviceIdentifier string, scope string) ([]string, error) {
	svc, err := dbc.getService(serviceIdentifier)
	if err != nil {
		if errors.Is(err, database.ErrServiceNotFound) {
			return nil, fmt.Errorf("no service %s configured", serviceIdentifier)
		}
		return nil, err
	}
	return svc.GetRequiredCredentialTypes(scope)
}

// GetDefaultScope returns the configured default OIDC scope for the given service.
func (dbc DbBackedCredentialsConfig) GetDefaultScope(serviceIdentifier string) (string, error) {
	svc, err := dbc.getService(serviceIdentifier)
	if err != nil {
		logging.Log().Warnf("Was not able to get default scope: %s", err)
		return "", ErrorNoDefaultScope
	}
	return svc.DefaultOidcScope, nil
}

// GetScope returns all configured scope names for the given service.
func (dbc DbBackedCredentialsConfig) GetScope(serviceIdentifier string) ([]string, error) {
	svc, err := dbc.getService(serviceIdentifier)
	if err != nil {
		logging.Log().Warnf("Was not able to get scope for %s: %s", serviceIdentifier, err)
		return []string{}, nil
	}
	return maps.Keys(svc.ServiceScopes), nil
}

// GetAuthorizationType returns the authorization type for the given service.
func (dbc DbBackedCredentialsConfig) GetAuthorizationType(serviceIdentifier string) (string, error) {
	svc, err := dbc.getService(serviceIdentifier)
	if err != nil {
		logging.Log().Warnf("Was not able to get authorization type for %s: %s", serviceIdentifier, err)
		return "", nil
	}
	return svc.AuthorizationType, nil
}

// GetAuthorizationPath returns the authorization endpoint path for the given service.
func (dbc DbBackedCredentialsConfig) GetAuthorizationPath(serviceIdentifier string) string {
	svc, err := dbc.getService(serviceIdentifier)
	if err != nil {
		logging.Log().Warnf("Was not able to get authorization path for %s: %s", serviceIdentifier, err)
		return ""
	}
	return svc.AuthorizationPath
}

// GetPresentationDefinition returns the presentation definition for the given service and scope.
func (dbc DbBackedCredentialsConfig) GetPresentationDefinition(serviceIdentifier string, scope string) (*config.PresentationDefinition, error) {
	svc, err := dbc.getService(serviceIdentifier)
	if err != nil {
		logging.Log().Warnf("Was not able to get presentation definition for %s: %s", serviceIdentifier, err)
		return nil, nil
	}
	return svc.GetPresentationDefinition(scope)
}

// GetDcqlQuery returns the DCQL query for the given service and scope.
func (dbc DbBackedCredentialsConfig) GetDcqlQuery(serviceIdentifier string, scope string) (*config.DCQL, error) {
	svc, err := dbc.getService(serviceIdentifier)
	if err != nil {
		logging.Log().Warnf("Was not able to get dcql for %s: %s", serviceIdentifier, err)
		return nil, nil
	}
	return svc.GetDcqlQuery(scope)
}

// GetTrustedParticipantLists returns trusted participant list endpoints for the
// given service, scope, and credential type.
func (dbc DbBackedCredentialsConfig) GetTrustedParticipantLists(serviceIdentifier string, scope string, credentialType string) ([]config.TrustedParticipantsList, error) {
	svc, err := dbc.getService(serviceIdentifier)
	if err != nil {
		return []config.TrustedParticipantsList{}, nil
	}
	credential, ok := svc.GetCredential(scope, credentialType)
	if !ok {
		return []config.TrustedParticipantsList{}, nil
	}
	return credential.TrustedParticipantsLists, nil
}

// GetTrustedIssuersLists returns trusted issuers list endpoints for the given
// service, scope, and credential type.
func (dbc DbBackedCredentialsConfig) GetTrustedIssuersLists(serviceIdentifier string, scope string, credentialType string) ([]string, error) {
	svc, err := dbc.getService(serviceIdentifier)
	if err != nil {
		return []string{}, nil
	}
	credential, ok := svc.GetCredential(scope, credentialType)
	if !ok {
		return []string{}, nil
	}
	return credential.TrustedIssuersLists, nil
}

// GetHolderVerification returns holder verification settings for the given credential type.
func (dbc DbBackedCredentialsConfig) GetHolderVerification(serviceIdentifier string, scope string, credentialType string) (bool, string, error) {
	svc, err := dbc.getService(serviceIdentifier)
	if err != nil {
		return false, "", nil
	}
	credential, ok := svc.GetCredential(scope, credentialType)
	if !ok {
		return false, "", nil
	}
	return credential.HolderVerification.Enabled, credential.HolderVerification.Claim, nil
}

// GetComplianceRequired returns whether compliance is required for the given credential type.
func (dbc DbBackedCredentialsConfig) GetComplianceRequired(serviceIdentifier string, scope string, credentialType string) (bool, error) {
	svc, err := dbc.getService(serviceIdentifier)
	if err != nil {
		return false, nil
	}
	credential, ok := svc.GetCredential(scope, credentialType)
	if !ok {
		return false, nil
	}
	return credential.RequireCompliance, nil
}

// GetJwtInclusion returns the JWT inclusion configuration for the given credential type.
func (dbc DbBackedCredentialsConfig) GetJwtInclusion(serviceIdentifier string, scope string, credentialType string) (config.JwtInclusion, error) {
	svc, err := dbc.getService(serviceIdentifier)
	if err != nil {
		return config.JwtInclusion{}, nil
	}
	credential, ok := svc.GetCredential(scope, credentialType)
	if !ok {
		return config.JwtInclusion{}, nil
	}
	return credential.JwtInclusion, nil
}

// GetFlatClaims returns whether flat claims should be used for the given service and scope.
func (dbc DbBackedCredentialsConfig) GetFlatClaims(serviceIdentifier string, scope string) (bool, error) {
	svc, err := dbc.getService(serviceIdentifier)
	if err != nil {
		return false, nil
	}
	scopeEntry, ok := svc.ServiceScopes[scope]
	if !ok {
		return false, nil
	}
	return scopeEntry.FlatClaims, nil
}

// GetCredentialStatusConfig returns the per-credential revocation-list
// configuration for the given service, scope and credential type.
func (dbc DbBackedCredentialsConfig) GetCredentialStatusConfig(serviceIdentifier string, scope string, credentialType string) (config.CredentialStatus, error) {
	svc, err := dbc.getService(serviceIdentifier)
	if err != nil {
		return config.CredentialStatus{}, nil
	}
	credential, ok := svc.GetCredential(scope, credentialType)
	if !ok {
		return config.CredentialStatus{}, nil
	}
	return credential.CredentialStatus, nil
}
