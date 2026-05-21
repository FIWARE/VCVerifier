package verifier

import (
	"context"

	"github.com/fiware/VCVerifier/common"
	"github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/database"
	"github.com/fiware/VCVerifier/logging"
	"github.com/patrickmn/go-cache"
)

// defaultDbPageSize is the page size used when fetching all services from the database
// for cache population. A large page size minimizes the number of DB round-trips.
const defaultDbPageSize = 1000

// DbBackedCredentialsConfig is a CredentialsConfig implementation that reads service
// configurations directly from the database via a ServiceRepository, caching them in
// the global service cache. Cache updates are triggered on demand via the
// ConfigUpdateNotifier interface (called by the CCS API after every write operation)
// rather than by a periodic polling interval. It embeds cacheBasedCredentialsConfig
// for all cache-reading methods and only overrides the cache population logic.
type DbBackedCredentialsConfig struct {
	cacheBasedCredentialsConfig
	repo          database.ServiceRepository
	initialConfig *config.ConfigRepo
}

// InitDbBackedCredentialsConfig creates a CredentialsConfig that reads service
// configurations from the database via the given ServiceRepository. Static
// configuration from repoConfig.Services is loaded into the cache first (with
// default expiration so DB data can override it). The returned
// ConfigUpdateNotifier should be called after every write to the database so
// that the cache is refreshed immediately.
func InitDbBackedCredentialsConfig(repoConfig *config.ConfigRepo, repo database.ServiceRepository) (CredentialsConfig, common.ConfigUpdateNotifier, error) {
	dbc := DbBackedCredentialsConfig{
		repo:          repo,
		initialConfig: repoConfig,
	}

	// Load static services into cache with default expiration so DB data takes precedence.
	if err := fillStaticValues(repoConfig, false); err != nil {
		return nil, nil, err
	}

	// Perform an initial cache fill from the database.
	dbc.fillCache(context.Background())

	logging.Log().Info("Database-backed credentials config initialized (event-driven cache refresh)")
	return dbc, dbc, nil
}

// NotifyConfigUpdate triggers an immediate cache refresh from the database.
// This implements common.ConfigUpdateNotifier and is called by the CCS API
// handlers after every successful create, update, or delete operation.
func (dbc DbBackedCredentialsConfig) NotifyConfigUpdate() {
	logging.Log().Debug("Config update notification received, refreshing cache from database")
	dbc.fillCache(context.Background())
}

// fillCache queries all services from the database and refreshes the global service
// cache. If the database is unavailable, the existing cache entries are preserved and
// a warning is logged.
func (dbc DbBackedCredentialsConfig) fillCache(ctx context.Context) {
	services, err := dbc.fetchAllServices(ctx)
	if err != nil {
		logging.Log().Warnf("Failed to refresh credentials config from database, will retry. Err: %v", err)
		return
	}

	// Clear stale entries: set all fetched services into the cache. Entries that
	// were removed from the DB will expire naturally via the cache TTL.
	updateCacheFromServices(services)

	logging.Log().Debugf("Refreshed credentials config cache from database: %d service(s)", len(services))
}

// fetchAllServices retrieves all services from the database, paginating through
// results until all services are fetched.
func (dbc DbBackedCredentialsConfig) fetchAllServices(ctx context.Context) ([]config.ConfiguredService, error) {
	var allServices []config.ConfiguredService
	page := 0

	for {
		services, total, err := dbc.repo.GetAllServices(ctx, page, defaultDbPageSize)
		if err != nil {
			return nil, err
		}
		allServices = append(allServices, services...)

		// Stop when we've fetched all services or the page was not full.
		if len(allServices) >= total || len(services) < defaultDbPageSize {
			break
		}
		page++
	}

	// Also include static services that may not be in the DB yet, but only if
	// they are not already present from the DB results.
	dbServiceIDs := make(map[string]bool, len(allServices))
	for _, svc := range allServices {
		dbServiceIDs[svc.Id] = true
	}
	for _, staticSvc := range dbc.initialConfig.Services {
		if !dbServiceIDs[staticSvc.Id] {
			// Re-add static service to cache so it remains available.
			common.GlobalCache.ServiceCache.Set(staticSvc.Id, staticSvc, cache.DefaultExpiration)
		}
	}

	return allServices, nil
}
