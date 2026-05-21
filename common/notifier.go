package common

// ConfigUpdateNotifier allows components to signal that service configuration
// has changed so that caches can be refreshed immediately instead of waiting
// for the next polling interval.
type ConfigUpdateNotifier interface {
	// NotifyConfigUpdate triggers an immediate cache refresh from the
	// underlying data source (e.g. database).
	NotifyConfigUpdate()
}
