package eidas

import (
	"sync"

	"github.com/fiware/VCVerifier/logging"
)

var testLoggingOnce sync.Once

// initTestLogging configures the logging system for tests. It is safe to call
// from multiple test files; the actual configuration runs only once.
func initTestLogging() {
	testLoggingOnce.Do(func() {
		logging.Configure(logging.LoggingConfig{
			Level:         "DEBUG",
			JsonLogging:   true,
			LogRequests:   true,
			PathsToSkip:   []string{},
			DisableCaller: false,
		})
	})
}
