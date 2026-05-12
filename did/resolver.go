package did

import (
	"errors"
	"fmt"
	"strings"

	"github.com/fiware/VCVerifier/logging"
)

var (
	ErrInvalidDID         = errors.New("invalid DID format")
	ErrMethodNotSupported = errors.New("DID method not supported")
	ErrResolutionFailed   = errors.New("DID resolution failed")
)

// VDR is the interface for a DID method resolver.
type VDR interface {
	// Accept returns true if this resolver handles the given DID method.
	Accept(method string) bool
	// Read resolves a DID and returns the DID document.
	Read(did string) (*DocResolution, error)
}

// Registry resolves DIDs by delegating to the appropriate VDR.
type Registry struct {
	vdrs []VDR
}

// RegistryOpt is a functional option for configuring a Registry.
type RegistryOpt func(*Registry)

// NewRegistry creates a new DID resolution registry with the given options.
func NewRegistry(opts ...RegistryOpt) *Registry {
	r := &Registry{}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// WithVDR adds a VDR to the registry.
func WithVDR(v VDR) RegistryOpt {
	return func(r *Registry) {
		r.vdrs = append(r.vdrs, v)
	}
}

// Resolve resolves a DID by finding a matching VDR and delegating to it.
func (r *Registry) Resolve(didStr string) (*DocResolution, error) {
	logging.Log().Debugf("Resolving DID: %s", didStr)

	method, err := extractMethod(didStr)
	if err != nil {
		return nil, err
	}

	for _, v := range r.vdrs {
		if v.Accept(method) {
			return v.Read(didStr)
		}
	}

	logging.Log().Infof("No VDR found for DID method %q (DID: %s)", method, didStr)
	return nil, fmt.Errorf("%w: %s", ErrMethodNotSupported, method)
}

// extractMethod extracts the DID method from a DID string (e.g., "web" from "did:web:example.com").
func extractMethod(didStr string) (string, error) {
	if !strings.HasPrefix(didStr, "did:") {
		return "", fmt.Errorf("%w: %s", ErrInvalidDID, didStr)
	}
	parts := strings.SplitN(didStr, ":", 3)
	if len(parts) < 3 || parts[1] == "" {
		return "", fmt.Errorf("%w: %s", ErrInvalidDID, didStr)
	}
	return parts[1], nil
}
