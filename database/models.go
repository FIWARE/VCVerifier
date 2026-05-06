package database

import (
	"encoding/json"
	"fmt"

	"github.com/fiware/VCVerifier/config"
)

// ServiceRow represents a row in the service table.
type ServiceRow struct {
	// ID is the unique service identifier (primary key).
	ID string
	// DefaultOidcScope is the default OIDC scope name; may be nil.
	DefaultOidcScope *string
	// AuthorizationType describes the authorization mode; may be nil.
	AuthorizationType *string
}

// ScopeEntryRow represents a row in the scope_entry table.
type ScopeEntryRow struct {
	// ID is the auto-generated primary key.
	ID int64
	// ServiceID is the foreign key referencing service.id.
	ServiceID string
	// ScopeKey is the OIDC scope name (map key in ServiceScopes).
	ScopeKey string
	// Credentials is a JSON-encoded array of config.Credential objects.
	Credentials string
	// PresentationDefinition is a JSON-encoded config.PresentationDefinition; may be nil.
	PresentationDefinition *string
	// FlatClaims indicates whether claims should be flattened in the JWT.
	FlatClaims bool
	// DcqlQuery is a JSON-encoded config.DCQL object; may be nil.
	DcqlQuery *string
}

// ServiceToRow converts a config.ConfiguredService into a ServiceRow.
// The scope entries are handled separately via ScopeEntryToRows.
func ServiceToRow(service config.ConfiguredService) ServiceRow {
	row := ServiceRow{ID: service.Id}
	if service.DefaultOidcScope != "" {
		row.DefaultOidcScope = &service.DefaultOidcScope
	}
	if service.AuthorizationType != "" {
		row.AuthorizationType = &service.AuthorizationType
	}
	return row
}

// ScopeEntryToRows converts the ServiceScopes map from a ConfiguredService
// into a slice of ScopeEntryRow values, marshalling the complex fields to
// JSON text. An error is returned if any JSON serialisation fails.
func ScopeEntryToRows(serviceID string, scopes map[string]config.ScopeEntry) ([]ScopeEntryRow, error) {
	rows := make([]ScopeEntryRow, 0, len(scopes))
	for key, entry := range scopes {
		row, err := scopeEntryToRow(serviceID, key, config.ScopeEntryDB{}.FromVO(entry))
		if err != nil {
			return nil, fmt.Errorf("scope %q: %w", key, err)
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// scopeEntryToRow converts a single scope key + ScopeEntry pair into a
// ScopeEntryRow, marshalling credentials, presentationDefinition, and dcql
// to JSON text columns.
func scopeEntryToRow(serviceID, scopeKey string, entry config.ScopeEntryDB) (ScopeEntryRow, error) {
	credJSON, err := json.Marshal(entry.Credentials)
	if err != nil {
		return ScopeEntryRow{}, fmt.Errorf("failed to marshal credentials: %w", err)
	}

	row := ScopeEntryRow{
		ServiceID:   serviceID,
		ScopeKey:    scopeKey,
		Credentials: string(credJSON),
		FlatClaims:  entry.FlatClaims,
	}

	if entry.PresentationDefinition != nil {
		pdJSON, err := json.Marshal(entry.PresentationDefinition)
		if err != nil {
			return ScopeEntryRow{}, fmt.Errorf("failed to marshal presentationDefinition: %w", err)
		}
		s := string(pdJSON)
		row.PresentationDefinition = &s
	}

	if entry.DCQL != nil {
		dcqlJSON, err := json.Marshal(entry.DCQL)
		if err != nil {
			return ScopeEntryRow{}, fmt.Errorf("failed to marshal dcql: %w", err)
		}
		s := string(dcqlJSON)
		row.DcqlQuery = &s
	}

	return row, nil
}

// RowToService assembles a config.ConfiguredService from a ServiceRow and
// its associated ScopeEntryRow values, unmarshalling JSON text columns back
// into typed Go structs.
func RowToService(row ServiceRow, scopeRows []ScopeEntryRow) (config.ConfiguredService, error) {
	svc := config.ConfiguredService{
		Id:            row.ID,
		ServiceScopes: make(map[string]config.ScopeEntry, len(scopeRows)),
	}
	if row.DefaultOidcScope != nil {
		svc.DefaultOidcScope = *row.DefaultOidcScope
	}
	if row.AuthorizationType != nil {
		svc.AuthorizationType = *row.AuthorizationType
	}

	for _, sr := range scopeRows {
		scopeKey, entry, err := rowToScopeEntry(sr)
		if err != nil {
			return svc, fmt.Errorf("scope_entry id=%d: %w", sr.ID, err)
		}
		svc.ServiceScopes[scopeKey] = entry.VO()
	}
	return svc, nil
}

// rowToScopeEntry converts a single ScopeEntryRow back into a scope key
// and config.ScopeEntry, unmarshalling JSON text columns.
func rowToScopeEntry(row ScopeEntryRow) (string, config.ScopeEntryDB, error) {
	var entry config.ScopeEntryDB

	if err := json.Unmarshal([]byte(row.Credentials), &entry.Credentials); err != nil {
		return "", entry, fmt.Errorf("failed to unmarshal credentials: %w", err)
	}

	entry.FlatClaims = row.FlatClaims

	if row.PresentationDefinition != nil {
		var pd config.PresentationDefinitionDB
		if err := json.Unmarshal([]byte(*row.PresentationDefinition), &pd); err != nil {
			return "", entry, fmt.Errorf("failed to unmarshal presentationDefinition: %w", err)
		}
		entry.PresentationDefinition = &pd
	}

	if row.DcqlQuery != nil {
		var dcql config.DCQLDB
		if err := json.Unmarshal([]byte(*row.DcqlQuery), &dcql); err != nil {
			return "", entry, fmt.Errorf("failed to unmarshal dcql: %w", err)
		}
		entry.DCQL = &dcql
	}

	return row.ScopeKey, entry, nil
}
