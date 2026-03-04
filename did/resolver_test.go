package did

import (
	"testing"
)

func TestExtractMethod(t *testing.T) {
	tests := []struct {
		name     string
		did      string
		expected string
		wantErr  bool
	}{
		{"did:web", "did:web:example.com", "web", false},
		{"did:key", "did:key:z6MkTest", "key", false},
		{"did:jwk", "did:jwk:eyJhbGciOiJFUzI1NiJ9", "jwk", false},
		{"no prefix", "web:example.com", "", true},
		{"empty method", "did::something", "", true},
		{"too short", "did:web", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			method, err := extractMethod(tc.did)
			if tc.wantErr && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
			if method != tc.expected {
				t.Errorf("Expected method %q, got %q", tc.expected, method)
			}
		})
	}
}

func TestRegistry_Resolve(t *testing.T) {
	t.Run("unsupported method", func(t *testing.T) {
		registry := NewRegistry(WithVDR(NewWebVDR()))
		_, err := registry.Resolve("did:example:123")
		if err == nil {
			t.Error("Expected error for unsupported method")
		}
	})

	t.Run("invalid DID", func(t *testing.T) {
		registry := NewRegistry(WithVDR(NewWebVDR()))
		_, err := registry.Resolve("not-a-did")
		if err == nil {
			t.Error("Expected error for invalid DID")
		}
	})

	t.Run("routes to correct VDR", func(t *testing.T) {
		mockVdr := &mockVDR{
			acceptMethod: "mock",
			readFunc: func(did string) (*DocResolution, error) {
				return &DocResolution{DIDDocument: &Doc{ID: did}}, nil
			},
		}
		registry := NewRegistry(WithVDR(mockVdr))
		res, err := registry.Resolve("did:mock:test")
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if res.DIDDocument.ID != "did:mock:test" {
			t.Errorf("Expected DID did:mock:test, got %s", res.DIDDocument.ID)
		}
	})
}

// mockVDR for testing the registry routing
type mockVDR struct {
	acceptMethod string
	readFunc     func(did string) (*DocResolution, error)
}

func (m *mockVDR) Accept(method string) bool {
	return method == m.acceptMethod
}

func (m *mockVDR) Read(did string) (*DocResolution, error) {
	return m.readFunc(did)
}
