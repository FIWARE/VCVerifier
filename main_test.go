package main

import (
	"reflect"
	"sort"
	"testing"

	"github.com/fiware/VCVerifier/config"
)

func TestResolveAllowedOrigins(t *testing.T) {
	tests := []struct {
		name     string
		services []config.ConfiguredService
		want     []string
	}{
		{
			name:     "no services returns wildcard",
			services: nil,
			want:     []string{"*"},
		},
		{
			name:     "empty services slice returns wildcard",
			services: []config.ConfiguredService{},
			want:     []string{"*"},
		},
		{
			name: "services with no allowedOrigins returns wildcard",
			services: []config.ConfiguredService{
				{Id: "svc1"},
				{Id: "svc2"},
			},
			want: []string{"*"},
		},
		{
			name: "services with empty allowedOrigins returns wildcard",
			services: []config.ConfiguredService{
				{Id: "svc1", AllowedOrigins: []string{}},
			},
			want: []string{"*"},
		},
		{
			name: "single service with specific origins",
			services: []config.ConfiguredService{
				{Id: "svc1", AllowedOrigins: []string{"https://example.com", "https://app.example.com"}},
			},
			want: []string{"https://example.com", "https://app.example.com"},
		},
		{
			name: "multiple services with different origins returns deduplicated union",
			services: []config.ConfiguredService{
				{Id: "svc1", AllowedOrigins: []string{"https://alpha.com"}},
				{Id: "svc2", AllowedOrigins: []string{"https://beta.com"}},
			},
			want: []string{"https://alpha.com", "https://beta.com"},
		},
		{
			name: "duplicate origins across services are deduplicated",
			services: []config.ConfiguredService{
				{Id: "svc1", AllowedOrigins: []string{"https://shared.com", "https://alpha.com"}},
				{Id: "svc2", AllowedOrigins: []string{"https://shared.com", "https://beta.com"}},
			},
			want: []string{"https://shared.com", "https://alpha.com", "https://beta.com"},
		},
		{
			name: "any service with wildcard returns wildcard only",
			services: []config.ConfiguredService{
				{Id: "svc1", AllowedOrigins: []string{"https://example.com"}},
				{Id: "svc2", AllowedOrigins: []string{"*"}},
			},
			want: []string{"*"},
		},
		{
			name: "first service with wildcard short-circuits",
			services: []config.ConfiguredService{
				{Id: "svc1", AllowedOrigins: []string{"*"}},
				{Id: "svc2", AllowedOrigins: []string{"https://example.com"}},
			},
			want: []string{"*"},
		},
		{
			name: "wildcard mixed within origins of a single service",
			services: []config.ConfiguredService{
				{Id: "svc1", AllowedOrigins: []string{"https://example.com", "*", "https://other.com"}},
			},
			want: []string{"*"},
		},
		{
			name: "mix of configured and unconfigured services",
			services: []config.ConfiguredService{
				{Id: "svc1"},
				{Id: "svc2", AllowedOrigins: []string{"https://example.com"}},
				{Id: "svc3", AllowedOrigins: []string{}},
			},
			want: []string{"https://example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveAllowedOrigins(tt.services)

			// Sort both slices for order-independent comparison when not testing
			// wildcard (wildcard is always a single element so order is irrelevant).
			if len(got) > 1 || len(tt.want) > 1 {
				sortedGot := make([]string, len(got))
				copy(sortedGot, got)
				sort.Strings(sortedGot)

				sortedWant := make([]string, len(tt.want))
				copy(sortedWant, tt.want)
				sort.Strings(sortedWant)

				if !reflect.DeepEqual(sortedGot, sortedWant) {
					t.Errorf("ResolveAllowedOrigins() = %v, want %v", got, tt.want)
				}
			} else if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ResolveAllowedOrigins() = %v, want %v", got, tt.want)
			}
		})
	}
}
