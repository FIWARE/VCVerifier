package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestServer_NormalizedPathPrefix(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
		want   string
	}{
		{"unset", "", ""},
		{"root slash", "/", ""},
		{"no leading slash", "myservice", "/myservice"},
		{"leading and trailing slash", "/myservice/", "/myservice"},
		{"trailing slash only", "myservice/", "/myservice"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Server{PathPrefix: tt.prefix}
			assert.Equal(t, tt.want, s.NormalizedPathPrefix())
		})
	}
}
