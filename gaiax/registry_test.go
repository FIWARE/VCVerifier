package gaiax

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestGaiaXRegistryClient_GetComplianceIssuers(t *testing.T) {

	type fields struct {
		response     string
		responseCode int
	}
	tests := []struct {
		name    string
		fields  fields
		want    []string
		wantErr bool
	}{
		{
			"Should return one did",
			fields{
				`["did:web:compliance.test.com"]`,
				200,
			},
			[]string{"did:web:compliance.test.com"},
			false,
		},
		{
			"Should return multiple dids",
			fields{
				`["did:web:compliance.test.com","did:key:123"]`,
				200,
			},
			[]string{"did:web:compliance.test.com", "did:key:123"},
			false,
		},
		{
			"Should return error when malformatted",
			fields{
				`{"someThing":"else"}`,
				200,
			},
			[]string{},
			true,
		},
		{
			"Should return error when http error",
			fields{
				``,
				500,
			},
			[]string{},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.fields.responseCode)
				_, _ = w.Write([]byte(tt.fields.response))
			}))
			defer server.Close()

			rc := InitGaiaXRegistryVerificationService(server.URL)

			got, err := rc.GetComplianceIssuers()
			if (err != nil) != tt.wantErr {
				t.Errorf("GaiaXRegistryClient.GetComplianceIssuers() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GaiaXRegistryClient.GetComplianceIssuers() = %v, want %v", got, tt.want)
			}
		})
	}
}
