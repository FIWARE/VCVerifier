package config

import (
	"io"
	"io/ioutil"
	"strings"
	"testing"

	"net/http"

	"github.com/stretchr/testify/assert"
)

type MockHttpClient struct {
	Answer string
}

func (mhc MockHttpClient) Get(url string) (resp *http.Response, err error) {
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(mhc.Answer))}, nil
}

func readFile(filename string, t *testing.T) string {
	data, err := ioutil.ReadFile("data/" + filename)
	if err != nil {
		t.Error("could not read file", err)
	}
	return string(data)
}

func Test_getServices(t *testing.T) {
	mockedHttpClient := MockHttpClient{readFile("ccs_full.json", t)}
	ccsClient := HttpConfigClient{mockedHttpClient, "test.com"}
	services, err := ccsClient.GetServices()
	if err != nil {
		t.Error("should not return error", err)
	}
	assert.NotEmpty(t, services)
	expectedData := []ConfiguredService{
		{
			Id:               "service_all",
			DefaultOidcScope: "did_write",
			ServiceScopes: map[string][]Credential{
				"did_write": {
					{
						Type:                     "VerifiableCredential",
						TrustedParticipantsLists: []TrustedParticipantsList{{Type: "ebsi", Url: "https://tir-pdc.ebsi.fiware.dev"}},
						TrustedIssuersLists:      []string{"https://til-pdc.ebsi.fiware.dev"},
						HolderVerification:       HolderVerification{Enabled: false, Claim: "subject"},
					},
				},
			},
		},
	}
	assert.Equal(t, 1, len(services))
	assert.Equal(t, expectedData, services)

}
