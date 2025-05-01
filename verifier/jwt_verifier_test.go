package verifier

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/did-go/method/jwk"
	"github.com/trustbloc/did-go/method/key"
	"github.com/trustbloc/did-go/method/web"
	"github.com/trustbloc/did-go/vdr"
)

func TestJWTVerfificationMethodResolver_ResolveVerificationMethod(t *testing.T) {
	const did = "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KbnPqt55NG29q8Re1ZVdg7X8RpqraEb9YaMyypYLzMyvre78pJ3Mz1GeN71YL1GBvwtNu5KtoDeT6D51hAY2VMemiqDihyqnTGHosBNRykPCYtLe8XiHfWFWMdc3XRvyeWXv"

	registry := vdr.New(vdr.WithVDR(web.New()), vdr.WithVDR(key.New()), vdr.WithVDR(jwk.New()))
	didDocument, err := registry.Resolve(did)
	require.NoError(t, err, "No error should occure when resolving this DID")
	require.NotNil(t, didDocument, "DID Document should have been created for DID")
	require.Equal(t, did, didDocument.DIDDocument.ID, "The DID Document id should be the did:key")
	require.Len(t, didDocument.DIDDocument.VerificationMethod, 1, "Should have exactly one verification method")
	require.NotNil(t, didDocument.DIDDocument.VerificationMethod[0].JSONWebKey().JSONWebKey, "JWK should have been parsed")
}
