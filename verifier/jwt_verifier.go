package verifier

import (
	"errors"
	"strings"

	"github.com/fiware/VCVerifier/gaiax"
	"github.com/fiware/VCVerifier/logging"
	"github.com/trustbloc/did-go/method/jwk"
	"github.com/trustbloc/did-go/method/key"
	"github.com/trustbloc/did-go/vdr"
	"github.com/trustbloc/vc-go/verifiable"
	"github.com/trustbloc/vc-go/vermethod"
)

var ErrorNoKID = errors.New("no_kid_provided")
var ErrorUnresolvableDid = errors.New("unresolvable_did")
var ErrorNoVerificationKey = errors.New("no_verification_key")
var ErrorNotAValidVerficationMethod = errors.New("not_a_valid_verfication_method")

const RsaVerificationKey2018 = "RsaVerificationKey2018"
const Ed25519VerificationKey2018 = "Ed25519VerificationKey2018"

var SupportedModes = []string{"none", "combined", "jsonLd", "baseContext"}

type TrustBlocValidator struct {
	validationMode string
}

type JWTVerfificationMethodResolver struct{}

func (jwtVMR JWTVerfificationMethodResolver) ResolveVerificationMethod(verificationMethod string, expectedProofIssuer string) (*vermethod.VerificationMethod, error) {
	registry := vdr.New(vdr.WithVDR(gaiax.NewGaiaxVDR()), vdr.WithVDR(key.New()), vdr.WithVDR(jwk.New()))
	didDocument, err := registry.Resolve(expectedProofIssuer)
	if err != nil {
		logging.Log().Warnf("Was not able to resolve the issuer %s. E: %v", expectedProofIssuer, err)
		return nil, ErrorUnresolvableDid
	}
	for _, vm := range didDocument.DIDDocument.VerificationMethod {
		if compareVerificationMethod(verificationMethod, vm.ID) {
			var vermethod = vermethod.VerificationMethod{Type: vm.Type, Value: vm.Value, JWK: vm.JSONWebKey()}
			return &vermethod, err
		}
	}
	return nil, ErrorNoVerificationKey
}

// the jwt-vc standard defines multiple options for the kid-header, while the standard implementation only allows for absolute paths.
// see https://identity.foundation/jwt-vc-presentation-profile/#kid-jose-header
// potential headers:
//   - thePublicKey(1)
//   - did:key:thePublicKey(2)
//   - did:key:thePublicKey#id(3)
func compareVerificationMethod(presentedMethod string, didDocumentMethod string) (result bool) {
	keyId, absolutePath, fullAbsolutePath, _ := getKeyFromMethod(didDocumentMethod)

	if presentedMethod != "" {
		return keyId == presentedMethod || absolutePath == presentedMethod || fullAbsolutePath == presentedMethod
	}
	logging.Log().Info("DidDocumentMethod is invalid.")
	return false

}

func getKeyFromMethod(verificationMethod string) (keyId, absolutePath, fullAbsolutePath string, err error) {
	keyArray := strings.Split(verificationMethod, "#")
	if len(keyArray) == 2 {
		// full-absolute path - format 3
		return keyArray[1], keyArray[0], verificationMethod, nil
	} else if didParts := strings.Split(verificationMethod, ":"); len(didParts) == 1 && len(keyArray) == 1 {
		// just the key - format 1
		return verificationMethod, absolutePath, fullAbsolutePath, nil
	} else if didParts := strings.Split(verificationMethod, ":"); len(didParts) > 1 && len(keyArray) == 1 {
		// absolute path did - format 2
		return didParts[len(didParts)-1], verificationMethod, fullAbsolutePath, nil
	}

	logging.Log().Warnf("The verification method %s is invalid.", verificationMethod)
	return keyId, absolutePath, fullAbsolutePath, ErrorNotAValidVerficationMethod
}

// the credential is already verified after parsing it from the VP, only content validation should happen here.
func (tbv TrustBlocValidator) ValidateVC(verifiableCredential *verifiable.Credential, verificationContext ValidationContext) (result bool, err error) {

	switch tbv.validationMode {
	case "none":
		return true, err
	case "combined":
		err = verifiableCredential.ValidateCredential()
	case "jsonLd":
		err = verifiableCredential.ValidateCredential(verifiable.WithJSONLDValidation())
	case "baseContext":
		err = verifiableCredential.ValidateCredential(verifiable.WithBaseContextValidation())
	}
	if err != nil {
		logging.Log().Info("Credential is invalid.")
		return false, err
	}
	return true, err
}
