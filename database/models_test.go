package database

import (
	"testing"

	"github.com/fiware/VCVerifier/config"
	"github.com/stretchr/testify/assert"
)

// ---------------------------------------------------------------------------
// RefreshTokenRow — basic struct instantiation tests
// ---------------------------------------------------------------------------

func TestRefreshTokenRow_Fields(t *testing.T) {
	tests := []struct {
		name       string
		row        RefreshTokenRow
		wantToken  string
		wantSuffix string
		wantClient string
		wantClaims string
		wantExp    int64
	}{
		{
			name: "all fields populated",
			row: RefreshTokenRow{
				Token:       "tok-abc",
				TokenSuffix: "k-abc",
				ClientID:    "client-1",
				Claims:      `{"iss":"https://verifier.example.com","sub":"did:key:holder"}`,
				ExpiresAt:   9999999999,
			},
			wantToken:  "tok-abc",
			wantSuffix: "k-abc",
			wantClient: "client-1",
			wantClaims: `{"iss":"https://verifier.example.com","sub":"did:key:holder"}`,
			wantExp:    9999999999,
		},
		{
			name: "empty suffix and claims",
			row: RefreshTokenRow{
				Token:     "tok-empty",
				ClientID:  "client-2",
				Claims:    "",
				ExpiresAt: 0,
			},
			wantToken:  "tok-empty",
			wantSuffix: "",
			wantClient: "client-2",
			wantClaims: "",
			wantExp:    0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.wantToken, tc.row.Token)
			assert.Equal(t, tc.wantSuffix, tc.row.TokenSuffix)
			assert.Equal(t, tc.wantClient, tc.row.ClientID)
			assert.Equal(t, tc.wantClaims, tc.row.Claims)
			assert.Equal(t, tc.wantExp, tc.row.ExpiresAt)
		})
	}
}

// ---------------------------------------------------------------------------
// ClaimsQueryDB — VO / FromVO round-trip
// ---------------------------------------------------------------------------

func TestClaimsQueryDB_VO(t *testing.T) {
	db := ClaimsQueryDB{
		Id:             "claim-1",
		Path:           []interface{}{"credentialSubject", "familyName"},
		Values:         []interface{}{"Smith"},
		IntentToRetain: true,
		Namespace:      "eu.europa.ec.eudi.pid.1",
		ClaimName:      "family_name",
	}
	vo := db.VO()
	assert.Equal(t, "claim-1", vo.Id)
	assert.Equal(t, []interface{}{"credentialSubject", "familyName"}, vo.Path)
	assert.Equal(t, []interface{}{"Smith"}, vo.Values)
	assert.True(t, vo.IntentToRetain)
	assert.Equal(t, "eu.europa.ec.eudi.pid.1", vo.Namespace)
	assert.Equal(t, "family_name", vo.ClaimName)
}

func TestClaimsQueryDB_FromVO(t *testing.T) {
	vo := config.ClaimsQuery{
		Id:             "claim-2",
		Path:           []interface{}{"credentialSubject", "givenName"},
		Values:         []interface{}{"John"},
		IntentToRetain: false,
		Namespace:      "ns",
		ClaimName:      "given_name",
	}
	db := ClaimsQueryDB{}.FromVO(vo)
	assert.Equal(t, "claim-2", db.Id)
	assert.Equal(t, []interface{}{"credentialSubject", "givenName"}, db.Path)
	assert.Equal(t, []interface{}{"John"}, db.Values)
	assert.False(t, db.IntentToRetain)
	assert.Equal(t, "ns", db.Namespace)
	assert.Equal(t, "given_name", db.ClaimName)
}

// ---------------------------------------------------------------------------
// CredentialQueryDB — format mapping in VO / FromVO
// ---------------------------------------------------------------------------

func TestCredentialQueryDB_VO_FormatMapping(t *testing.T) {
	tests := []struct {
		dbFormat   string
		wantFormat string
	}{
		{"DC_SD_JWT", "dc+sd-jwt"},
		{"VC_SD_JWT", "vc+sd-jwt"},
		{"MSO_MDOC", "mso_mdoc"},
		{"LDP_VC", "ldp_vc"},
		{"JWT_VC_JSON", "jwt_vc_json"},
		// unknown format falls back to lower-case
		{"CUSTOM_FORMAT", "custom_format"},
	}

	for _, tc := range tests {
		t.Run(tc.dbFormat, func(t *testing.T) {
			db := CredentialQueryDB{Format: tc.dbFormat}
			vo := db.VO()
			assert.Equal(t, tc.wantFormat, vo.Format)
		})
	}
}

func TestCredentialQueryDB_FromVO_FormatMapping(t *testing.T) {
	tests := []struct {
		voFormat   string
		wantFormat string
	}{
		{"dc+sd-jwt", "DC_SD_JWT"},
		{"vc+sd-jwt", "VC_SD_JWT"},
		{"mso_mdoc", "MSO_MDOC"},
		{"ldp_vc", "LDP_VC"},
		{"jwt_vc_json", "JWT_VC_JSON"},
		// unknown format falls back to upper-case
		{"custom_format", "CUSTOM_FORMAT"},
	}

	for _, tc := range tests {
		t.Run(tc.voFormat, func(t *testing.T) {
			vo := config.CredentialQuery{Format: tc.voFormat}
			db := CredentialQueryDB{}.FromVO(vo)
			assert.Equal(t, tc.wantFormat, db.Format)
		})
	}
}

func TestCredentialQueryDB_VO_ClaimsConverted(t *testing.T) {
	db := CredentialQueryDB{
		Id:     "cred-1",
		Format: "DC_SD_JWT",
		Claims: []ClaimsQueryDB{
			{Id: "c1", Path: []interface{}{"sub"}, Values: []interface{}{"alice"}},
			{Id: "c2", Namespace: "ns", ClaimName: "age"},
		},
		ClaimSets: [][]string{{"c1", "c2"}},
	}
	vo := db.VO()
	assert.Len(t, vo.Claims, 2)
	assert.Equal(t, "c1", vo.Claims[0].Id)
	assert.Equal(t, []interface{}{"sub"}, vo.Claims[0].Path)
	assert.Equal(t, "c2", vo.Claims[1].Id)
	assert.Equal(t, "age", vo.Claims[1].ClaimName)
	assert.Equal(t, [][]string{{"c1", "c2"}}, vo.ClaimSets)
}

func TestCredentialQueryDB_FromVO_ClaimsConverted(t *testing.T) {
	reqBinding := false
	vo := config.CredentialQuery{
		Id:     "cred-2",
		Format: "dc+sd-jwt",
		Claims: []config.ClaimsQuery{
			{Id: "c1", Path: []interface{}{"given_name"}},
		},
		RequireCryptographicHolderBinding: &reqBinding,
		ClaimSets:                         [][]string{{"c1"}},
	}
	db := CredentialQueryDB{}.FromVO(vo)
	assert.Equal(t, "DC_SD_JWT", db.Format)
	assert.Len(t, db.Claims, 1)
	assert.Equal(t, "c1", db.Claims[0].Id)
	assert.Equal(t, []interface{}{"given_name"}, db.Claims[0].Path)
	assert.False(t, db.RequireCryptographicHolderBinding)
	assert.Equal(t, [][]string{{"c1"}}, db.ClaimSets)
}

// ---------------------------------------------------------------------------
// DCQLDB — full VO / FromVO conversion
// ---------------------------------------------------------------------------

func TestDCQLDB_VO(t *testing.T) {
	db := DCQLDB{
		Credentials: []CredentialQueryDB{
			{Id: "pid", Format: "DC_SD_JWT", Claims: []ClaimsQueryDB{{Id: "fn", Path: []interface{}{"family_name"}}}},
		},
		CredentialSets: []config.CredentialSetQuery{
			{Options: [][]string{{"pid"}}, Required: true},
		},
	}
	vo := db.VO()
	assert.Len(t, vo.Credentials, 1)
	assert.Equal(t, "pid", vo.Credentials[0].Id)
	assert.Equal(t, "dc+sd-jwt", vo.Credentials[0].Format)
	assert.Len(t, vo.Credentials[0].Claims, 1)
	assert.Equal(t, "fn", vo.Credentials[0].Claims[0].Id)
	assert.Len(t, vo.CredentialSets, 1)
	assert.Equal(t, [][]string{{"pid"}}, vo.CredentialSets[0].Options)
}

func TestDCQLDB_FromVO(t *testing.T) {
	reqBinding := true
	vo := config.DCQL{
		Credentials: []config.CredentialQuery{
			{
				Id:     "mdl",
				Format: "mso_mdoc",
				Claims: []config.ClaimsQuery{{Id: "age", Namespace: "org.iso.18013.5.1", ClaimName: "age_over_18"}},
				RequireCryptographicHolderBinding: &reqBinding,
			},
		},
		CredentialSets: []config.CredentialSetQuery{
			{Options: [][]string{{"mdl"}}, Required: false},
		},
	}
	db := DCQLDB{}.FromVO(vo)
	assert.Len(t, db.Credentials, 1)
	assert.Equal(t, "MSO_MDOC", db.Credentials[0].Format)
	assert.Equal(t, "mdl", db.Credentials[0].Id)
	assert.Len(t, db.Credentials[0].Claims, 1)
	assert.Equal(t, "age", db.Credentials[0].Claims[0].Id)
	assert.Equal(t, "org.iso.18013.5.1", db.Credentials[0].Claims[0].Namespace)
	assert.True(t, db.Credentials[0].RequireCryptographicHolderBinding)
	assert.Len(t, db.CredentialSets, 1)
}
