// Package eidas provides parsing and handling of ETSI TS 119 612 EU Trusted Lists.
//
// ETSI TS 119 612 defines the XML schema for EU Trusted Lists (TLs) used in the
// eIDAS trust framework. A List of Trusted Lists (LOTL) references national TLs,
// each of which contains Trust Service Providers (TSPs) and their trust services.
//
// This package parses trust list XML documents into Go structs and extracts X.509
// certificates from service digital identities for trust validation.
//
// Known limitation: XMLDSig signature verification on trust lists is not yet
// implemented. The caller must ensure transport-level integrity (e.g. HTTPS).
package eidas

import (
	"crypto/x509"
	"encoding/xml"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/fiware/VCVerifier/common"
)

// XML namespace for ETSI TS 119 612 trust lists (v2).
const TrustListNamespace = "https://uri.etsi.org/02231/v2#"

// TSLTag identifies the trust list format version.
const TSLTag = "https://uri.etsi.org/19612/TSLTag"

// TrustListClockSkewTolerance is the allowance applied when comparing trust
// list timestamps against the local clock, so that modest clock drift between
// the scheme operator and this verifier does not invalidate a list.
const TrustListClockSkewTolerance = 5 * time.Minute

// ErrorTrustListStale is returned when a trust list's NextUpdate time has
// passed: the scheme operator committed to publishing a newer list by then, so
// the content can no longer be assumed to reflect the current service statuses.
var ErrorTrustListStale = errors.New("trust_list_stale")

// ErrorTrustListNotYetIssued is returned when a trust list's ListIssueDateTime
// lies in the future, beyond the clock skew tolerance.
var ErrorTrustListNotYetIssued = errors.New("trust_list_not_yet_issued")

// ErrorTrustListRollback is returned when a fetched national trust list carries
// a lower TSLSequenceNumber than the list already loaded for that country.
var ErrorTrustListRollback = errors.New("trust_list_rollback")

// ErrorInvalidTrustListTimestamp is returned when ListIssueDateTime or
// NextUpdate carries a value that cannot be parsed.
var ErrorInvalidTrustListTimestamp = errors.New("invalid_trust_list_timestamp")

// ErrorInvalidStatusStartingTime is returned when a trust service carries a
// StatusStartingTime that cannot be parsed. The value is mandatory per
// ETSI TS 119 612 §5.5.5 and time-based status evaluation depends on it, so
// an unparseable value invalidates the entry instead of defaulting to the
// zero time.
var ErrorInvalidStatusStartingTime = errors.New("invalid_status_starting_time")

// --- Service Type Identifier URIs (ETSI TS 119 612 §5.5.1) ---

const (
	// ServiceTypeCAQC identifies a Certification Authority issuing qualified certificates.
	ServiceTypeCAQC = "https://uri.etsi.org/TrstSvc/Svctype/CA/QC"

	// ServiceTypeQTST identifies a Qualified Time Stamping Authority.
	ServiceTypeQTST = "https://uri.etsi.org/TrstSvc/Svctype/TSA/QTST"

	// ServiceTypeTSA identifies a (non-qualified) Time Stamping Authority.
	ServiceTypeTSA = "https://uri.etsi.org/TrstSvc/Svctype/TSA"

	// ServiceTypeCA identifies a (non-qualified) Certification Authority.
	ServiceTypeCA = "https://uri.etsi.org/TrstSvc/Svctype/CA"

	// ServiceTypeIdV identifies an Identity Verification service.
	ServiceTypeIdV = "https://uri.etsi.org/TrstSvc/Svctype/IdV"

	// ServiceTypeNationalRootCAQC identifies a national root CA for qualified certificates.
	ServiceTypeNationalRootCAQC = "https://uri.etsi.org/TrstSvc/Svctype/NationalRootCA-QC"

	// ServiceTypeEDS identifies an Electronic Delivery Service.
	ServiceTypeEDS = "https://uri.etsi.org/TrstSvc/Svctype/EDS/Q"

	// ServiceTypeREMD identifies a Qualified Electronic Registered Delivery Service.
	ServiceTypeREMD = "https://uri.etsi.org/TrstSvc/Svctype/EDS/REM/Q"
)

// --- Service Status URIs (ETSI TS 119 612 §5.5.4) ---

const (
	// ServiceStatusGranted indicates the service has been granted (active and trusted).
	ServiceStatusGranted = "https://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"

	// ServiceStatusWithdrawn indicates the service has been withdrawn.
	ServiceStatusWithdrawn = "https://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn"

	// ServiceStatusRecognisedAtNationalLevel indicates the service is recognised at national level.
	ServiceStatusRecognisedAtNationalLevel = "https://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel"

	// ServiceStatusDeprecatedAtNationalLevel indicates the service is deprecated at national level.
	ServiceStatusDeprecatedAtNationalLevel = "https://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/deprecatedatnationallevel"

	// ServiceStatusSetByNationalLaw indicates the service status is set by national law.
	ServiceStatusSetByNationalLaw = "https://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/setbynationallaw"

	// ServiceStatusUnderSupervision indicates the service is under supervision.
	ServiceStatusUnderSupervision = "https://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision"
)

// --- Status Determination Approaches (ETSI TS 119 612 §5.3.13) ---
//
// The approach is declared as a URI. Only the final path segment is
// significant for identification: lists in the wild differ in the URI scheme
// (http vs. https) and in intermediate path segments, so matching is done on
// the segment rather than on the full URI.
const (
	// StatusDetnEUAppropriate marks a list whose service statuses are
	// determined according to the EU rules. Declared by EU national trust lists.
	StatusDetnEUAppropriate = "euappropriate"

	// StatusDetnEUListOfTheLists marks the status determination approach of the
	// EU List of Trusted Lists itself.
	StatusDetnEUListOfTheLists = "eulistofthelists"

	// StatusDetnCCDetermination marks a list whose service statuses are
	// determined by the scheme operator of a third country.
	StatusDetnCCDetermination = "ccdetermination"
)

// --- TSL Type URIs ---

const (
	// TSLTypeEUGeneric identifies a generic EU trust list.
	TSLTypeEUGeneric = "https://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric"

	// TSLTypeEUListOfTheLists identifies the EU List of Trusted Lists (LOTL).
	TSLTypeEUListOfTheLists = "https://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists"
)

// --- XML Struct Definitions ---

// TrustServiceStatusList is the root element of an ETSI TS 119 612 trust list XML document.
// It contains scheme information (metadata about the list) and optionally a list of
// trust service providers with their services.
type TrustServiceStatusList struct {
	XMLName                  xml.Name                  `xml:"TrustServiceStatusList"`
	ID                       string                    `xml:"Id,attr,omitempty"`
	TSLTag                   string                    `xml:"TSLTag,attr,omitempty"`
	SchemeInformation        SchemeInformation         `xml:"SchemeInformation"`
	TrustServiceProviderList *TrustServiceProviderList `xml:"TrustServiceProviderList,omitempty"`
}

// IsLOTL returns true if this trust list is a List of Trusted Lists (LOTL),
// determined by the TSLType field in SchemeInformation.
func (tl *TrustServiceStatusList) IsLOTL() bool {
	return tl.SchemeInformation.TSLType == TSLTypeEUListOfTheLists
}

// ValidateFreshness checks the trust list's own timestamps against now.
//
// It returns an error when
//   - ListIssueDateTime or NextUpdate is present but unparseable
//     (ErrorInvalidTrustListTimestamp),
//   - the list claims to have been issued in the future
//     (ErrorTrustListNotYetIssued), or
//   - the NextUpdate time has passed (ErrorTrustListStale).
//
// Both comparisons allow TrustListClockSkewTolerance. A list that declares no
// NextUpdate at all cannot be judged for staleness and is accepted; the caller
// is expected to surface that case to the operator.
func (tl *TrustServiceStatusList) ValidateFreshness(now time.Time) error {
	si := tl.SchemeInformation

	if issued := strings.TrimSpace(si.ListIssueDateTime); issued != "" {
		issueTime, err := parseDateTime(issued)
		if err != nil {
			return fmt.Errorf("%w: ListIssueDateTime: %v", ErrorInvalidTrustListTimestamp, err)
		}
		if issueTime.After(now.Add(TrustListClockSkewTolerance)) {
			return fmt.Errorf("%w: issued at %s, current time is %s",
				ErrorTrustListNotYetIssued, issueTime.Format(time.RFC3339), now.Format(time.RFC3339))
		}
	}

	nextUpdate := strings.TrimSpace(si.NextUpdate.DateTime)
	if nextUpdate == "" {
		// ETSI TS 119 612 allows an empty NextUpdate for lists that are not
		// published on a fixed schedule. Nothing to compare against.
		return nil
	}

	nextUpdateTime, err := parseDateTime(nextUpdate)
	if err != nil {
		return fmt.Errorf("%w: NextUpdate: %v", ErrorInvalidTrustListTimestamp, err)
	}
	if now.After(nextUpdateTime.Add(TrustListClockSkewTolerance)) {
		return fmt.Errorf("%w: NextUpdate was %s, current time is %s",
			ErrorTrustListStale, nextUpdateTime.Format(time.RFC3339), now.Format(time.RFC3339))
	}

	return nil
}

// HasNextUpdate reports whether the list declares a NextUpdate time at all.
// A list without one cannot be checked for staleness.
func (tl *TrustServiceStatusList) HasNextUpdate() bool {
	return strings.TrimSpace(tl.SchemeInformation.NextUpdate.DateTime) != ""
}

// SequenceNumber returns the list's TSLSequenceNumber. Within one scheme
// territory the sequence number increases with every published list, so a
// value lower than one already seen indicates that an older list is being
// served in place of a newer one.
func (tl *TrustServiceStatusList) SequenceNumber() int {
	return tl.SchemeInformation.TSLSequenceNumber
}

// StatusDeterminationKind returns the normalised status determination approach
// declared by the list: the lower-cased final path segment of the
// StatusDeterminationApproach URI, or an empty string when none is declared.
// It is compared against the StatusDetn* constants.
func (si SchemeInformation) StatusDeterminationKind() string {
	approach := strings.TrimSpace(si.StatusDeterminationApproach)
	if approach == "" {
		return ""
	}
	approach = strings.TrimRight(approach, "/")
	if idx := strings.LastIndex(approach, "/"); idx >= 0 {
		approach = approach[idx+1:]
	}
	return strings.ToLower(approach)
}

// IsEUStatusDetermination reports whether the service statuses in this list are
// determined according to the EU rules (ETSI TS 119 612 §5.3.13). A list using
// a third-country approach (CCdetermination), or declaring no approach at all,
// returns false: its "granted" statuses do not carry the EU meaning that the
// trust decisions in this package assume.
func (si SchemeInformation) IsEUStatusDetermination() bool {
	switch si.StatusDeterminationKind() {
	case StatusDetnEUAppropriate, StatusDetnEUListOfTheLists:
		return true
	default:
		return false
	}
}

// SchemeInformation contains metadata about the trust list, including the
// scheme operator, territory, type, and pointers to other trust lists (for LOTLs).
type SchemeInformation struct {
	TSLVersionIdentifier        int                 `xml:"TSLVersionIdentifier"`
	TSLSequenceNumber           int                 `xml:"TSLSequenceNumber"`
	TSLType                     string              `xml:"TSLType"`
	SchemeOperatorName          InternationalNames  `xml:"SchemeOperatorName"`
	SchemeName                  InternationalNames  `xml:"SchemeName"`
	SchemeInformationURI        InternationalURIs   `xml:"SchemeInformationURI"`
	StatusDeterminationApproach string              `xml:"StatusDeterminationApproach"`
	SchemeTerritory             string              `xml:"SchemeTerritory"`
	HistoricalInformationPeriod int                 `xml:"HistoricalInformationPeriod"`
	ListIssueDateTime           string              `xml:"ListIssueDateTime"`
	NextUpdate                  NextUpdate          `xml:"NextUpdate"`
	PointersToOtherTSL          *PointersToOtherTSL `xml:"PointersToOtherTSL,omitempty"`
}

// NextUpdate holds the date/time when the next update of the trust list is expected.
type NextUpdate struct {
	DateTime string `xml:"dateTime"`
}

// InternationalNames holds a list of multilingual name values, each tagged with an xml:lang attribute.
type InternationalNames struct {
	Names []InternationalName `xml:"Name"`
}

// GetEnglish returns the English-language name, or the first available name if
// no English name exists, or an empty string if no names are present.
func (n InternationalNames) GetEnglish() string {
	for _, name := range n.Names {
		if strings.EqualFold(name.Lang, "en") {
			return name.Value
		}
	}
	if len(n.Names) > 0 {
		return n.Names[0].Value
	}
	return ""
}

// InternationalName is a single multilingual name value with a language tag.
type InternationalName struct {
	Lang  string `xml:"lang,attr"`
	Value string `xml:",chardata"`
}

// InternationalURIs holds a list of multilingual URI values.
type InternationalURIs struct {
	URIs []InternationalURI `xml:"URI"`
}

// InternationalURI is a single multilingual URI value with a language tag.
type InternationalURI struct {
	Lang  string `xml:"lang,attr"`
	Value string `xml:",chardata"`
}

// --- Pointers to Other TSL (for LOTL) ---

// PointersToOtherTSL contains references to other trust lists, typically
// national trust lists pointed to by a LOTL.
type PointersToOtherTSL struct {
	OtherTSLPointers []OtherTSLPointer `xml:"OtherTSLPointer"`
}

// OtherTSLPointer represents a reference to another trust list, including its
// download URL, digital identity for signature verification, and additional
// metadata such as country code and TSL type.
type OtherTSLPointer struct {
	ServiceDigitalIdentities ServiceDigitalIdentities `xml:"ServiceDigitalIdentities"`
	TSLLocation              string                   `xml:"TSLLocation"`
	AdditionalInformation    AdditionalInformation    `xml:"AdditionalInformation"`
}

// GetSchemeTerritory extracts the country code from the pointer's additional information.
func (p OtherTSLPointer) GetSchemeTerritory() string {
	for _, info := range p.AdditionalInformation.OtherInformation {
		if info.SchemeTerritory != "" {
			return info.SchemeTerritory
		}
	}
	return ""
}

// GetTSLType extracts the TSL type from the pointer's additional information.
func (p OtherTSLPointer) GetTSLType() string {
	for _, info := range p.AdditionalInformation.OtherInformation {
		if info.TSLType != "" {
			return info.TSLType
		}
	}
	return ""
}

// AdditionalInformation holds supplementary metadata about a TSL pointer.
type AdditionalInformation struct {
	OtherInformation []OtherInformation `xml:"OtherInformation"`
}

// OtherInformation holds metadata fields found within a TSL pointer's additional information.
// Only SchemeTerritory, TSLType, and SchemeOperatorName are extracted; other fields are ignored.
type OtherInformation struct {
	SchemeTerritory    string             `xml:"SchemeTerritory"`
	TSLType            string             `xml:"TSLType"`
	SchemeOperatorName InternationalNames `xml:"SchemeOperatorName"`
}

// --- Trust Service Providers ---

// TrustServiceProviderList wraps the list of trust service providers in a trust list.
type TrustServiceProviderList struct {
	TrustServiceProviders []TrustServiceProvider `xml:"TrustServiceProvider"`
}

// TrustServiceProvider represents a single trust service provider (TSP) entry,
// containing the provider's identity information and its trust services.
type TrustServiceProvider struct {
	TSPInformation TSPInformation `xml:"TSPInformation"`
	TSPServices    TSPServices    `xml:"TSPServices"`
}

// TSPInformation holds identity and contact information for a trust service provider.
type TSPInformation struct {
	TSPName           InternationalNames `xml:"TSPName"`
	TSPTradeName      InternationalNames `xml:"TSPTradeName"`
	TSPInformationURI InternationalURIs  `xml:"TSPInformationURI"`
}

// TSPServices wraps the list of trust services offered by a TSP.
type TSPServices struct {
	TSPService []TSPService `xml:"TSPService"`
}

// TSPService represents a single trust service entry within a TSP.
type TSPService struct {
	ServiceInformation ServiceInformation `xml:"ServiceInformation"`
	ServiceHistory     *ServiceHistory    `xml:"ServiceHistory,omitempty"`
}

// ServiceInformation holds the core details of a trust service: its type,
// status, digital identities (X.509 certificates), and extensions.
type ServiceInformation struct {
	ServiceTypeIdentifier        string                        `xml:"ServiceTypeIdentifier"`
	ServiceName                  InternationalNames            `xml:"ServiceName"`
	ServiceDigitalIdentity       ServiceDigitalIdentity        `xml:"ServiceDigitalIdentity"`
	ServiceStatus                string                        `xml:"ServiceStatus"`
	StatusStartingTime           string                        `xml:"StatusStartingTime"`
	ServiceInformationExtensions *ServiceInformationExtensions `xml:"ServiceInformationExtensions,omitempty"`
}

// ServiceHistory contains historical service status entries.
type ServiceHistory struct {
	ServiceHistoryInstances []ServiceHistoryInstance `xml:"ServiceHistoryInstance"`
}

// ServiceHistoryInstance represents a historical status entry for a trust service.
type ServiceHistoryInstance struct {
	ServiceTypeIdentifier        string                        `xml:"ServiceTypeIdentifier"`
	ServiceName                  InternationalNames            `xml:"ServiceName"`
	ServiceDigitalIdentity       ServiceDigitalIdentity        `xml:"ServiceDigitalIdentity"`
	ServiceStatus                string                        `xml:"ServiceStatus"`
	StatusStartingTime           string                        `xml:"StatusStartingTime"`
	ServiceInformationExtensions *ServiceInformationExtensions `xml:"ServiceInformationExtensions,omitempty"`
}

// ServiceInformationExtensions holds extension data for a service entry.
type ServiceInformationExtensions struct {
	Extensions []Extension `xml:"Extension"`
}

// Extension represents a single service information extension element.
type Extension struct {
	Critical                     bool                          `xml:"Critical,attr"`
	ExpiredCertsRevocationInfo   string                        `xml:"ExpiredCertsRevocationInfo,omitempty"`
	AdditionalServiceInformation *AdditionalServiceInformation `xml:"AdditionalServiceInformation,omitempty"`
}

// AdditionalServiceInformation holds the URI of additional service information.
type AdditionalServiceInformation struct {
	URI InternationalURI `xml:"URI"`
}

// --- Digital Identity ---

// ServiceDigitalIdentities wraps a list of digital identity containers (used in TSL pointers).
type ServiceDigitalIdentities struct {
	ServiceDigitalIdentity []ServiceDigitalIdentity `xml:"ServiceDigitalIdentity"`
}

// ServiceDigitalIdentity holds one or more digital identity entries for a trust service.
// Each DigitalId may contain an X.509 certificate, subject name, or subject key identifier.
type ServiceDigitalIdentity struct {
	DigitalIds []DigitalId `xml:"DigitalId"`
}

// DigitalId represents a single digital identity entry. Exactly one of
// X509Certificate, X509SubjectName, or X509SKI is typically populated.
type DigitalId struct {
	X509Certificate string `xml:"X509Certificate,omitempty"`
	X509SubjectName string `xml:"X509SubjectName,omitempty"`
	X509SKI         string `xml:"X509SKI,omitempty"`
}

// --- Parsing ---

// ParseTrustList parses an ETSI TS 119 612 trust list XML document from raw bytes
// into a TrustServiceStatusList struct.
//
// The function validates the basic structure but does not verify the XML digital
// signature. Callers must ensure transport-level integrity (e.g. via HTTPS).
func ParseTrustList(xmlData []byte) (*TrustServiceStatusList, error) {
	var tl TrustServiceStatusList
	if err := xml.Unmarshal(xmlData, &tl); err != nil {
		return nil, fmt.Errorf("failed to parse trust list XML: %w", err)
	}

	return &tl, nil
}

// --- Certificate Extraction ---

// ExtractServiceCertificates extracts X.509 certificates from a ServiceDigitalIdentity.
// Each DigitalId entry with a non-empty X509Certificate field is base64-decoded and
// parsed into an *x509.Certificate using common.ParseBase64Certificate.
// Entries without X509Certificate data are skipped.
// Returns an error if any certificate data is malformed.
func ExtractServiceCertificates(identity ServiceDigitalIdentity) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for i, did := range identity.DigitalIds {
		if did.X509Certificate == "" {
			continue
		}
		cert, err := common.ParseBase64Certificate(did.X509Certificate)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate at index %d: %w", i, err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// GetDistributionPoints extracts the national trust list URLs from a LOTL's
// PointersToOtherTSL section. Only pointers with a TSLType of EUgeneric
// (i.e. national trust lists, not other LOTLs) are included.
// Each returned DistributionPoint includes the TSL URL and the scheme territory.
func (tl *TrustServiceStatusList) GetDistributionPoints() []DistributionPoint {
	if tl.SchemeInformation.PointersToOtherTSL == nil {
		return nil
	}
	var points []DistributionPoint
	for _, ptr := range tl.SchemeInformation.PointersToOtherTSL.OtherTSLPointers {
		tslType := ptr.GetTSLType()
		// Include only national TLs (EUgeneric), not pointers to other LOTLs
		if tslType != TSLTypeEUGeneric {
			continue
		}
		points = append(points, DistributionPoint{
			TSLLocation:     ptr.TSLLocation,
			SchemeTerritory: ptr.GetSchemeTerritory(),
		})
	}
	return points
}

// DistributionPoint represents a pointer from a LOTL to a national trust list,
// including the download URL and the country code.
type DistributionPoint struct {
	// TSLLocation is the URL from which the national trust list can be downloaded.
	TSLLocation string
	// SchemeTerritory is the ISO 3166-1 alpha-2 country code for the national trust list.
	SchemeTerritory string
}

// GetTrustServices extracts all trust services from the trust list as a flat
// list of TrustedService structs, enriched with the scheme territory from the
// trust list metadata and the TSP name from the provider entry.
func (tl *TrustServiceStatusList) GetTrustServices() ([]TrustedService, error) {
	if tl.TrustServiceProviderList == nil {
		return nil, nil
	}
	territory := tl.SchemeInformation.SchemeTerritory
	var services []TrustedService
	for _, tsp := range tl.TrustServiceProviderList.TrustServiceProviders {
		tspName := tsp.TSPInformation.TSPName.GetEnglish()
		for _, svc := range tsp.TSPServices.TSPService {
			info := svc.ServiceInformation
			certs, err := ExtractServiceCertificates(info.ServiceDigitalIdentity)
			if err != nil {
				return nil, fmt.Errorf("failed to extract certificates for service %q of TSP %q: %w",
					info.ServiceName.GetEnglish(), tspName, err)
			}
			// StatusStartingTime is mandatory (ETSI TS 119 612 §5.5.5) and is the
			// basis for evaluating a service status as of a point in time. An
			// entry we cannot place on the timeline is rejected rather than
			// silently treated as "in effect since the zero time".
			statusTime, err := parseDateTime(info.StatusStartingTime)
			if err != nil {
				return nil, fmt.Errorf("%w: service %q of TSP %q: %v",
					ErrorInvalidStatusStartingTime, info.ServiceName.GetEnglish(), tspName, err)
			}
			history, err := extractServiceHistory(svc.ServiceHistory, info.ServiceName.GetEnglish(), tspName)
			if err != nil {
				return nil, err
			}

			services = append(services, TrustedService{
				CountryCode:        territory,
				TSPName:            tspName,
				ServiceName:        info.ServiceName.GetEnglish(),
				ServiceType:        info.ServiceTypeIdentifier,
				ServiceStatus:      info.ServiceStatus,
				StatusStartingTime: statusTime,
				Certificates:       certs,
				History:            history,
			})
		}
	}
	return services, nil
}

// TrustedService represents a single trust service extracted from a trust list,
// with all the fields needed for trust validation.
type TrustedService struct {
	// CountryCode is the ISO 3166-1 alpha-2 country code from the trust list's SchemeTerritory.
	CountryCode string
	// TSPName is the English name of the trust service provider.
	TSPName string
	// ServiceName is the English name of the service.
	ServiceName string
	// ServiceType is the ETSI service type identifier URI.
	ServiceType string
	// ServiceStatus is the ETSI service status URI.
	ServiceStatus string
	// StatusStartingTime is the time from which the current status applies.
	StatusStartingTime time.Time
	// Certificates are the X.509 certificates associated with this service.
	Certificates []*x509.Certificate
	// History holds the service's previous status entries, oldest first. It is
	// populated from the ServiceHistory element and is what makes it possible
	// to evaluate the service status as of a point in the past.
	History []ServiceStatusRecord
}

// ServiceStatusRecord is one entry on a trust service's status timeline: the
// service type and status that took effect at StatusStartingTime and applied
// until the next entry began.
type ServiceStatusRecord struct {
	// ServiceType is the ETSI service type identifier URI in effect for this entry.
	ServiceType string
	// ServiceStatus is the ETSI service status URI in effect for this entry.
	ServiceStatus string
	// StatusStartingTime is the time from which this entry applies.
	StatusStartingTime time.Time
}

// RecordAt returns the status record in effect at the given time: the most
// recent entry — current or historical — whose StatusStartingTime is not after
// at. The second return value is false when the service has no entry covering
// that time, which happens when at predates the service's first known status.
//
// A zero at returns the current entry, matching the behaviour of the
// ServiceType / ServiceStatus fields.
func (ts TrustedService) RecordAt(at time.Time) (ServiceStatusRecord, bool) {
	current := ServiceStatusRecord{
		ServiceType:        ts.ServiceType,
		ServiceStatus:      ts.ServiceStatus,
		StatusStartingTime: ts.StatusStartingTime,
	}
	if at.IsZero() {
		return current, true
	}

	best := ServiceStatusRecord{}
	found := false
	consider := func(record ServiceStatusRecord) {
		if record.StatusStartingTime.After(at) {
			return
		}
		if !found || record.StatusStartingTime.After(best.StatusStartingTime) {
			best = record
			found = true
		}
	}

	for _, record := range ts.History {
		consider(record)
	}
	consider(current)

	return best, found
}

// IsGrantedAt reports whether the service was in granted status at the given
// time. A time that predates the service's first known status returns false:
// the service cannot be shown to have been trusted then.
//
// A zero at evaluates the current status, matching IsGranted.
func (ts TrustedService) IsGrantedAt(at time.Time) bool {
	record, ok := ts.RecordAt(at)
	return ok && record.ServiceStatus == ServiceStatusGranted
}

// HasServiceTypeAt reports whether the service had one of the given service
// types at the given time. An empty serviceTypes matches any type.
//
// A zero at evaluates the current service type.
func (ts TrustedService) HasServiceTypeAt(at time.Time, serviceTypes map[string]struct{}) bool {
	if len(serviceTypes) == 0 {
		return true
	}
	record, ok := ts.RecordAt(at)
	if !ok {
		return false
	}
	_, matches := serviceTypes[record.ServiceType]
	return matches
}

// extractServiceHistory converts the parsed ServiceHistory element into status
// records. An entry whose StatusStartingTime cannot be parsed is rejected for
// the same reason as in the current ServiceInformation: it cannot be placed on
// the timeline.
func extractServiceHistory(history *ServiceHistory, serviceName, tspName string) ([]ServiceStatusRecord, error) {
	if history == nil || len(history.ServiceHistoryInstances) == 0 {
		return nil, nil
	}

	records := make([]ServiceStatusRecord, 0, len(history.ServiceHistoryInstances))
	for _, instance := range history.ServiceHistoryInstances {
		statusTime, err := parseDateTime(instance.StatusStartingTime)
		if err != nil {
			return nil, fmt.Errorf("%w: history entry of service %q of TSP %q: %v",
				ErrorInvalidStatusStartingTime, serviceName, tspName, err)
		}
		records = append(records, ServiceStatusRecord{
			ServiceType:        instance.ServiceTypeIdentifier,
			ServiceStatus:      instance.ServiceStatus,
			StatusStartingTime: statusTime,
		})
	}

	sort.Slice(records, func(i, j int) bool {
		return records[i].StatusStartingTime.Before(records[j].StatusStartingTime)
	})

	return records, nil
}

// IsQualified returns true if the service type URI indicates a qualified trust service.
// Qualified services are identified by matching one of the known qualified service
// type URIs defined in ETSI TS 119 612 (CA/QC, QTST, NationalRootCA-QC, EDS/Q, EDS/REM/Q).
func (ts TrustedService) IsQualified() bool {
	// Qualified service types per ETSI TS 119 612
	qualifiedTypes := []string{
		ServiceTypeCAQC,
		ServiceTypeQTST,
		ServiceTypeNationalRootCAQC,
		ServiceTypeEDS,
		ServiceTypeREMD,
	}
	for _, qt := range qualifiedTypes {
		if ts.ServiceType == qt {
			return true
		}
	}
	return false
}

// IsGranted returns true if the service has the "granted" status.
func (ts TrustedService) IsGranted() bool {
	return ts.ServiceStatus == ServiceStatusGranted
}

// parseDateTime parses a date-time string in the format used by ETSI trust lists.
// It tries RFC 3339 first, then falls back to the format without timezone offset.
func parseDateTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, fmt.Errorf("empty date-time string")
	}
	// Try RFC 3339 (e.g. "2023-01-15T00:00:00Z")
	t, err := time.Parse(time.RFC3339, s)
	if err == nil {
		return t, nil
	}
	// Try ISO 8601 without timezone (e.g. "2023-01-15T00:00:00")
	t, err = time.Parse("2006-01-02T15:04:05", s)
	if err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("failed to parse date-time %q: %w", s, err)
}
