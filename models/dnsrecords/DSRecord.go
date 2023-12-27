package dnsrecords

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// DSRecord represents a single DNSSEC Delegation Signer (DS) record.
// A DS record is used in DNSSEC to link a child zone to a parent zone,
// enabling the validation of DNSSEC-signed records in the child zone.
//
// Fields:
//
//	KeyTag: A 16-bit identifier of the DNSKEY record in the child zone
//	        that is used to sign the zone's DNS records. It is used to efficiently
//	        locate the correct DNSKEY record in the child zone.
//
//	Algorithm: An 8-bit integer identifying the cryptographic algorithm
//	           used to create the signature in the DNSKEY record. The value corresponds
//	           to IANA DNSSEC Algorithm Identifiers.
//
//	DigestType: An 8-bit integer representing the type of digest
//	            that is used to create a hash of the DNSKEY record. The value
//	            corresponds to IANA DS Record Digest Types.
//
//	Digest: A string representing the hexadecimal value of the digest
//	        (hash) of the DNSKEY record. The digest is calculated using the method
//	        specified in the DigestType field.
type DSRecord struct {
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     string
}

// DSResponse represents a complete response for a DNSSEC DS record query.
// This includes potentially multiple DS records, a flag indicating whether
// the response was validated, the RRSIG record for the response, and the
// raw response received from the DNS server.
//
// Fields:
//
//	Records: A slice of DSRecord, each representing an individual
//	         Delegation Signer record. Multiple DS records may be included to
//	         support different algorithms or keys.
//
//	Validated: A boolean flag indicating whether the DS records
//	           in the response have been validated using DNSSEC validation procedures.
//
//	RRSIG: A pointer to an RRSIGRecord, which contains the DNSSEC
//	       signature for this DS record set. This field may be nil if the
//	       response does not include a signature or if DNSSEC is not enabled.
//
//	RawResponse: A string containing the raw textual response received
//	             from the DNS server. It may be used for logging, debugging, or
//	             other diagnostic purposes.
type DSResponse struct {
	Records     []DSRecord
	Validated   bool
	RRSIG       *RRSIGRecord
	RawResponse string
}

// NewDSRecord creates a new DSResponse struct from a raw DNS response string.
// A DSResponse struct is populated with the parsed information from the DNS response,
// typically obtained from a DNSSEC DS record query using the 'delv' command-line tool.
//
// Parameters:
//
//	response: A string containing the raw textual response from the 'delv' command-line tool.
//	          This response should be the result of a query for DS records for a specific domain.
//	          The response string is expected to include one or more DS records, along with
//	          any associated RRSIG records and other relevant DNSSEC information.
//
// Return Value:
//
//	*DSResponse: A pointer to a DSResponse struct that contains the parsed DS records,
//	             validation status, associated RRSIG record (if available), and the raw response.
//	             This struct provides a structured representation of the DNSSEC DS records
//	             and associated data.
//
//	error: An error object that indicates any issues encountered during the parsing of the
//	       response string. If the parsing is successful, the error is nil. If parsing fails,
//	       the error provides details about the cause of the failure.
//
// Example Usage:
//
//	dsResponse, err := NewDSRecord(rawDelvResponse)
//	if err != nil {
//	    // Handle error
//	}
//	// Use dsResponse for DNSSEC validation or other purposes
//
// Note:
//
//	This function is designed to parse the output of the 'delv' command-line tool,
//	which is used for DNSSEC troubleshooting and diagnostics. The function assumes
//	that the input string is in the format provided by 'delv', and it may not work
//	correctly with responses from other tools or in different formats.
func NewDSRecord(response string) (*DSResponse, error) {
	lines := strings.Split(response, "\n")
	if strings.Contains(response, "resolution failed") {
		return nil, fmt.Errorf("resolution failed: %s", lines[0])
	}
	record := &DSResponse{}
	record.RawResponse = response
	dsRegex := regexp.MustCompile(`\bIN\s+DS\b`)
	rrsigRegex := regexp.MustCompile(`\bRRSIG\s+DS\b`)

	for _, line := range lines {
		if strings.HasPrefix(line, "; fully validated") {
			record.Validated = true
		} else if strings.HasPrefix(line, "; unsigned answer") {
			record.Validated = false
		} else if dsRegex.MatchString(line) {
			dsRecord := &DSRecord{}
			parts := strings.Fields(line)
			if len(parts) < 8 {
				return nil, fmt.Errorf("invalid DS record format: %s", line)
			}

			keyTag, err := strconv.ParseUint(parts[4], 10, 16)
			if err != nil {
				return nil, fmt.Errorf("invalid key tag '%s' in DS record: %v", parts[4], err)
			}
			dsRecord.KeyTag = uint16(keyTag)

			algorithm, err := strconv.ParseUint(parts[5], 10, 8)
			if err != nil {
				return nil, fmt.Errorf("invalid algorithm '%s' in DS record: %v", parts[5], err)
			}
			dsRecord.Algorithm = uint8(algorithm)

			digestType, err := strconv.ParseUint(parts[6], 10, 8)
			if err != nil {
				return nil, fmt.Errorf("invalid digest type '%s' in DS record: %v", parts[6], err)
			}
			dsRecord.DigestType = uint8(digestType)

			dsRecord.Digest = strings.Join(parts[7:], "")

			record.Records = append(record.Records, *dsRecord)
		} else if rrsigRegex.MatchString(line) {
			rrsigRecord, err := NewRRSIGRecord(line)
			if err != nil {
				return nil, err
			}
			record.RRSIG = rrsigRecord
		}
	}
	return record, nil
}
