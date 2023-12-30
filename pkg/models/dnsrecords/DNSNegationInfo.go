package dnsrecords

// RawResponseDNSNegationInfo represents the raw textual data of DNSSEC denial-of-existence records.
// This struct is typically used to store the raw output of DNS negation records, such as NSEC and NSEC3PARAM,
// as provided by the 'delv' command-line tool or similar DNS diagnostic tools.
//
// Fields:
//
//	NSEC: A string representing the raw textual output of an NSEC (Next SECure) record.
//	      NSEC records are used in DNSSEC to provide authenticated denial of existence for DNS records.
//
//	NSEC3Param: A string representing the raw textual output of an NSEC3PARAM (NSEC3 Parameters) record.
//	            NSEC3PARAM records specify the parameters for NSEC3, an enhanced version of NSEC that
//	            prevents zone enumeration while providing authenticated denial of existence.
type RawResponseDNSNegationInfo struct {
	NSEC       string
	NSEC3Param string
}

// DNSNegationInfo represents structured information about DNSSEC denial-of-existence records.
// This struct encapsulates the parsed details of NSEC and NSEC3PARAM records, which are used in DNSSEC
// to provide authenticated denial of existence for DNS records. It also includes the raw response
// for these records, allowing for further analysis or diagnostics.
//
// Fields:
//
//	NSEC: A pointer to an NSECRecord struct, representing the parsed details of an NSEC record.
//	      NSEC records indicate which domain names do not exist in a zone and the types of records
//	      available for a given domain name. This field may be nil if no NSEC record is present.
//
//	NSEC3Param: A pointer to an NSEC3PARAMRecord struct, representing the parsed details of an NSEC3PARAM record.
//	            NSEC3PARAM records define the parameters for NSEC3, enhancing DNSSEC's ability to provide
//	            authenticated denial of existence. This field may be nil if no NSEC3PARAM record is present.
//
//	RawResponse: A pointer to a RawResponseDNSNegationInfo struct, containing the raw textual responses
//	             of NSEC and NSEC3PARAM records. Useful for logging, debugging, or other diagnostic purposes.
type DNSNegationInfo struct {
	NSEC        *NSECRecord
	NSEC3Param  *NSEC3PARAMRecord
	RawResponse *RawResponseDNSNegationInfo
}

// NewDNSNegationInfo parses raw DNS response strings for NSEC and NSEC3PARAM records and creates a new DNSNegationInfo struct.
// This function is designed to work with the output of the 'delv' command-line tool for queries related to DNSSEC denial-of-existence.
// It processes the responses for both NSEC and NSEC3PARAM records to provide a comprehensive view of the DNSSEC negation information.
//
// Parameters:
//
//	responseNSEC: A string containing the raw textual response from the 'delv' command-line tool for an NSEC query.
//	              This response typically includes the NSEC record, which provides authenticated denial of existence for DNS records.
//
//	responseNSEC3Param: A string containing the raw textual response from the 'delv' command-line tool for an NSEC3PARAM query.
//	                    This response includes the NSEC3PARAM record, which specifies parameters for the NSEC3 protocol in DNSSEC.
//
// Return Value:
//
//	*DNSNegationInfo: A pointer to a DNSNegationInfo struct that contains the parsed details of NSEC and NSEC3PARAM records,
//	                  along with the raw responses. This struct provides a structured representation of DNSSEC denial-of-existence information.
//
//	error: An error object that indicates any issues encountered during the parsing of the response strings.
//	       If both parsing operations are successful, the error is nil. If parsing of either record type fails,
//	       the error provides details about the cause of the failure. In case of an error, the respective record field in DNSNegationInfo
//	       will be set to nil.
//
// Example Usage:
//
//	dnsNegationInfo, err := NewDNSNegationInfo(rawNSECResponse, rawNSEC3ParamResponse)
//	if err != nil {
//	    // Handle error
//	}
//	// Use dnsNegationInfo for DNSSEC analysis or other purposes
//
// Note:
//
//	This function is specifically designed to handle the output of the 'delv' command-line tool for DNSSEC-related queries,
//	particularly NSEC and NSEC3PARAM records. It expects the input strings to be in the format provided by 'delv' and may not work
//	correctly with responses from other tools or in different formats.
func NewDNSNegationInfo(responseNSEC string, responseNSEC3Param string) (*DNSNegationInfo, error) {
	dnsNegationInfo := &DNSNegationInfo{}
	dnsNegationInfo.RawResponse.NSEC = responseNSEC
	dnsNegationInfo.RawResponse.NSEC3Param = responseNSEC3Param

	r := &NSECRecord{}
	result, err := r.Parse(responseNSEC)
	nsecRecord, ok := result.(*NSECRecord)
	if !ok {
		return nil, err
	}
	if err != nil {
		dnsNegationInfo.NSEC = nil
	} else {
		dnsNegationInfo.NSEC = nsecRecord
	}

	rr := &NSEC3PARAMRecord{}
	result, err = rr.Parse(responseNSEC3Param)
	nsec3paramRecord, ok := result.(*NSEC3PARAMRecord)
	if !ok {
		return nil, err
	}
	if err != nil {
		dnsNegationInfo.NSEC3Param = nil
	} else {
		dnsNegationInfo.NSEC3Param = nsec3paramRecord
	}

	return dnsNegationInfo, nil
}
