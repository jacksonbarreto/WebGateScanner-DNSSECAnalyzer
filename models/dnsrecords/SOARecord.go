package dnsrecords

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// SOARecord represents a DNS Start of Authority (SOA) record.
// It contains metadata about the DNS zone, including information about the zone's primary name server,
// the administrator's contact email, and various timing parameters. The structure also holds
// information about the validation status of the record and any associated DNSSEC RRSIG record.
//
// Fields:
//
//	PrimaryNS: The primary name server for the DNS zone. This is typically the authoritative name server
//	           that contains the original zone records.
//	Contact: The email address of the administrative contact for the DNS zone.
//	Serial: The serial number of the SOA record, which is used by secondary name servers to check if
//	        their data is up-to-date. Incremented each time the zone data is changed.
//	Refresh: The time interval (in seconds) before the zone should be refreshed.
//	Retry: The time interval (in seconds) that should elapse before a failed refresh should be retried.
//	Expire: The time interval (in seconds) that specifies the upper limit on the time interval that can
//	        elapse before the zone is no longer authoritative.
//	Minimum: The minimum TTL (time-to-live) field that should be exported with any resource record from
//	         this zone.
//	Validated: Indicates whether the SOA record has been validated by DNSSEC. True if the record has been
//	           validated, false otherwise.
//	RRSIG: Pointer to an RRSIGRecord struct, which contains the DNSSEC signature for this SOA record.
//	       This field is nil if DNSSEC is not used or if the record is not signed.
//	RawResponse: The raw text of the DNS response containing the SOA record.
type SOARecord struct {
	PrimaryNS   string
	Contact     string
	Serial      uint32
	Refresh     uint32
	Retry       uint32
	Expire      uint32
	Minimum     uint32
	Validated   bool
	RRSIG       *RRSIGRecord
	RawResponse string
}

func NewSOARecord(response string) (*SOARecord, error) {
	lines := strings.Split(response, "\n")
	if strings.Contains(response, "resolution failed") {
		return nil, fmt.Errorf("resolution failed: %s", lines[0])
	}
	record := &SOARecord{}
	record.RawResponse = response
	soaRegex := regexp.MustCompile(`\bIN\s+SOA\b`)
	rrsigRegex := regexp.MustCompile(`\bRRSIG\s+SOA\b`)

	for _, line := range lines {
		if strings.HasPrefix(line, "; fully validated") {
			record.Validated = true
		} else if strings.HasPrefix(line, "; unsigned answer") {
			record.Validated = false
		} else if soaRegex.MatchString(line) {
			parts := strings.Fields(line)
			if len(parts) < 11 {
				return nil, errors.New("invalid SOA record format")
			}

			record.PrimaryNS = strings.TrimSuffix(parts[4], ".")

			contact := strings.TrimSuffix(parts[5], ".")
			firstDotIndex := strings.Index(contact, ".")
			if firstDotIndex != -1 {
				contact = contact[:firstDotIndex] + "@" + contact[firstDotIndex+1:]
			}
			record.Contact = contact

			serial, err := strconv.ParseUint(parts[6], 10, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid serial number '%s' in SOA record: %v", parts[6], err)
			}
			record.Serial = uint32(serial)

			refresh, err := strconv.ParseUint(parts[7], 10, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid refresh time '%s' in SOA record: %v", parts[7], err)
			}
			record.Refresh = uint32(refresh)

			retry, err := strconv.ParseUint(parts[8], 10, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid retry time '%s' in SOA record: %v", parts[8], err)
			}
			record.Retry = uint32(retry)

			expire, err := strconv.ParseUint(parts[9], 10, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid expire time '%s' in SOA record: %v", parts[9], err)
			}
			record.Expire = uint32(expire)

			minimum, err := strconv.ParseUint(parts[10], 10, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid minimum time '%s' in SOA record: %v", parts[10], err)
			}
			record.Minimum = uint32(minimum)
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