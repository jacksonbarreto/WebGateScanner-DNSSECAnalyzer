package dnsrecords

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// RRSIGRecord represents a DNSSEC Resource Record Signature (RRSIG). It includes metadata
// about the digital signature used to secure a specific set of DNS records (RRset).
// Fields:
// TypeCovered: Type of the RRset that this RRSIG record covers (e.g., SOA, DS, DNSKEY).
// Algorithm: Numerical identifier of the cryptographic algorithm used for the signature, as per RFC 4034.
// Labels: Number of labels in the original RRSIG RR owner name.
// OriginalTTL: Original TTL of the covered RRset, as it appears in the authoritative zone.
// Expiration: Expiration date of the signature, represented as a UNIX timestamp.
// Inception: Inception date of the signature, also as a UNIX timestamp.
// KeyTag: Identifier of the DNSKEY record that validates this signature.
// SignerName: Domain name of the signer (entity that generated the signature).
// Signature: Actual digital signature in base64 encoding.
type RRSIGRecord struct {
	TypeCovered string
	Algorithm   uint8
	Labels      uint8
	OriginalTTL uint32
	Expiration  uint32
	Inception   uint32
	KeyTag      uint16
	SignerName  string
	Signature   string
}

func NewRRSIGRecord(rrsigLine string) (*RRSIGRecord, error) {
	parts := strings.Fields(rrsigLine)
	if len(parts) < 13 {
		return nil, errors.New("invalid RRSIG record format")
	}

	algorithm, err := strconv.ParseUint(parts[5], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("invalid algorithm value '%s' in RRSIG record: %v", parts[5], err)
	}

	labels, err := strconv.ParseUint(parts[6], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("invalid labels value '%s' in RRSIG record: %v", parts[6], err)
	}

	originalTTL, err := strconv.ParseUint(parts[7], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid original TTL value '%s' in RRSIG record: %v", parts[7], err)
	}

	expiration, err := parseTime(parts[8])
	if err != nil {
		return nil, fmt.Errorf("invalid expiration time value '%s' in RRSIG record: %v", parts[8], err)
	}

	inception, err := parseTime(parts[9])
	if err != nil {
		return nil, fmt.Errorf("invalid inception time value '%s' in RRSIG record: %v", parts[9], err)
	}

	keyTag, err := strconv.ParseUint(parts[10], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid key tag value '%s' in RRSIG record: %v", parts[10], err)
	}

	signerName := strings.TrimSuffix(parts[11], ".")
	signature := strings.Join(parts[12:], "")

	return &RRSIGRecord{
		TypeCovered: parts[4],
		Algorithm:   uint8(algorithm),
		Labels:      uint8(labels),
		OriginalTTL: uint32(originalTTL),
		Expiration:  uint32(expiration),
		Inception:   uint32(inception),
		KeyTag:      uint16(keyTag),
		SignerName:  signerName,
		Signature:   signature,
	}, nil
}

// DateFormat follows the Go standard layout for time parsing (YearMonthDayHourMinuteSecond), which uses the reference date: Mon Jan 2 15:04:05 MST 2006.
const DateFormat = "20060102150405"

func parseTime(timeStr string) (int64, error) {
	t, err := time.Parse(DateFormat, timeStr)
	if err != nil {
		return 0, err
	}
	return t.Unix(), nil
}
