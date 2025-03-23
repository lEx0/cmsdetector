// Package cmsdetector provides functions for detecting and identifying various
// CMS (Cryptographic Message Syntax) and PKCS (Public Key Cryptography Standards) formats.
package cmsdetector

import (
	"bytes"
	"encoding/asn1"
	"fmt"
)

// OIDs for various types of CMS/PKCS messages
var (
	// PKCS#7 OIDs
	PKCS7DataOID               = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	PKCS7SignedDataOID         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	PKCS7EnvelopedDataOID      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	PKCS7SignedAndEnvelopedOID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 4}
	PKCS7DigestedDataOID       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 5}
	PKCS7EncryptedDataOID      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}

	// Other common OIDs for CMS/PKCS
	PKCS12OID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1}
)

// Additional type constants for formats that can't be detected via OID
const (
	TypeEncryptedPKCS12 = "Encrypted PKCS#12"
)

// ContentInfo provides the ASN.1 structure for the main CMS/PKCS container
type ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

// DetectionResult contains the result of CMS/PKCS type detection
type DetectionResult struct {
	Type        string
	ContentType asn1.ObjectIdentifier
	IsEncrypted bool // Indicates if the content is encrypted
}

// Detect tries to determine the type of CMS/PKCS data
func Detect(data []byte) (DetectionResult, error) {
	// Try standard ASN.1 parsing first
	var contentInfo ContentInfo
	_, err := asn1.Unmarshal(data, &contentInfo)

	// If standard parsing succeeds
	if err == nil {
		result := DetectionResult{
			ContentType: contentInfo.ContentType,
			IsEncrypted: false,
		}

		// Determine the type based on the OID
		switch {
		case contentInfo.ContentType.Equal(PKCS7DataOID):
			result.Type = "PKCS#7 Data"
		case contentInfo.ContentType.Equal(PKCS7SignedDataOID):
			result.Type = "PKCS#7 Signed Data"
		case contentInfo.ContentType.Equal(PKCS7EnvelopedDataOID):
			result.Type = "PKCS#7 Enveloped Data"
		case contentInfo.ContentType.Equal(PKCS7SignedAndEnvelopedOID):
			result.Type = "PKCS#7 Signed And Enveloped Data"
		case contentInfo.ContentType.Equal(PKCS7DigestedDataOID):
			result.Type = "PKCS#7 Digested Data"
		case contentInfo.ContentType.Equal(PKCS7EncryptedDataOID):
			result.Type = "PKCS#7 Encrypted Data"
		case contentInfo.ContentType.Equal(PKCS12OID):
			result.Type = "PKCS#12"
		default:
			result.Type = fmt.Sprintf("Unknown OID: %s", contentInfo.ContentType.String())
		}

		return result, nil
	}

	// If standard parsing fails, try to detect encrypted PKCS#12 key containers
	if isEncryptedPKCS12(data) {
		result := DetectionResult{
			Type:        TypeEncryptedPKCS12,
			IsEncrypted: true,
		}

		return result, nil
	}

	// If all detection methods fail
	return DetectionResult{}, fmt.Errorf("failed to parse ASN.1 structure: %w", err)
}

// isEncryptedPKCS12 checks if the data appears to be an encrypted PKCS#12 container
func isEncryptedPKCS12(data []byte) bool {
	// Basic checks for PKCS#12 format
	if len(data) < 20 {
		return false
	}

	// Check basic PKCS#12 signature - should start with SEQUENCE tag (0x30)
	if data[0] != 0x30 {
		return false
	}

	// Look for version 3 indicator which is common in PKCS#12
	versionBytes := []byte{0x02, 0x01, 0x03} // INTEGER 3

	// Try to find the version pattern
	versionFound := false

	for i := 0; i < len(data)-len(versionBytes); i++ {
		if bytes.Equal(data[i:i+len(versionBytes)], versionBytes) {
			versionFound = true
			break
		}
	}

	if !versionFound {
		return false
	}

	// Additional checks specific for key containers

	// Look for key-related OIDs in binary form
	// 1.2.840.113549.1.12.10.1 (PKCS#12)
	pkcs12Signature := []byte{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x0A, 0x01}
	if bytes.Contains(data, pkcs12Signature) {
		return true
	}

	// Check for private key indicators
	if bytes.Contains(data, []byte("KEY")) ||
		bytes.Contains(data, []byte("PrivateKey")) {
		return true
	}

	// If we found version 3 and the file is in the right size range,
	// it's likely a PKCS#12 file even if we couldn't find specific signatures
	return versionFound && len(data) > 100 && len(data) < 100000
}

// IsPKCS7Data checks if the data is PKCS#7 data
func IsPKCS7Data(data []byte) bool {
	result, err := Detect(data)

	if err != nil {
		return false
	}

	return result.ContentType.Equal(PKCS7DataOID)
}

// IsPKCS7SignedData checks if the data is PKCS#7 signed data
func IsPKCS7SignedData(data []byte) bool {
	result, err := Detect(data)

	if err != nil {
		return false
	}

	return result.ContentType.Equal(PKCS7SignedDataOID)
}

// IsPKCS7EnvelopedData checks if the data is PKCS#7 enveloped data
func IsPKCS7EnvelopedData(data []byte) bool {
	result, err := Detect(data)

	if err != nil {
		return false
	}

	return result.ContentType.Equal(PKCS7EnvelopedDataOID)
}

// IsPKCS12 checks if the data is a PKCS#12 container (including encrypted ones)
func IsPKCS12(data []byte) bool {
	result, err := Detect(data)

	if err != nil {
		return false
	}

	// Check for both regular and encrypted PKCS#12 containers
	return result.ContentType.Equal(PKCS12OID) ||
		result.Type == TypeEncryptedPKCS12
}

// IsUserKeyPKCS12 checks if the data appears to be a user PKCS#12 key container
func IsUserKeyPKCS12(data []byte) bool {
	result, err := Detect(data)
	if err != nil {
		return false
	}

	// Check for both regular and encrypted PKCS#12 containers
	return result.ContentType.Equal(PKCS12OID) ||
		result.Type == TypeEncryptedPKCS12
}

// GetOIDDescription returns a human-readable description of the OID
func GetOIDDescription(oid asn1.ObjectIdentifier) string {
	switch {
	case oid.Equal(PKCS7DataOID):
		return "PKCS#7 Data"
	case oid.Equal(PKCS7SignedDataOID):
		return "PKCS#7 Signed Data"
	case oid.Equal(PKCS7EnvelopedDataOID):
		return "PKCS#7 Enveloped Data"
	case oid.Equal(PKCS7SignedAndEnvelopedOID):
		return "PKCS#7 Signed And Enveloped Data"
	case oid.Equal(PKCS7DigestedDataOID):
		return "PKCS#7 Digested Data"
	case oid.Equal(PKCS7EncryptedDataOID):
		return "PKCS#7 Encrypted Data"
	case oid.Equal(PKCS12OID):
		return "PKCS#12"
	default:
		return fmt.Sprintf("Unknown OID: %s", oid.String())
	}
}
