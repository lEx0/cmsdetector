// Package cmsdetector provides functions for detecting and identifying various
// CMS (Cryptographic Message Syntax) and PKCS (Public Key Cryptography Standards) formats.
package cmsdetector

import (
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

	// Other common OIDs for CMS/PKCS can be added here
	PKCS12OID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1}
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
}

// Detect tries to determine the type of CMS/PKCS data
func Detect(data []byte) (DetectionResult, error) {
	var contentInfo ContentInfo

	_, err := asn1.Unmarshal(data, &contentInfo)
	if err != nil {
		return DetectionResult{}, fmt.Errorf("failed to parse ASN.1 structure: %w", err)
	}

	result := DetectionResult{
		ContentType: contentInfo.ContentType,
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

// IsPKCS12 checks if the data is a PKCS#12 container
func IsPKCS12(data []byte) bool {
	// For PKCS#12, a more complex check may be needed,
	// as a simple OID check may not be sufficient.
	// This is a simplified implementation.
	result, err := Detect(data)

	if err != nil {
		return false
	}

	return result.ContentType.Equal(PKCS12OID)
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
