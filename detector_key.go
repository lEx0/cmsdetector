package cmsdetector

import (
	"bytes"
)

// IsUserKeyPKCS12 checks if the data appears to be a user PKCS#12 key container
// This function works for encrypted PKCS#12 files like those from NCA systems
// without requiring decryption or password
func IsUserKeyPKCS12(data []byte) bool {
	// Basic checks for PKCS#12 format
	if len(data) < 8 {
		return false
	}

	// Check basic PKCS#12 signature - should start with SEQUENCE tag (0x30)
	if data[0] != 0x30 {
		return false
	}

	// Try the standard detection first
	result, err := Detect(data)
	if err == nil && result.ContentType.Equal(PKCS12OID) {
		return true
	}

	// For encrypted PKCS#12, the standard detection might fail
	// Look for version 3 indicator which is common in PKCS#12
	versionFound := false
	versionBytes := []byte{0x02, 0x01, 0x03} // INTEGER 3

	// Try to find the version pattern
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

	// Size check - user key files are typically within a certain range
	if len(data) < 20 || len(data) > 100000 {
		return false
	}

	// Look for GOST signatures (common in NCA/KalkanCrypt keys)
	if bytes.Contains(data, []byte("GOST")) ||
		bytes.Contains(data, []byte("ГОСТ")) ||
		bytes.Contains(data, []byte("gost")) {
		return true
	}

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
	return versionFound
}

// IsNCAKeyPKCS12 is a specialized function to detect NCA user key containers
// based on Kazakhstan's national cryptographic provider (KalkanCrypt) specific formats
func IsNCAKeyPKCS12(data []byte) bool {
	// First check if it's a PKCS#12 key container at all
	if !IsUserKeyPKCS12(data) {
		return false
	}

	// Additional checks specific to NCA/KalkanCrypt:

	// Look for Kazakhstan's GOST indicators
	// (these strings often appear in NCA key containers)
	if bytes.Contains(data, []byte("GOST")) ||
		bytes.Contains(data, []byte("ГОСТ")) {
		return true
	}

	// Check for KalkanCrypt specific patterns
	if bytes.Contains(data, []byte("Kalkan")) ||
		bytes.Contains(data, []byte("kalkan")) ||
		bytes.Contains(data, []byte("KALKAN")) ||
		bytes.Contains(data, []byte("Калкан")) {
		return true
	}

	// Check for specific Kazakhstan OIDs (in binary form)
	// This would need to be replaced with actual KZ OIDs
	// Example for demonstration purposes:
	kazakhstanSignature := []byte{0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01}

	// If specific indicators aren't found, it might still be an NCA key,
	// but we can't confirm it with high confidence
	return bytes.Contains(data, kazakhstanSignature)
}
