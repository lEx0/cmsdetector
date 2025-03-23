package cmsdetector

import (
	"testing"
)

func TestIsUserKeyPKCS12(t *testing.T) {
	// Create a mock PKCS#12 file content with more accurate ASN.1 structure
	mockP12 := []byte{
		0x30, 0x82, 0x01, 0x00, // SEQUENCE tag with length
		0x02, 0x01, 0x03, // INTEGER 3 (version)
		0x30, 0x82, 0x00, 0x50, // SEQUENCE for AuthSafe
		// Add at least 10 more bytes to satisfy the minimum size check
		0x04, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		// Some mock content including GOST reference
		0x47, 0x4F, 0x53, 0x54, // "GOST" string
		// More mock data
		0x4B, 0x45, 0x59, // "KEY" string
	}

	// Test with mock PKCS#12 data
	result := IsUserKeyPKCS12(mockP12)
	if !result {
		t.Error("IsUserKeyPKCS12 returned false for mock key data")
	}

	// Test with invalid data (too short)
	invalidData := []byte{0x30, 0x03}
	result = IsUserKeyPKCS12(invalidData)
	if result {
		t.Error("IsUserKeyPKCS12 returned true for invalid data")
	}

	// Test with non-PKCS#12 data
	nonP12Data := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}
	result = IsUserKeyPKCS12(nonP12Data)
	if result {
		t.Error("IsUserKeyPKCS12 returned true for non-PKCS#12 data")
	}
}

func TestIsNCAKeyPKCS12(t *testing.T) {
	// Create a mock NCA PKCS#12 file content with more accurate structure
	mockNCAP12 := []byte{
		0x30, 0x82, 0x01, 0x00, // SEQUENCE tag with length
		0x02, 0x01, 0x03, // INTEGER 3 (version)
		0x30, 0x82, 0x00, 0x50, // SEQUENCE for AuthSafe
		// Add at least 10 more bytes to satisfy the minimum size check
		0x04, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		// Some mock content including GOST reference
		0x47, 0x4F, 0x53, 0x54, // "GOST" string
		// KalkanCrypt reference
		0x4B, 0x61, 0x6C, 0x6B, 0x61, 0x6E, // "Kalkan" string
		// More mock data
		0x4B, 0x45, 0x59, // "KEY" string
	}

	// Test with mock NCA PKCS#12 data
	result := IsNCAKeyPKCS12(mockNCAP12)
	if !result {
		t.Error("IsNCAKeyPKCS12 returned false for mock NCA key data")
	}

	// Test with generic PKCS#12 data (no NCA/Kalkan indicators)
	genericP12 := []byte{
		0x30, 0x82, 0x01, 0x00, // SEQUENCE tag with length
		0x02, 0x01, 0x03, // INTEGER 3 (version)
		0x30, 0x82, 0x00, 0x50, // SEQUENCE for AuthSafe
		// Add at least 10 more bytes to satisfy the minimum size check
		0x04, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		// Just some generic content
		0x04, 0x02, 0xDE, 0xAD, // OCTET STRING with some data
		// "KEY" string but no GOST or Kalkan references
		0x4B, 0x45, 0x59,
	}

	// A generic PKCS#12 might be detected as a key, but not as an NCA key
	if IsUserKeyPKCS12(genericP12) && IsNCAKeyPKCS12(genericP12) {
		t.Error("IsNCAKeyPKCS12 incorrectly identified generic PKCS#12 as NCA key")
	}
}
