package cmsdetector

import (
	"encoding/asn1"
	"testing"
)

// createTestData creates ASN.1 encoded ContentInfo structure with the given OID
func createTestData(t *testing.T, oid asn1.ObjectIdentifier) []byte {
	contentInfo := ContentInfo{
		ContentType: oid,
		Content: asn1.RawValue{
			Class:      2, // CONTEXT-SPECIFIC
			Tag:        0,
			IsCompound: true,
			Bytes:      []byte{0x04, 0x02, 0xDE, 0xAD}, // Some sample data
		},
	}

	data, err := asn1.Marshal(contentInfo)
	if err != nil {
		t.Fatalf("Failed to marshal test data: %v", err)
	}

	return data
}

// createMockPKCS12Key creates a mock encrypted PKCS#12 key for testing
func createMockPKCS12Key(t *testing.T) []byte {
	// Basic PKCS#12 header with version 3
	header := []byte{
		0x30, 0x82, 0x01, 0x00, // SEQUENCE tag with length
		0x02, 0x01, 0x03, // INTEGER 3 (version)
		0x30, 0x82, 0x00, 0x50, // SEQUENCE for AuthSafe
	}

	// Add some mock content
	content := []byte{
		// Add padding to satisfy the minimum size check
		0x04, 0x20, // OCTET STRING with 32 bytes of data
	}
	// Add 32 bytes of padding
	for i := 0; i < 32; i++ {
		content = append(content, byte(i))
	}

	// Add a "KEY" marker
	content = append(content, []byte("KEY")...)

	// Combine all parts
	result := append(header, content...)
	return result
}

// TestDetect tests the Detect function with different CMS types
func TestDetect(t *testing.T) {
	tests := []struct {
		name         string
		oid          asn1.ObjectIdentifier
		expectedType string
	}{
		{
			name:         "PKCS#7 Data",
			oid:          PKCS7DataOID,
			expectedType: "PKCS#7 Data",
		},
		{
			name:         "PKCS#7 Signed Data",
			oid:          PKCS7SignedDataOID,
			expectedType: "PKCS#7 Signed Data",
		},
		{
			name:         "PKCS#7 Enveloped Data",
			oid:          PKCS7EnvelopedDataOID,
			expectedType: "PKCS#7 Enveloped Data",
		},
		{
			name:         "PKCS#7 Signed And Enveloped Data",
			oid:          PKCS7SignedAndEnvelopedOID,
			expectedType: "PKCS#7 Signed And Enveloped Data",
		},
		{
			name:         "PKCS#7 Digested Data",
			oid:          PKCS7DigestedDataOID,
			expectedType: "PKCS#7 Digested Data",
		},
		{
			name:         "PKCS#7 Encrypted Data",
			oid:          PKCS7EncryptedDataOID,
			expectedType: "PKCS#7 Encrypted Data",
		},
		{
			name:         "PKCS#12",
			oid:          PKCS12OID,
			expectedType: "PKCS#12",
		},
		{
			name:         "Unknown OID",
			oid:          asn1.ObjectIdentifier{1, 2, 3, 4, 5},
			expectedType: "Unknown OID: 1.2.3.4.5",
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				data := createTestData(t, tt.oid)
				result, err := Detect(data)

				if err != nil {
					t.Fatalf("Detect returned an error: %v", err)
				}

				if result.Type != tt.expectedType {
					t.Errorf("Expected type %s, got %s", tt.expectedType, result.Type)
				}

				if !result.ContentType.Equal(tt.oid) {
					t.Errorf(
						"Expected OID %s, got %s",
						tt.oid.String(),
						result.ContentType.String(),
					)
				}
			},
		)
	}
}

// TestEncryptedPKCS12Detection tests detection of encrypted PKCS#12 containers
func TestEncryptedPKCS12Detection(t *testing.T) {
	// Create a mock encrypted PKCS#12 container
	mockP12 := createMockPKCS12Key(t)

	// Test detection
	result, err := Detect(mockP12)
	if err != nil {
		t.Fatalf("Detect returned an error for encrypted PKCS#12: %v", err)
	}

	// Check if it's detected as encrypted PKCS#12
	if result.Type != TypeEncryptedPKCS12 {
		t.Errorf("Expected type %s, got %s", TypeEncryptedPKCS12, result.Type)
	}

	if !result.IsEncrypted {
		t.Errorf("Expected IsEncrypted to be true")
	}

	// Check if IsPKCS12 correctly identifies it
	if !IsPKCS12(mockP12) {
		t.Errorf("IsPKCS12 failed to detect encrypted PKCS#12")
	}

	// Check if IsUserKeyPKCS12 correctly identifies it
	if !IsUserKeyPKCS12(mockP12) {
		t.Errorf("IsUserKeyPKCS12 failed to detect encrypted PKCS#12")
	}
}

// TestSpecificFormatDetection tests the specific format detection functions
func TestSpecificFormatDetection(t *testing.T) {
	tests := []struct {
		name     string
		oid      asn1.ObjectIdentifier
		testFunc func([]byte) bool
		expected bool
	}{
		{
			name:     "IsPKCS7Data with PKCS7DataOID",
			oid:      PKCS7DataOID,
			testFunc: IsPKCS7Data,
			expected: true,
		},
		{
			name:     "IsPKCS7Data with PKCS7SignedDataOID",
			oid:      PKCS7SignedDataOID,
			testFunc: IsPKCS7Data,
			expected: false,
		},
		{
			name:     "IsPKCS7SignedData with PKCS7SignedDataOID",
			oid:      PKCS7SignedDataOID,
			testFunc: IsPKCS7SignedData,
			expected: true,
		},
		{
			name:     "IsPKCS7SignedData with PKCS7DataOID",
			oid:      PKCS7DataOID,
			testFunc: IsPKCS7SignedData,
			expected: false,
		},
		{
			name:     "IsPKCS7EnvelopedData with PKCS7EnvelopedDataOID",
			oid:      PKCS7EnvelopedDataOID,
			testFunc: IsPKCS7EnvelopedData,
			expected: true,
		},
		{
			name:     "IsPKCS7EnvelopedData with PKCS7DataOID",
			oid:      PKCS7DataOID,
			testFunc: IsPKCS7EnvelopedData,
			expected: false,
		},
		{
			name:     "IsPKCS12 with PKCS12OID",
			oid:      PKCS12OID,
			testFunc: IsPKCS12,
			expected: true,
		},
		{
			name:     "IsPKCS12 with PKCS7DataOID",
			oid:      PKCS7DataOID,
			testFunc: IsPKCS12,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				data := createTestData(t, tt.oid)
				result := tt.testFunc(data)

				if result != tt.expected {
					t.Errorf("Expected %v, got %v", tt.expected, result)
				}
			},
		)
	}
}

// TestInvalidData tests behavior with invalid ASN.1 data
func TestInvalidData(t *testing.T) {
	invalidData := []byte{0x01, 0x02, 0x03} // Invalid ASN.1 data

	// Test Detect with invalid data
	_, err := Detect(invalidData)
	if err == nil {
		t.Error("Expected error for invalid data, got nil")
	}

	// Test specific functions with invalid data
	if IsPKCS7Data(invalidData) {
		t.Error("IsPKCS7Data should return false for invalid data")
	}

	if IsPKCS7SignedData(invalidData) {
		t.Error("IsPKCS7SignedData should return false for invalid data")
	}

	if IsPKCS7EnvelopedData(invalidData) {
		t.Error("IsPKCS7EnvelopedData should return false for invalid data")
	}

	if IsPKCS12(invalidData) {
		t.Error("IsPKCS12 should return false for invalid data")
	}

	if IsUserKeyPKCS12(invalidData) {
		t.Error("IsUserKeyPKCS12 should return false for invalid data")
	}
}

// TestGetOIDDescription tests the GetOIDDescription function
func TestGetOIDDescription(t *testing.T) {
	tests := []struct {
		name        string
		oid         asn1.ObjectIdentifier
		expectedStr string
	}{
		{
			name:        "PKCS7DataOID",
			oid:         PKCS7DataOID,
			expectedStr: "PKCS#7 Data",
		},
		{
			name:        "PKCS7SignedDataOID",
			oid:         PKCS7SignedDataOID,
			expectedStr: "PKCS#7 Signed Data",
		},
		{
			name:        "Unknown OID",
			oid:         asn1.ObjectIdentifier{1, 2, 3, 4, 5},
			expectedStr: "Unknown OID: 1.2.3.4.5",
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				result := GetOIDDescription(tt.oid)
				if result != tt.expectedStr {
					t.Errorf("Expected %s, got %s", tt.expectedStr, result)
				}
			},
		)
	}
}
