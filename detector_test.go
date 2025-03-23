package cmsdetector

import (
	"encoding/asn1"
	"encoding/hex"
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

// TestDetect tests the Detect function with different CMS types
func TestDetect(t *testing.T) {
	tests := []struct {
		name           string
		oid            asn1.ObjectIdentifier
		expectedType   string
		expectedResult bool
	}{
		{
			name:           "PKCS#7 Data",
			oid:            PKCS7DataOID,
			expectedType:   "PKCS#7 Data",
			expectedResult: true,
		},
		{
			name:           "PKCS#7 Signed Data",
			oid:            PKCS7SignedDataOID,
			expectedType:   "PKCS#7 Signed Data",
			expectedResult: true,
		},
		{
			name:           "PKCS#7 Enveloped Data",
			oid:            PKCS7EnvelopedDataOID,
			expectedType:   "PKCS#7 Enveloped Data",
			expectedResult: true,
		},
		{
			name:           "PKCS#7 Signed And Enveloped Data",
			oid:            PKCS7SignedAndEnvelopedOID,
			expectedType:   "PKCS#7 Signed And Enveloped Data",
			expectedResult: true,
		},
		{
			name:           "PKCS#7 Digested Data",
			oid:            PKCS7DigestedDataOID,
			expectedType:   "PKCS#7 Digested Data",
			expectedResult: true,
		},
		{
			name:           "PKCS#7 Encrypted Data",
			oid:            PKCS7EncryptedDataOID,
			expectedType:   "PKCS#7 Encrypted Data",
			expectedResult: true,
		},
		{
			name:           "PKCS#12",
			oid:            PKCS12OID,
			expectedType:   "PKCS#12",
			expectedResult: true,
		},
		{
			name:           "Unknown OID",
			oid:            asn1.ObjectIdentifier{1, 2, 3, 4, 5},
			expectedType:   "Unknown OID: 1.2.3.4.5",
			expectedResult: false,
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
}

// TestRealWorldSample tests with a hexadecimal representation of a real-world sample
func TestRealWorldSample(t *testing.T) {
	// This is a simplified example of a PKCS#7 SignedData structure
	// In a real test, this would be a complete PKCS#7 SignedData sample
	hexData := "308006092a864886f70d010702a080" // Simplified PKCS#7 SignedData header

	data, err := hex.DecodeString(hexData)
	if err != nil {
		t.Fatalf("Failed to decode hex: %v", err)
	}

	// Just testing that we don't panic - the sample is too simplified to actually detect
	_, err = Detect(data)
	if err == nil {
		// This would normally pass with a complete real-world sample
		// Here we expect an error since our sample is too simplified
		t.Log("Note: With a complete sample, this shouldn't error")
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
