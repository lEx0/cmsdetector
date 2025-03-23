package cmsdetector_test

import (
	"fmt"
	"os"

	"github.com/lEx0/cmsdetector"
)

// This file contains examples that demonstrate how to use the cmsdetector package.
// These examples can be run with `go test -v github.com/lEx0/cmsdetector -run Example`

// ExampleDetect demonstrates the basic usage of the Detect function
func Example_detect() {
	// In a real application, this would be data from a file
	// Here we'll just use a placeholder to demonstrate the API
	data := []byte("This would be binary CMS data")

	// Try to detect the CMS/PKCS format
	result, err := cmsdetector.Detect(data)
	if err != nil {
		fmt.Printf("Error detecting format: %v\n", err)
		return
	}

	// Use the detection results
	fmt.Printf("Detected format: %s\n", result.Type)
	fmt.Printf("Content type OID: %s\n", result.ContentType.String())

	// Output:
	// Error detecting format: failed to parse ASN.1 structure: asn1: structure error: tags don't match (16 vs {class:1 tag:20 length:104 isCompound:false}) {optional:false explicit:false application:false private:false defaultValue:<nil> tag:<nil> stringType:0 timeType:0 set:false omitEmpty:false} ContentInfo @2
}

// ExampleFileDetection demonstrates how to detect the format of a file
func Example_fileDetection() {
	// Skip this example when running tests
	if os.Getenv("SKIP_FILE_EXAMPLES") != "" {
		fmt.Println("Skipping file example")
		return
	}

	// The path to your CMS/PKCS file
	filePath := "тест.jpg.cms"
	// filePath := "тест.pdf"

	// Read the file
	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		return
	}

	// Detect the format
	result, err := cmsdetector.Detect(data)
	if err != nil {
		fmt.Printf("Error detecting format: %v\n", err)
		return
	}

	// Process based on the detected format
	switch {
	case cmsdetector.IsPKCS7SignedData(data):
		fmt.Println("This is a signed PKCS#7 file")
	case cmsdetector.IsPKCS7EnvelopedData(data):
		fmt.Println("This is an enveloped PKCS#7 file")
	case cmsdetector.IsPKCS12(data):
		fmt.Println("This is a PKCS#12 certificate store")
	default:
		fmt.Printf("This is a %s file\n", result.Type)
	}

	// Output:
	// Error reading file: open тест.jpg.cms: no such file or directory
}

// ExampleUsingHelperFunctions demonstrates how to use the helper functions
func Example_usingHelperFunctions() {
	// In a real application, this would be data from a file
	// Here we'll just use a placeholder to demonstrate the API
	data := []byte("This would be binary CMS data")

	// Use the specific format detection functions
	if cmsdetector.IsPKCS7SignedData(data) {
		fmt.Println("This contains PKCS#7 signed data")
	} else {
		fmt.Println("This is not PKCS#7 signed data")
	}

	if cmsdetector.IsPKCS7EnvelopedData(data) {
		fmt.Println("This contains PKCS#7 enveloped data")
	} else {
		fmt.Println("This is not PKCS#7 enveloped data")
	}

	if cmsdetector.IsPKCS12(data) {
		fmt.Println("This is a PKCS#12 container")
	} else {
		fmt.Println("This is not a PKCS#12 container")
	}

	// Output:
	// This is not PKCS#7 signed data
	// This is not PKCS#7 enveloped data
	// This is not a PKCS#12 container
}
