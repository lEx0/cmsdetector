# CMS Detector

A Go library for detecting and identifying various CMS (Cryptographic Message Syntax) and PKCS (Public Key Cryptography Standards) formats.

## Installation

```bash
go get github.com/lEx0/cmsdetector
```

## Features

- Detection of various PKCS#7 (CMS) structures:
  - PKCS#7 Data
  - PKCS#7 Signed Data
  - PKCS#7 Enveloped Data
  - PKCS#7 Signed And Enveloped Data
  - PKCS#7 Digested Data
  - PKCS#7 Encrypted Data
- Basic verification of PKCS#12 containers
- User key detection for PKCS#12 containers (including encrypted keys and NCA user keys)
- Extraction of CMS structure metadata
- Compatibility with KalkanCrypt (Kazakhstan's national cryptographic provider) formats and standards

## Usage Example

```go
package main

import (
	"fmt"
	"os"

	"github.com/lEx0/cmsdetector"
)

func main() {
	data, err := os.ReadFile("test.cms")
	if err != nil {
		fmt.Printf("Error reading file: %s\n", err)
		return
	}
	
	// Main method for type detection
	result, err := cmsdetector.Detect(data)
	if err != nil {
		fmt.Printf("Analysis error: %s\n", err)
		return
	}
	
	fmt.Printf("File type: %s\n", result.Type)
	fmt.Printf("Encrypted: %v\n", result.IsEncrypted)
	
	if result.ContentType != nil {
		fmt.Printf("OID: %s\n", result.ContentType.String())
	}
	
	// Check for specific type
	if cmsdetector.IsPKCS7SignedData(data) {
		fmt.Println("File contains PKCS#7 signed data")
	}
}
```

## Specialized Checks

```go
// Check for PKCS#7 SignedData
if cmsdetector.IsPKCS7SignedData(data) {
    fmt.Println("Found signed data")
}

// Check for PKCS#7 EnvelopedData
if cmsdetector.IsPKCS7EnvelopedData(data) {
    fmt.Println("Found encrypted data")
}

// Check for PKCS#12
if cmsdetector.IsPKCS12(data) {
    fmt.Println("Found PKCS#12 container")
}

// Check for user PKCS#12 key container (even encrypted)
if cmsdetector.IsUserKeyPKCS12(data) {
    fmt.Println("Found user PKCS#12 key container")
}
```

## Detecting Encrypted PKCS#12 Keys

The library includes specialized detection for encrypted PKCS#12 containers like those used for personal keys:

```go
// Read an encrypted .p12 file
data, err := os.ReadFile("GOST512_112233.p12")
if err != nil {
    fmt.Printf("Error reading file: %s\n", err)
    return
}

// Detect will now handle encrypted containers
result, err := cmsdetector.Detect(data)
if err == nil {
    fmt.Printf("Detected: %s\n", result.Type)
    
    if result.IsEncrypted {
        fmt.Println("This is an encrypted container")
    }
}
```

## Limitations

- The library only performs type detection of CMS/PKCS data, not full parsing or validation
- For PKCS#12 containers, basic structure verification is performed, but not content decryption
- The specialized key detection functions use heuristics and may not be 100% accurate for all cases

## KalkanCrypt Compatibility

This library is designed to work with files created by KalkanCrypt, the national cryptographic provider in Kazakhstan. It can detect and identify various cryptographic formats generated by KalkanCrypt, including:

- CMS/PKCS#7 signed data (digital signatures)
- PKCS#12 (.p12) key containers
- Encrypted user key containers (with from National Certification Authority of the Republic of Kazakhstan aka NCA)

This makes the library particularly useful for applications that need to interoperate with the KalkanCrypt ecosystem and NCA (National Certification Authority) of Kazakhstan.

## License

MIT
