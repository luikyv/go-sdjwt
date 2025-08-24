# go-sdjwt

A Go implementation of Selective Disclosure JWT (SD-JWT).

SD-JWT (Selective Disclosure JWT) is a standard for creating verifiable credentials that allow holders to selectively disclose only specific claims while maintaining the cryptographic integrity of the original credential. This library provides a complete implementation of the SD-JWT specification in Go.

## Installation

```bash
go get github.com/luikyv/go-sdjwt
```

## Quick Start

### Creating an SD-JWT

```go
package main

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "time"

    "github.com/go-jose/go-jose/v4"
    "github.com/luikyv/go-sdjwt/sdjwt"
)

func main() {
    // Generate issuer key.
    issuerKey, _ := rsa.GenerateKey(rand.Reader, 2048)
    issuerSigner, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.PS256, Key: issuerKey}, nil)

    // Create disclosures for sensitive data.
    disclosureName := sdjwt.NewDisclosure("John Doe", &sdjwt.DisclosureOptions{ClaimName: "name"})
    disclosureEmail := sdjwt.NewDisclosure("john@example.com", &sdjwt.DisclosureOptions{ClaimName: "email"})
    disclosurePhone := sdjwt.NewDisclosure("+1234567890", &sdjwt.DisclosureOptions{ClaimName: "phone"})

    // Build and serialize the SD-JWT.
    serialized, _ := sdjwt.Signed(issuerSigner).
        Hash(sha256.New()).
        Disclosures([]sdjwt.Disclosure{disclosureName, disclosureEmail, disclosurePhone}).
        Claims(map[string]any{
            "iss": "https://issuer.example.com",
            "sub": "1234567890",
            "exp": time.Now().Add(time.Hour).Unix(),
            "_sd": []any{
                disclosureName.MustHash(sha256.New()),
                disclosureEmail.MustHash(sha256.New()),
                disclosurePhone.MustHash(sha256.New()),
            },
            "_sd_alg": "sha-256",
        }).
        Serialize()

    fmt.Println(serialized)
}
```

### Parsing and Verifying an SD-JWT

```go
// Parse the SD-JWT
sdJWT, err := sdjwt.ParseSigned(serialized, []jose.SignatureAlgorithm{jose.PS256}, nil)
if err != nil {
    panic(err)
}

// Resolve all claims
var claims map[string]any
err = sdJWT.Claims(issuerKey.Public(), &claims)
if err != nil {
    panic(err)
}

// Access the disclosed claims
name := claims["name"].(string)     // "John Doe"
email := claims["email"].(string)   // "john@example.com"
phone := claims["phone"].(string)   // "+1234567890"
```

### Selective Disclosure

```go
// Create a presentation with only specific disclosures.
selectedDisclosures := []sdjwt.Disclosure{nameDisclosure, emailDisclosure}
presentation, _ := sdJWT.Serialize(selectedDisclosures, "")

// Parse the presentation.
presentationSDJWT, _ := sdjwt.ParseSigned(presentation, []jose.SignatureAlgorithm{jose.PS256}, nil)

var presentationClaims map[string]any
presentationSDJWT.Claims(issuerKey.Public(), &presentationClaims)

// Only name and email are available.
name := presentationClaims["name"].(string)   // "John Doe"
email := presentationClaims["email"].(string) // "john@example.com"
phone := presentationClaims["phone"]          // nil (not disclosed)
```

## Advanced Features

### Nested Disclosures

```go
// Create nested address disclosure.
streetDisclosure := sdjwt.NewDisclosure("123 Main St", &sdjwt.DisclosureOptions{ClaimName: "street"})
zipDisclosure := sdjwt.NewDisclosure("12345", &sdjwt.DisclosureOptions{ClaimName: "zip"})

addressDisclosure := sdjwt.NewDisclosure(map[string]any{
    "_sd": []any{
        streetDisclosure.MustHash(sha256.New()),
        zipDisclosure.MustHash(sha256.New()),
    },
    "city":  "Anytown",
    "state": "CA",
}, &sdjwt.DisclosureOptions{ClaimName: "address"})
```

### Array Disclosures

```go
// Create disclosure for array element.
frenchDisclosure := sdjwt.NewDisclosure("FR", nil)

claims := map[string]any{
    "nationalities": []any{
        "US",
        map[string]any{"...": frenchDisclosure.MustHash(sha256.New())},
        "DE",
    },
}
```

### Key Binding

```go
// Create key binding JWT.
holderKey, _ := rsa.GenerateKey(rand.Reader, 2048)
holderSigner, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: holderKey}, nil)

keyBindingJWT, _ := jwt.Signed(holderSigner).Claims(map[string]any{
    "nonce": "1234567890",
    "aud":   "https://verifier.example.com",
    "iat":   time.Now().Unix(),
}).Serialize()

// Add key binding to SD-JWT.
presentation := sdJWT.Serialize(disclosures, keyBindingJWT)
```
