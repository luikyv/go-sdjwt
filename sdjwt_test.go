package sdjwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func TestNewDisclosure(t *testing.T) {
	tests := []struct {
		name     string
		value    any
		opts     *DisclosureOptions
		expected Disclosure
	}{
		{
			name:  "basic disclosure without options",
			value: "test value",
			opts:  nil,
			expected: Disclosure{
				Value: "test value",
			},
		},
		{
			name:  "disclosure with salt and claim name",
			value: "secret value",
			opts: &DisclosureOptions{
				Salt:      "custom-salt",
				ClaimName: "secret_claim",
			},
			expected: Disclosure{
				Salt:      "custom-salt",
				ClaimName: "secret_claim",
				Value:     "secret value",
			},
		},
		{
			name:  "disclosure with only salt",
			value: "another value",
			opts: &DisclosureOptions{
				Salt: "another-salt",
			},
			expected: Disclosure{
				Salt:  "another-salt",
				Value: "another value",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NewDisclosure(tt.value, tt.opts)

			if tt.opts == nil || tt.opts.Salt == "" {
				// Auto-generated salt should be present.
				if result.Salt == "" {
					t.Errorf("expected auto-generated salt, got empty string")
				}
				if len(result.Salt) != 22 { // base64.RawURLEncoding of 16 bytes.
					t.Errorf("expected salt length 22, got %d", len(result.Salt))
				}
			} else {
				if result.Salt != tt.expected.Salt {
					t.Errorf("expected salt %s, got %s", tt.expected.Salt, result.Salt)
				}
			}

			if result.ClaimName != tt.expected.ClaimName {
				t.Errorf("expected claim name %s, got %s", tt.expected.ClaimName, result.ClaimName)
			}
			if result.Value != tt.expected.Value {
				t.Errorf("expected value %v, got %v", tt.expected.Value, result.Value)
			}
		})
	}
}

func TestDisclosure_Encode(t *testing.T) {
	tests := []struct {
		name       string
		disclosure Disclosure
	}{
		{
			name: "disclosure without claim name",
			disclosure: Disclosure{
				Salt:  "test-salt",
				Value: "test value",
			},
		},
		{
			name: "disclosure with claim name",
			disclosure: Disclosure{
				Salt:      "test-salt",
				ClaimName: "test_claim",
				Value:     "test value",
			},
		},
		{
			name: "disclosure with complex value",
			disclosure: Disclosure{
				Salt:      "test-salt",
				ClaimName: "complex_claim",
				Value: map[string]any{
					"nested": "value",
					"number": 42,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.disclosure.Encode()

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if result == "" {
				t.Errorf("expected non-empty result, got empty string")
				return
			}

			// Verify the encoded string can be decoded back.
			decoded, err := decodeDisclosure(result)
			if err != nil {
				t.Fatalf("failed to decode disclosure: %v", err)
				return
			}

			if decoded.Salt != tt.disclosure.Salt {
				t.Errorf("expected salt %s, got %s", tt.disclosure.Salt, decoded.Salt)
			}
			if decoded.ClaimName != tt.disclosure.ClaimName {
				t.Errorf("expected claim name %s, got %s", tt.disclosure.ClaimName, decoded.ClaimName)
			}
			if fmt.Sprintf("%v", decoded.Value) != fmt.Sprintf("%v", tt.disclosure.Value) {
				t.Errorf("expected value %v, got %v", tt.disclosure.Value, decoded.Value)
			}
		})
	}
}

func TestDisclosure_Hash(t *testing.T) {
	disclosure := Disclosure{
		Salt:      "test-salt",
		ClaimName: "test_claim",
		Value:     "test value",
	}

	tests := []struct {
		name         string
		hashFunc     func() hash.Hash
		algorithm    string
		digestLength int
	}{
		{
			name:         "SHA-256",
			hashFunc:     sha256.New,
			algorithm:    "sha-256",
			digestLength: 43,
		},
		{
			name:         "SHA-512",
			hashFunc:     sha512.New,
			algorithm:    "sha-512",
			digestLength: 86,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := tt.hashFunc()

			result, err := disclosure.Hash(hash)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if result == "" {
				t.Errorf("expected non-empty result, got empty string")
				return
			}
			if len(result) != tt.digestLength {
				t.Errorf("expected hash length %d, got %d", tt.digestLength, len(result))
			}
		})
	}
}

func TestDisclosure_MustHash(t *testing.T) {
	disclosure := Disclosure{
		Salt:      "test-salt",
		ClaimName: "test_claim",
		Value:     "test value",
	}

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("MustHash panicked: %v", r)
		}
	}()
	result := disclosure.MustHash(sha256.New())
	if result == "" {
		t.Errorf("expected non-empty result, got empty string")
	}

	// Test that MustHash produces same result as Hash
	hash1, err := disclosure.Hash(sha256.New())
	if err != nil {
		t.Errorf("Hash failed: %v", err)
		return
	}

	hash2 := disclosure.MustHash(sha256.New())
	if hash1 != hash2 {
		t.Errorf("expected hash %s, got %s", hash1, hash2)
	}
}

func TestSigned(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.PS256, Key: key}, nil)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	builder := Signed(signer)
	if builder == nil {
		t.Error("expected non-nil builder")
	}
}

func TestBuilder_Disclosures(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.PS256, Key: key}, nil)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	disclosures := []Disclosure{
		NewDisclosure("value1", &DisclosureOptions{ClaimName: "claim1"}),
		NewDisclosure("value2", &DisclosureOptions{ClaimName: "claim2"}),
	}

	builder := Signed(signer).Disclosures(disclosures)
	if builder == nil {
		t.Error("expected non-nil builder")
	}
}

func TestBuilder_Claims(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.PS256, Key: key}, nil)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	claims := map[string]any{
		"iss": "https://issuer.example.com",
		"sub": "1234567890",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	builder := Signed(signer).Claims(claims)
	if builder == nil {
		t.Error("expected non-nil builder")
	}
}

func TestBuilder_Hash(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.PS256, Key: key}, nil)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	builder := Signed(signer).Hash(sha256.New())
	if builder == nil {
		t.Error("expected non-nil builder")
	}
}

func TestBuilder_Serialize(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.PS256, Key: key}, nil)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	disclosures := []Disclosure{
		NewDisclosure("value1", &DisclosureOptions{ClaimName: "claim1"}),
		NewDisclosure("value2", &DisclosureOptions{ClaimName: "claim2"}),
	}

	claims := map[string]any{
		"iss": "https://issuer.example.com",
		"sub": "1234567890",
		"exp": time.Now().Add(time.Hour).Unix(),
		"_sd": []any{
			disclosures[0].MustHash(sha256.New()),
			disclosures[1].MustHash(sha256.New()),
		},
		"_sd_alg": "sha-256",
	}

	serialized, err := Signed(signer).Disclosures(disclosures).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("failed to serialize: %v", err)
	}
	if serialized == "" {
		t.Error("expected non-empty serialized string")
	}
	if !strings.Contains(serialized, "~") {
		t.Error("expected serialized string to contain tilde separator")
	}
}

func TestBuilder_Token(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.PS256, Key: key}, nil)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	disclosures := []Disclosure{
		NewDisclosure("value1", &DisclosureOptions{ClaimName: "claim1"}),
		NewDisclosure("value2", &DisclosureOptions{ClaimName: "claim2"}),
	}

	claims := map[string]any{
		"iss": "https://issuer.example.com",
		"sub": "1234567890",
		"exp": time.Now().Add(time.Hour).Unix(),
		"_sd": []any{
			disclosures[0].MustHash(sha256.New()),
			disclosures[1].MustHash(sha256.New()),
		},
		"_sd_alg": "sha-256",
	}

	sdJWT, err := Signed(signer).Disclosures(disclosures).Claims(claims).Token()
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}
	if sdJWT == nil {
		t.Fatal("expected non-nil SDJWT")
	}
	if len(sdJWT.Disclosures) != 2 {
		t.Errorf("expected 2 disclosures, got %d", len(sdJWT.Disclosures))
	}
}

func TestParseSigned(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.PS256, Key: key}, nil)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	disclosures := []Disclosure{
		NewDisclosure("value1", &DisclosureOptions{ClaimName: "claim1"}),
		NewDisclosure("value2", &DisclosureOptions{ClaimName: "claim2"}),
	}

	claims := map[string]any{
		"iss": "https://issuer.example.com",
		"sub": "1234567890",
		"exp": time.Now().Add(time.Hour).Unix(),
		"_sd": []any{
			disclosures[0].MustHash(sha256.New()),
			disclosures[1].MustHash(sha256.New()),
		},
		"_sd_alg": "sha-256",
	}

	serialized, err := Signed(signer).Disclosures(disclosures).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("failed to serialize: %v", err)
	}

	parsed, err := ParseSigned(serialized, []jose.SignatureAlgorithm{jose.PS256}, nil)
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}
	if parsed == nil {
		t.Fatal("expected non-nil parsed SDJWT")
	}
	if len(parsed.Disclosures) != 2 {
		t.Errorf("expected 2 disclosures, got %d", len(parsed.Disclosures))
	}
}

func TestParseSigned_InvalidInput(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectedErr string
	}{
		{
			name:        "empty string",
			input:       "",
			expectedErr: "invalid SD-JWT",
		},
		{
			name:        "no tilde separator",
			input:       "invalid.jwt.token",
			expectedErr: "invalid SD-JWT",
		},
		{
			name:        "invalid JWT",
			input:       "invalid~disclosure~",
			expectedErr: "failed to parse issuer JWT",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseSigned(tt.input, []jose.SignatureAlgorithm{jose.PS256}, nil)
			if err == nil {
				t.Error("expected error, got nil")
				return
			}
			if !strings.Contains(err.Error(), tt.expectedErr) {
				t.Errorf("expected error containing %s, got %s", tt.expectedErr, err.Error())
			}
		})
	}
}

func TestParseSigned_WithKeyBinding(t *testing.T) {
	issuerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate issuer key: %v", err)
	}

	holderKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate holder key: %v", err)
	}

	issuerSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.PS256, Key: issuerKey}, nil)
	if err != nil {
		t.Fatalf("failed to create issuer signer: %v", err)
	}

	holderSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: holderKey}, nil)
	if err != nil {
		t.Fatalf("failed to create holder signer: %v", err)
	}

	disclosures := []Disclosure{
		NewDisclosure("value1", &DisclosureOptions{ClaimName: "claim1"}),
	}

	claims := map[string]any{
		"iss": "https://issuer.example.com",
		"sub": "1234567890",
		"exp": time.Now().Add(time.Hour).Unix(),
		"_sd": []any{
			disclosures[0].MustHash(sha256.New()),
		},
		"_sd_alg": "sha-256",
	}

	keyBindingClaims := map[string]any{
		"nonce": "1234567890",
		"aud":   "https://verifier.example.com",
		"iat":   time.Now().Unix(),
	}

	keyBindingJWT, err := jwt.Signed(holderSigner).Claims(keyBindingClaims).Serialize()
	if err != nil {
		t.Fatalf("failed to create key binding JWT: %v", err)
	}

	serialized, err := Signed(issuerSigner).Disclosures(disclosures).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("failed to serialize: %v", err)
	}

	// Add key binding JWT to the serialized string.
	serialized += keyBindingJWT

	parsed, err := ParseSigned(serialized, []jose.SignatureAlgorithm{jose.PS256}, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}
	if parsed == nil {
		t.Fatal("expected non-nil parsed SDJWT")
	}
	if parsed.KeyBindingJWT == nil {
		t.Error("expected non-nil key binding JWT")
	}
}

func TestSDJWT_Serialize(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.PS256, Key: key}, nil)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	disclosures := []Disclosure{
		NewDisclosure("value1", &DisclosureOptions{ClaimName: "claim1"}),
		NewDisclosure("value2", &DisclosureOptions{ClaimName: "claim2"}),
	}

	claims := map[string]any{
		"iss": "https://issuer.example.com",
		"sub": "1234567890",
		"exp": time.Now().Add(time.Hour).Unix(),
		"_sd": []any{
			disclosures[0].MustHash(sha256.New()),
			disclosures[1].MustHash(sha256.New()),
		},
		"_sd_alg": "sha-256",
	}

	sdJWT, err := Signed(signer).Disclosures(disclosures).Claims(claims).Token()
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	// Serialize with only first disclosure
	selectedDisclosures := []Disclosure{disclosures[0]}
	serialized, err := sdJWT.Serialize(selectedDisclosures, "")
	if err != nil {
		t.Fatalf("failed to serialize: %v", err)
	}
	if serialized == "" {
		t.Error("expected non-empty serialized string")
	}
	if !strings.Contains(serialized, "~") {
		t.Error("expected serialized string to contain tilde separator")
	}
}

func TestSDJWT_Hash(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.PS256, Key: key}, nil)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	claims := map[string]any{
		"iss": "https://issuer.example.com",
		"sub": "1234567890",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	sdJWT, err := Signed(signer).Claims(claims).Token()
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	hash, err := sdJWT.Hash()
	if err != nil {
		t.Fatalf("failed to hash: %v", err)
	}
	if hash == "" {
		t.Error("expected non-empty hash")
	}
}

func TestSDJWT_Claims(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.PS256, Key: key}, nil)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	disclosures := []Disclosure{
		NewDisclosure("John Doe", &DisclosureOptions{ClaimName: "name"}),
		NewDisclosure("john@example.com", &DisclosureOptions{ClaimName: "email"}),
	}

	claims := map[string]any{
		"iss": "https://issuer.example.com",
		"sub": "1234567890",
		"exp": time.Now().Add(time.Hour).Unix(),
		"_sd": []any{
			disclosures[0].MustHash(sha256.New()),
			disclosures[1].MustHash(sha256.New()),
		},
		"_sd_alg": "sha-256",
	}

	sdJWT, err := Signed(signer).Disclosures(disclosures).Claims(claims).Token()
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	var resolvedClaims map[string]any
	err = sdJWT.Claims(key.Public(), &resolvedClaims)
	if err != nil {
		t.Fatalf("failed to resolve claims: %v", err)
	}

	if resolvedClaims["name"] != "John Doe" {
		t.Errorf("expected name 'John Doe', got %v", resolvedClaims["name"])
	}
	if resolvedClaims["email"] != "john@example.com" {
		t.Errorf("expected email 'john@example.com', got %v", resolvedClaims["email"])
	}
	if resolvedClaims["iss"] != "https://issuer.example.com" {
		t.Errorf("expected iss 'https://issuer.example.com', got %v", resolvedClaims["iss"])
	}
	if resolvedClaims["sub"] != "1234567890" {
		t.Errorf("expected sub '1234567890', got %v", resolvedClaims["sub"])
	}
}

func TestSDJWT_Claims_WithNestedDisclosures(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.PS256, Key: key}, nil)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	streetDisclosure := NewDisclosure("123 Main St", &DisclosureOptions{ClaimName: "street"})
	zipDisclosure := NewDisclosure("12345", &DisclosureOptions{ClaimName: "zip"})

	addressDisclosure := NewDisclosure(map[string]any{
		"_sd": []any{
			streetDisclosure.MustHash(sha256.New()),
			zipDisclosure.MustHash(sha256.New()),
		},
		"city":  "Anytown",
		"state": "CA",
	}, &DisclosureOptions{ClaimName: "address"})

	disclosures := []Disclosure{
		NewDisclosure("John Doe", &DisclosureOptions{ClaimName: "name"}),
		addressDisclosure,
		streetDisclosure,
		zipDisclosure,
	}

	claims := map[string]any{
		"iss": "https://issuer.example.com",
		"sub": "1234567890",
		"_sd": []any{
			disclosures[0].MustHash(sha256.New()),
			disclosures[1].MustHash(sha256.New()),
		},
		"_sd_alg": "sha-256",
	}

	sdJWT, err := Signed(signer).Disclosures(disclosures).Claims(claims).Token()
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	var resolvedClaims map[string]any
	err = sdJWT.Claims(key.Public(), &resolvedClaims)
	if err != nil {
		t.Fatalf("failed to resolve claims: %v", err)
	}

	if resolvedClaims["name"] != "John Doe" {
		t.Errorf("expected name 'John Doe', got %v", resolvedClaims["name"])
	}

	address, ok := resolvedClaims["address"].(map[string]any)
	if !ok {
		t.Fatal("expected address to be a map")
	}
	if address["street"] != "123 Main St" {
		t.Errorf("expected street '123 Main St', got %v", address["street"])
	}
	if address["zip"] != "12345" {
		t.Errorf("expected zip '12345', got %v", address["zip"])
	}
	if address["city"] != "Anytown" {
		t.Errorf("expected city 'Anytown', got %v", address["city"])
	}
	if address["state"] != "CA" {
		t.Errorf("expected state 'CA', got %v", address["state"])
	}
}

func TestSDJWT_Claims_WithArrayDisclosures(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.PS256, Key: key}, nil)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	frenchDisclosure := NewDisclosure("FR", nil)

	disclosures := []Disclosure{
		NewDisclosure("John Doe", &DisclosureOptions{ClaimName: "name"}),
		frenchDisclosure,
	}

	claims := map[string]any{
		"iss": "https://issuer.example.com",
		"sub": "1234567890",
		"_sd": []any{
			disclosures[0].MustHash(sha256.New()),
		},
		"_sd_alg": "sha-256",
		"nationalities": []any{
			"US",
			map[string]any{"...": frenchDisclosure.MustHash(sha256.New())},
			"DE",
		},
	}

	sdJWT, err := Signed(signer).Disclosures(disclosures).Claims(claims).Token()
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	var resolvedClaims map[string]any
	err = sdJWT.Claims(key.Public(), &resolvedClaims)
	if err != nil {
		t.Fatalf("failed to resolve claims: %v", err)
	}

	if resolvedClaims["name"] != "John Doe" {
		t.Errorf("expected name 'John Doe', got %v", resolvedClaims["name"])
	}

	nationalities, ok := resolvedClaims["nationalities"].([]any)
	if !ok {
		t.Fatal("expected nationalities to be a slice")
	}
	if len(nationalities) != 3 {
		t.Errorf("expected 3 nationalities, got %d", len(nationalities))
	}
	if nationalities[0] != "US" {
		t.Errorf("expected first nationality 'US', got %v", nationalities[0])
	}
	if nationalities[1] != "FR" {
		t.Errorf("expected second nationality 'FR', got %v", nationalities[1])
	}
	if nationalities[2] != "DE" {
		t.Errorf("expected third nationality 'DE', got %v", nationalities[2])
	}
}

func TestFullSDJWTWorkflow(t *testing.T) {
	issuerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate issuer key: %v", err)
	}

	issuerSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.PS256, Key: issuerKey}, nil)
	if err != nil {
		t.Fatalf("failed to create issuer signer: %v", err)
	}

	disclosureName := NewDisclosure("John Doe", &DisclosureOptions{ClaimName: "name"})
	disclosureEmail := NewDisclosure("john@example.com", &DisclosureOptions{ClaimName: "email"})
	disclosurePhone := NewDisclosure("+1234567890", &DisclosureOptions{ClaimName: "phone"})

	serialized, err := Signed(issuerSigner).Hash(sha256.New()).Disclosures([]Disclosure{
		disclosureName,
		disclosureEmail,
		disclosurePhone,
	}).Claims(map[string]any{
		"iss": "https://issuer.example.com",
		"sub": "1234567890",
		"exp": time.Now().Add(time.Hour).Unix(),
		"_sd": []any{
			disclosureName.MustHash(sha256.New()),
			disclosureEmail.MustHash(sha256.New()),
			disclosurePhone.MustHash(sha256.New()),
		},
		"_sd_alg": "sha-256",
	}).Serialize()

	if err != nil {
		t.Fatalf("failed to serialize: %v", err)
	}
	if serialized == "" {
		t.Fatal("expected non-empty serialized string")
	}

	sdJWT, err := ParseSigned(serialized, []jose.SignatureAlgorithm{jose.PS256}, nil)
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}
	if sdJWT == nil {
		t.Fatal("expected non-nil SDJWT")
	}
	if len(sdJWT.Disclosures) != 3 {
		t.Errorf("expected 3 disclosures, got %d", len(sdJWT.Disclosures))
	}

	var resolvedClaims map[string]any
	err = sdJWT.Claims(issuerKey.Public(), &resolvedClaims)
	if err != nil {
		t.Fatalf("failed to resolve claims: %v", err)
	}

	if resolvedClaims["name"] != "John Doe" {
		t.Errorf("expected name 'John Doe', got %v", resolvedClaims["name"])
	}
	if resolvedClaims["email"] != "john@example.com" {
		t.Errorf("expected email 'john@example.com', got %v", resolvedClaims["email"])
	}
	if resolvedClaims["phone"] != "+1234567890" {
		t.Errorf("expected phone '+1234567890', got %v", resolvedClaims["phone"])
	}
	if resolvedClaims["iss"] != "https://issuer.example.com" {
		t.Errorf("expected iss 'https://issuer.example.com', got %v", resolvedClaims["iss"])
	}
	if resolvedClaims["sub"] != "1234567890" {
		t.Errorf("expected sub '1234567890', got %v", resolvedClaims["sub"])
	}

	selectedDisclosures := []Disclosure{disclosureName, disclosureEmail}
	selectiveSerialized, err := sdJWT.Serialize(selectedDisclosures, "")
	if err != nil {
		t.Fatalf("failed to serialize selective disclosure: %v", err)
	}
	if selectiveSerialized == "" {
		t.Fatal("expected non-empty selective serialized string")
	}

	selectiveSDJWT, err := ParseSigned(selectiveSerialized, []jose.SignatureAlgorithm{jose.PS256}, nil)
	if err != nil {
		t.Fatalf("failed to parse selective disclosure: %v", err)
	}

	var selectiveClaims map[string]any
	err = selectiveSDJWT.Claims(issuerKey.Public(), &selectiveClaims)
	if err != nil {
		t.Fatalf("failed to resolve selective claims: %v", err)
	}

	if selectiveClaims["name"] != "John Doe" {
		t.Errorf("expected name 'John Doe', got %v", selectiveClaims["name"])
	}
	if selectiveClaims["email"] != "john@example.com" {
		t.Errorf("expected email 'john@example.com', got %v", selectiveClaims["email"])
	}
	if selectiveClaims["phone"] != nil {
		t.Errorf("expected phone to be nil, got %v", selectiveClaims["phone"])
	}
}

func TestHashAlgorithmSelection(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.PS256, Key: key}, nil)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	disclosure := NewDisclosure("test value", &DisclosureOptions{ClaimName: "test_claim"})

	tests := []struct {
		name  string
		hash  hash.Hash
		sdAlg string
	}{
		{
			name:  "SHA-256",
			hash:  sha256.New(),
			sdAlg: "sha-256",
		},
		{
			name:  "SHA-512",
			hash:  sha512.New(),
			sdAlg: "sha-512",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serialized, err := Signed(signer).Hash(tt.hash).Disclosures([]Disclosure{disclosure}).Claims(map[string]any{
				"iss":     "https://issuer.example.com",
				"sub":     "1234567890",
				"_sd":     []any{disclosure.MustHash(tt.hash)},
				"_sd_alg": tt.sdAlg,
			}).Serialize()

			if err != nil {
				t.Fatalf("failed to serialize: %v", err)
			}

			parsed, err := ParseSigned(serialized, []jose.SignatureAlgorithm{jose.PS256}, nil)
			if err != nil {
				t.Fatalf("failed to parse: %v", err)
			}

			var resolvedClaims map[string]any
			err = parsed.Claims(key.Public(), &resolvedClaims)
			if err != nil {
				t.Fatalf("failed to resolve claims: %v", err)
			}

			if resolvedClaims["test_claim"] != "test value" {
				t.Errorf("expected test_claim 'test value', got %v", resolvedClaims["test_claim"])
			}
		})
	}
}

// decodeDisclosure decodes a base64-encoded disclosure string back to a Disclosure.
func decodeDisclosure(encoded string) (Disclosure, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return Disclosure{}, err
	}

	var disclosureArray []any
	if err := json.Unmarshal(decoded, &disclosureArray); err != nil {
		return Disclosure{}, err
	}

	disclosure := Disclosure{}
	switch len(disclosureArray) {
	case 2:
		disclosure.Salt = disclosureArray[0].(string)
		disclosure.Value = disclosureArray[1]
	case 3:
		disclosure.Salt = disclosureArray[0].(string)
		disclosure.ClaimName = disclosureArray[1].(string)
		disclosure.Value = disclosureArray[2]
	default:
		return Disclosure{}, fmt.Errorf("invalid disclosure array length: %d", len(disclosureArray))
	}

	return disclosure, nil
}
