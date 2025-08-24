package sdjwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-sdjwt/sdjwt"
)

func Example() {
	h := sha256.New()

	issuerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	holderKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	disclosureName := sdjwt.NewDisclosure("John Doe", &sdjwt.DisclosureOptions{ClaimName: "name"})
	disclosureEmail := sdjwt.NewDisclosure("john.doe@example.com", &sdjwt.DisclosureOptions{ClaimName: "email"})
	disclosurePhone := sdjwt.NewDisclosure("+1234567890", &sdjwt.DisclosureOptions{ClaimName: "phone"})
	disclosureFrenchNationality := sdjwt.NewDisclosure("FR", nil)
	disclosureStreet := sdjwt.NewDisclosure("123 Main St", &sdjwt.DisclosureOptions{ClaimName: "street"})
	disclosureZip := sdjwt.NewDisclosure("12345", &sdjwt.DisclosureOptions{ClaimName: "zip"})
	disclosureAddress := sdjwt.NewDisclosure(map[string]any{
		"_sd":   []any{disclosureStreet, disclosureZip},
		"city":  "Anytown",
		"state": "CA",
	}, &sdjwt.DisclosureOptions{ClaimName: "address"})

	// ========================= Issuance =========================
	issuerSignerOpts := (&jose.SignerOptions{}).WithType("sd-jwt")
	issuerSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.PS256, Key: issuerKey}, issuerSignerOpts)
	if err != nil {
		panic(err)
	}

	serialized, err := sdjwt.Signed(issuerSigner).Hash(h).Disclosures([]sdjwt.Disclosure{
		disclosureName,
		disclosureEmail,
		disclosureAddress,
		disclosureZip,
		disclosureFrenchNationality,
	}).Claims(map[string]any{
		"iss": "https://issuer.luikyv.com",
		"_sd": []any{
			disclosureName.MustHash(h),
			disclosureEmail.MustHash(h),
			disclosurePhone.MustHash(h),
			disclosureAddress.MustHash(h),
			disclosureZip.MustHash(h),
		},
		"_sd_alg":       "sha-256",
		"nationalities": []any{"US", map[string]any{"...": disclosureFrenchNationality.MustHash(h)}, "DE"},
		"sub":           "1234567890",
		"exp":           time.Now().Add(time.Hour * 999999).Unix(),
		"cnf": map[string]any{
			"jwk": jose.JSONWebKey{
				Key: holderKey.Public(),
			},
		},
	}).Serialize()
	if err != nil {
		panic(err)
	}

	fmt.Printf("SD-JWT:\n%s\n\n", serialized)

	// ========================= Holder Verification =========================
	sdJWT, err := sdjwt.ParseSigned(serialized, []jose.SignatureAlgorithm{jose.PS256}, nil)
	if err != nil {
		panic(err)
	}

	var resolvedClaims map[string]any
	if err := sdJWT.Claims(issuerKey.Public(), &resolvedClaims); err != nil {
		panic(err)
	}

	resolvedJSON, err := json.MarshalIndent(resolvedClaims, "", "  ")
	if err != nil {
		panic(err)
	}
	fmt.Printf("Resolved claims:\n%s\n\n", string(resolvedJSON))

	// ========================= Holder Presentation =========================
	holderSignerOpts := (&jose.SignerOptions{}).WithType("JWT")
	holderSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: holderKey}, holderSignerOpts)
	if err != nil {
		panic(err)
	}

	sdHash, err := sdJWT.Hash()
	if err != nil {
		panic(err)
	}
	keyBindingJWT, err := jwt.Signed(holderSigner).Claims(map[string]any{
		"nonce":   "1234567890",
		"aud":     "https://verifier.luikyv.com",
		"iat":     time.Now().Unix(),
		"sd_hash": sdHash,
	}).Serialize()
	if err != nil {
		panic(err)
	}

	var presentedDisclosures []sdjwt.Disclosure
	for _, d := range sdJWT.Disclosures {
		if slices.Contains([]string{
			disclosureName.ClaimName,
			disclosureAddress.ClaimName,
			disclosureFrenchNationality.ClaimName,
		}, d.ClaimName) {
			presentedDisclosures = append(presentedDisclosures, d)
		}
	}

	serialized, err = sdJWT.Serialize(presentedDisclosures, keyBindingJWT)
	if err != nil {
		panic(err)
	}
	fmt.Printf("SD-JWT presented by the holder:\n%s\n\n", serialized)

	// ========================= Verifier Verification =========================
	verifierSDJWT, err := sdjwt.ParseSigned(
		serialized,
		[]jose.SignatureAlgorithm{jose.PS256},
		[]jose.SignatureAlgorithm{jose.RS256},
	)
	if err != nil {
		panic(err)
	}

	if verifierSDJWT.KeyBindingJWT == nil {
		panic("key binding JWT is nil")
	}

	var verifierResolvedClaims map[string]any
	var confirmation struct {
		Confirmation struct {
			JWK jose.JSONWebKey `json:"jwk"`
		} `json:"cnf"`
	}
	if err := verifierSDJWT.Claims(issuerKey.Public(), &verifierResolvedClaims, &confirmation); err != nil {
		panic(err)
	}

	var keyBindingResolvedClaims map[string]any
	if err := verifierSDJWT.KeyBindingJWT.Claims(confirmation.Confirmation.JWK.Public(), &keyBindingResolvedClaims); err != nil {
		panic(err)
	}

	verifierJSON, err := json.MarshalIndent(verifierResolvedClaims, "", "  ")
	if err != nil {
		panic(err)
	}
	fmt.Printf("Verifier resolved claims:\n%s\n\n", string(verifierJSON))

	keyBindingJSON, err := json.MarshalIndent(keyBindingResolvedClaims, "", "  ")
	if err != nil {
		panic(err)
	}
	fmt.Printf("Key binding claims:\n%s\n\n", string(keyBindingJSON))
}
