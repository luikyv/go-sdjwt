package sdjwt

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type Disclosure struct {
	Salt      string
	ClaimName string
	Value     any
}

type DisclosureOptions struct {
	// Salt is a random string used to salt the disclosure.
	// If not provided, a random salt will be generated.
	Salt string
	// ClaimName adds a name to the disclosure.
	// This must be informed for disclosures of claims.
	// This must not be informed for disclosures of array items.
	ClaimName string
}

func NewDisclosure(value any, opts *DisclosureOptions) Disclosure {
	if opts == nil {
		opts = &DisclosureOptions{}
	}

	if opts.Salt == "" {
		salt := make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			panic(err)
		}
		opts.Salt = base64.RawURLEncoding.EncodeToString(salt)
	}

	return Disclosure{
		Salt:      opts.Salt,
		ClaimName: opts.ClaimName,
		Value:     value,
	}
}

func (d Disclosure) Encode() (string, error) {
	disclosureArray := []any{d.Salt}
	if d.ClaimName != "" {
		disclosureArray = append(disclosureArray, d.ClaimName)
	}
	disclosureArray = append(disclosureArray, d.Value)

	disclosureArrayBytes, err := json.Marshal(disclosureArray)
	if err != nil {
		return "", fmt.Errorf("failed to marshal disclosure array: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(disclosureArrayBytes), nil
}

func (d Disclosure) MustHash(h hash.Hash) string {
	digest, err := d.Hash(h)
	if err != nil {
		panic(err)
	}
	return digest
}

func (d Disclosure) Hash(h hash.Hash) (string, error) {
	serialized, err := d.Encode()
	if err != nil {
		return "", err
	}

	defer h.Reset()
	_, err = h.Write([]byte(serialized))
	if err != nil {
		return "", fmt.Errorf("failed to write to disclosure hash: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)), nil
}

type Builder interface {
	Claims(i any) Builder
	Disclosures(disclosures []Disclosure) Builder
	Hash(h hash.Hash) Builder
	Token() (*SDJWT, error)
	Serialize() (string, error)
}

type builder struct {
	jwtBuilder  jwt.Builder
	disclosures []Disclosure
	hash        hash.Hash
}

func (b *builder) Disclosures(disclosures []Disclosure) Builder {
	b.disclosures = append(b.disclosures, disclosures...)
	return b
}

func (b *builder) Claims(claims any) Builder {
	b.jwtBuilder = b.jwtBuilder.Claims(claims)
	return b
}

func (b *builder) Hash(h hash.Hash) Builder {
	b.hash = h
	return b
}

func (b *builder) Serialize() (string, error) {
	serialized, err := b.jwtBuilder.Serialize()
	if err != nil {
		return "", err
	}

	serialized += "~"
	for _, disclosure := range b.disclosures {
		encoded, err := disclosure.Encode()
		if err != nil {
			return "", err
		}
		serialized += encoded + "~"
	}

	return serialized, nil
}

func (b *builder) Token() (*SDJWT, error) {
	issuerJWT, err := b.jwtBuilder.Token()
	if err != nil {
		return nil, err
	}

	serialized, err := b.Serialize()
	if err != nil {
		return nil, err
	}

	if b.hash == nil {
		b.hash = sha256.New()
	}

	return &SDJWT{
		issuerJWT:   serialized,
		IssuerJWT:   issuerJWT,
		Disclosures: b.disclosures,
	}, nil
}

func Signed(sig jose.Signer) Builder {
	return &builder{
		jwtBuilder: jwt.Signed(sig),
	}
}

func ParseSigned(s string, sigAlgs []jose.SignatureAlgorithm, kbSigAlgs []jose.SignatureAlgorithm) (*SDJWT, error) {
	sdJWT := &SDJWT{}

	if !strings.Contains(s, "~") {
		return nil, errors.New("invalid SD-JWT")
	}
	parts := strings.Split(s, "~")
	sdJWT.issuerJWT = parts[0]

	issuerJWT, err := jwt.ParseSigned(sdJWT.issuerJWT, sigAlgs)
	if err != nil {
		return nil, fmt.Errorf("failed to parse issuer JWT: %w", err)
	}
	sdJWT.IssuerJWT = issuerJWT

	var claims struct {
		SDAlg string `json:"_sd_alg"`
	}
	if err := issuerJWT.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse issuer JWT: %w", err)
	}
	switch claims.SDAlg {
	case "sha-224":
		sdJWT.h = sha256.New224()
	case "sha-384":
		sdJWT.h = sha512.New384()
	case "sha-512":
		sdJWT.h = sha512.New()
	default:
		sdJWT.h = sha256.New()
	}

	sdJWT.Disclosures = make([]Disclosure, 0, len(parts)-1)
	for _, part := range parts[1 : len(parts)-1] {
		disclosure, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil {
			return nil, err
		}

		disclosureArray := []any{}
		if err := json.Unmarshal(disclosure, &disclosureArray); err != nil {
			return nil, err
		}

		var opts *DisclosureOptions
		var value any
		switch len(disclosureArray) {
		case 2:
			salt, ok := disclosureArray[0].(string)
			if !ok {
				return nil, errors.New("invalid salt")
			}
			value = disclosureArray[1]
			opts = &DisclosureOptions{Salt: salt}
		case 3:
			salt, ok := disclosureArray[0].(string)
			if !ok {
				return nil, errors.New("invalid salt")
			}

			claimName, ok := disclosureArray[1].(string)
			if !ok {
				return nil, errors.New("invalid claim name")
			}

			value = disclosureArray[2]
			opts = &DisclosureOptions{
				Salt:      salt,
				ClaimName: claimName,
			}
		default:
			return nil, errors.New("invalid disclosure array length")
		}
		sdJWT.Disclosures = append(sdJWT.Disclosures, NewDisclosure(value, opts))
	}

	if parts[len(parts)-1] != "" {
		kbJWT, err := jwt.ParseSigned(parts[len(parts)-1], kbSigAlgs)
		if err != nil {
			return nil, fmt.Errorf("failed to parse key binding JWT: %w", err)
		}
		sdJWT.KeyBindingJWT = kbJWT
	}

	return sdJWT, nil
}

type SDJWT struct {
	issuerJWT     string
	IssuerJWT     *jwt.JSONWebToken
	Disclosures   []Disclosure
	KeyBindingJWT *jwt.JSONWebToken
	h             hash.Hash
}

// Serialize serializes the SD-JWT with only the given disclosures and an optional key binding JWT.
func (t *SDJWT) Serialize(disclosures []Disclosure, kbJWT string) (string, error) {
	serialized := t.issuerJWT + "~"
	for _, disclosure := range disclosures {
		encoded, err := disclosure.Encode()
		if err != nil {
			return "", err
		}
		serialized += encoded + "~"
	}

	serialized += kbJWT
	return serialized, nil
}

func (t *SDJWT) hash() hash.Hash {
	if t.h == nil {
		return sha256.New()
	}

	return t.h
}

// Hash returns the hash of the SD-JWT.
func (t *SDJWT) Hash() (string, error) {
	h := t.hash()
	defer h.Reset()
	_, err := h.Write([]byte(t.issuerJWT))
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)), nil
}

// Claims resolves the disclosures and unmarshals the claims into the given destinations.
func (t *SDJWT) Claims(key any, dests ...any) error {
	claims := map[string]any{}
	if err := t.IssuerJWT.Claims(key, &claims); err != nil {
		return err
	}

	resolvedClaims, err := t.resolveDisclosures(claims, make(map[string]struct{}))
	if err != nil {
		return err
	}

	resolvedClaimsBytes, err := json.Marshal(resolvedClaims)
	if err != nil {
		return err
	}

	for _, dest := range dests {
		if err := json.Unmarshal(resolvedClaimsBytes, dest); err != nil {
			return err
		}
	}

	return nil
}

func (t *SDJWT) resolveDisclosures(claims map[string]any, seenDisclosures map[string]struct{}) (map[string]any, error) {
	resolvedClaims := make(map[string]any)
	for key, value := range claims {
		if key == "_sd" || key == "_sd_alg" {
			continue
		}

		switch v := value.(type) {
		case map[string]any:
			resolved, err := t.resolveDisclosures(v, seenDisclosures)
			if err != nil {
				return nil, err
			}
			resolvedClaims[key] = resolved

		case []any:
			resolved, err := t.resolveArrayDisclosures(v, seenDisclosures)
			if err != nil {
				return nil, err
			}
			resolvedClaims[key] = resolved

		default:
			resolvedClaims[key] = value
		}
	}

	sdArray, exists := claims["_sd"]
	if !exists {
		return resolvedClaims, nil
	}

	digests, ok := sdArray.([]any)
	if !ok {
		return nil, errors.New("invalid _sd array")
	}

	for _, digest := range digests {
		digestStr, ok := digest.(string)
		if !ok {
			return nil, errors.New("invalid _sd digest")
		}

		if _, ok := seenDisclosures[digestStr]; ok {
			return nil, fmt.Errorf("disclosure %s already used", digestStr)
		}
		seenDisclosures[digestStr] = struct{}{}

		disclosure, ok := t.findDisclosure(digestStr)
		if !ok {
			continue
		}

		if _, ok := resolvedClaims[disclosure.ClaimName]; ok {
			return nil, fmt.Errorf("claim %s already exists", disclosure.ClaimName)
		}

		resolvedClaims[disclosure.ClaimName] = disclosure.Value
	}

	// Recursively resolve disclosures in the resolved claims.
	return t.resolveDisclosures(resolvedClaims, seenDisclosures)
}

func (t *SDJWT) resolveArrayDisclosures(array []any, seenDisclosures map[string]struct{}) ([]any, error) {
	resolvedItems := make([]any, 0, len(array))

	for _, item := range array {
		switch v := item.(type) {
		case map[string]any:
			if digest, exists := v["..."]; exists {
				digestStr, ok := digest.(string)
				if !ok {
					return nil, errors.New("invalid disclosure digest")
				}

				if _, ok := seenDisclosures[digestStr]; ok {
					return nil, fmt.Errorf("disclosure %s already used", digestStr)
				}
				seenDisclosures[digestStr] = struct{}{}

				disclosure, exists := t.findDisclosure(digestStr)
				if !exists {
					continue
				}

				resolvedItems = append(resolvedItems, disclosure.Value)
			} else {
				resolved, err := t.resolveDisclosures(v, seenDisclosures)
				if err != nil {
					return nil, err
				}
				resolvedItems = append(resolvedItems, resolved)
			}

		case []any:
			resolved, err := t.resolveArrayDisclosures(v, seenDisclosures)
			if err != nil {
				return nil, err
			}
			resolvedItems = append(resolvedItems, resolved)

		default:
			resolvedItems = append(resolvedItems, item)
		}
	}

	return resolvedItems, nil
}

func (t *SDJWT) findDisclosure(digest string) (Disclosure, bool) {
	for _, disclosure := range t.Disclosures {
		if d, err := disclosure.Hash(t.hash()); err == nil && d == digest {
			return disclosure, true
		}
	}
	return Disclosure{}, false
}
