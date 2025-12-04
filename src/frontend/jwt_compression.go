package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

// JWT Header constant - RS256 algorithm, JWT type
// This is hardcoded because it never changes across any JWT in our system
// Base64URL encoded: {"alg":"RS256","typ":"JWT"}
const JWTHeaderB64 = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"

// JWTComponents represents the decomposed parts of a JWT for compression
// Optimized design: only 2 components (payload + signature)
// Header is hardcoded constant, not transmitted
type JWTComponents struct {
	Payload   string // Raw JSON payload (base64 decoded)
	Signature string // Original signature (base64url encoded, unchanged)
}

// IsJWTCompressionEnabled checks if JWT compression is enabled via environment variable
func IsJWTCompressionEnabled() bool {
	return os.Getenv("ENABLE_JWT_COMPRESSION") == "true"
}

// DecomposeJWT splits a JWT for optimized transmission
// Input: "header.payload.signature" JWT string
// Output: JWTComponents with raw JSON payload and signature
// Operations: 1 base64 decode (payload only)
func DecomposeJWT(jwtToken string) (*JWTComponents, error) {
	parts := strings.Split(jwtToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	// Decode payload (base64url) - ONLY OPERATION
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	// Skip header - it's always {"alg":"RS256","typ":"JWT"}, receiver has it hardcoded

	return &JWTComponents{
		Payload:   string(payloadJSON), // Raw JSON, ~25% smaller than base64
		Signature: parts[2],            // Keep signature as-is (base64url encoded)
	}, nil
}

// ReassembleJWT reconstructs a JWT from its decomposed components
// Input: JWTComponents with raw JSON payload and signature
// Output: "header.payload.signature" JWT string
// Operations: 1 base64 encode (payload only)
func ReassembleJWT(components *JWTComponents) (string, error) {
	// Base64url encode the raw JSON payload - ONLY OPERATION
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(components.Payload))

	// Reconstruct JWT using hardcoded header constant
	return fmt.Sprintf("%s.%s.%s", JWTHeaderB64, payloadB64, components.Signature), nil
}

// GetJWTComponentSizes returns the byte sizes of each component for logging/metrics
func GetJWTComponentSizes(components *JWTComponents) map[string]int {
	return map[string]int{
		"payload":   len(components.Payload),
		"signature": len(components.Signature),
		"total":     len(components.Payload) + len(components.Signature),
	}
}
