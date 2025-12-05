package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

// Note: JWT header is always transmitted via x-jwt-header
// No default header - supports all IdPs (Auth0, Okta, Azure, Google with kid/jku/x5t)

// JWTComponents represents the decomposed parts of a JWT for compression
// 3-header design: header + payload + signature
// Supports IdPs with varying headers (kid, jku, x5t, etc.)
type JWTComponents struct {
	Header    string // Original header (base64url encoded, for IdP compatibility)
	Payload   string // Raw JSON payload (base64 decoded for HPACK efficiency)
	Signature string // Original signature (base64url encoded, unchanged)
}

// IsJWTCompressionEnabled checks if JWT compression is enabled via environment variable
func IsJWTCompressionEnabled() bool {
	return os.Getenv("ENABLE_JWT_COMPRESSION") == "true"
}

// DecomposeJWT splits a JWT for optimized transmission
// Input: "header.payload.signature" JWT string
// Output: JWTComponents with header, raw JSON payload, and signature
// Operations: 1 base64 decode (payload only)
// Header is kept as base64url - HPACK will index it after first request
func DecomposeJWT(jwtToken string) (*JWTComponents, error) {
	parts := strings.Split(jwtToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	// Decode payload (base64url) - ONLY DECODE OPERATION
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	// Keep header as base64url - supports IdPs with kid, jku, x5t, etc.
	// HPACK will index this after first request (~2 bytes subsequent)

	return &JWTComponents{
		Header:    parts[0],            // Keep header as-is (base64url, stable per IdP)
		Payload:   string(payloadJSON), // Raw JSON, ~25% smaller than base64
		Signature: parts[2],            // Keep signature as-is (base64url encoded)
	}, nil
}

// ReassembleJWT reconstructs a JWT from its decomposed components
// Input: JWTComponents with header, raw JSON payload, and signature
// Output: "header.payload.signature" JWT string
// Operations: 1 base64 encode (payload only)
func ReassembleJWT(components *JWTComponents) (string, error) {
	// Base64url encode the raw JSON payload - ONLY ENCODE OPERATION
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(components.Payload))

	// Reconstruct JWT using original header
	return fmt.Sprintf("%s.%s.%s", components.Header, payloadB64, components.Signature), nil
}

// GetJWTComponentSizes returns the byte sizes of each component for logging/metrics
func GetJWTComponentSizes(components *JWTComponents) map[string]int {
	return map[string]int{
		"header":    len(components.Header),
		"payload":   len(components.Payload),
		"signature": len(components.Signature),
		"total":     len(components.Header) + len(components.Payload) + len(components.Signature),
	}
}
