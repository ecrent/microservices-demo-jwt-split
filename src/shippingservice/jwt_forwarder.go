package main

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// jwtUnaryServerInterceptor extracts and reassembles JWT from incoming metadata
func jwtUnaryServerInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		// No metadata, continue without JWT
		return handler(ctx, req)
	}

	var jwtToken string

	// Check for compressed JWT format (x-jwt-payload header)
	if payloadHeaders := md.Get("x-jwt-payload"); len(payloadHeaders) > 0 {
		// Compressed format: raw JSON payload + signature
		var signature string
		
		if sigHeaders := md.Get("x-jwt-sig"); len(sigHeaders) > 0 {
			signature = sigHeaders[0]
		}
		
		components := &JWTComponents{
			Payload:   payloadHeaders[0],
			Signature: signature,
		}

		// Reassemble JWT from components (1 base64 encode operation)
		reassembled, err := ReassembleJWT(components)
		if err != nil {
			log.Warnf("Failed to reassemble JWT: %v", err)
			return handler(ctx, req)
		}
		jwtToken = reassembled

	} else if authHeaders := md.Get("authorization"); len(authHeaders) > 0 {
		// Standard format: "Bearer <token>"
		jwtToken = strings.TrimPrefix(authHeaders[0], "Bearer ")
	}

	// JWT available for validation/claims extraction if needed
	_ = jwtToken

	return handler(ctx, req)
}// jwtStreamServerInterceptor extracts JWT from incoming stream metadata
func jwtStreamServerInterceptor(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	ctx := ss.Context()
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return handler(srv, ss)
	}

	var jwtToken string

	// Check for compressed JWT format (x-jwt-payload header)
	if payloadHeaders := md.Get("x-jwt-payload"); len(payloadHeaders) > 0 {
		var signature string
		
		if sigHeaders := md.Get("x-jwt-sig"); len(sigHeaders) > 0 {
			signature = sigHeaders[0]
		}
		
		components := &JWTComponents{
			Payload:   payloadHeaders[0],
			Signature: signature,
		}

		reassembled, err := ReassembleJWT(components)
		if err != nil {
			log.Warnf("Failed to reassemble JWT in stream: %v", err)
			return handler(srv, ss)
		}
		jwtToken = reassembled
	} else if authHeaders := md.Get("authorization"); len(authHeaders) > 0 {
		jwtToken = strings.TrimPrefix(authHeaders[0], "Bearer ")
	}

	// JWT available for validation/claims extraction if needed
	_ = jwtToken

	return handler(srv, ss)
}
