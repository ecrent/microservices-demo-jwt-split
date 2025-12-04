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
			return handler(ctx, req) // Continue without JWT
		}
		jwtToken = reassembled

	} else if authHeaders := md.Get("authorization"); len(authHeaders) > 0 {
		// Standard format: "Bearer <token>"
		jwtToken = strings.TrimPrefix(authHeaders[0], "Bearer ")
	}

    // JWT received and reassembled (no forwarding needed for shippingservice)
	_ = jwtToken // Silence unused variable warning

	return handler(ctx, req)
}// jwtStreamServerInterceptor extracts and reassembles JWT from incoming stream metadata
func jwtStreamServerInterceptor(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	ctx := ss.Context()
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return handler(srv, ss)
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

		reassembled, err := ReassembleJWT(components)
		if err != nil {
			log.Warnf("Failed to reassemble JWT in stream: %v", err)
			return handler(srv, ss)
		}
		jwtToken = reassembled
	} else if authHeaders := md.Get("authorization"); len(authHeaders) > 0 {
		jwtToken = strings.TrimPrefix(authHeaders[0], "Bearer ")
	}

	if jwtToken != "" {
		log.Infof("JWT received for stream %s (compressed=%v)", info.FullMethod, len(md.Get("x-jwt-payload")) > 0)
	}

	return handler(srv, ss)
}
