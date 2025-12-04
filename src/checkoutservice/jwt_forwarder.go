package main

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// Context key for storing JWT token
type ctxKeyJWT struct{}

// jwtUnaryServerInterceptor extracts JWT from incoming metadata and stores in context
func jwtUnaryServerInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		// No metadata, continue without JWT
		return handler(ctx, req)
	}

	var jwtToken string

	// Check for compressed JWT format (x-jwt-payload header)
	if payloadHeaders := md.Get("x-jwt-payload"); len(payloadHeaders) > 0 {
		// Compressed format detected - raw JSON payload + signature
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
	}	// Store JWT in context for client interceptor to forward
	if jwtToken != "" {
		ctx = context.WithValue(ctx, ctxKeyJWT{}, jwtToken)
	}

	return handler(ctx, req)
}

// jwtStreamServerInterceptor extracts JWT from incoming stream metadata
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
		ctx = context.WithValue(ctx, ctxKeyJWT{}, jwtToken)
	}

	return handler(srv, &wrappedServerStream{ServerStream: ss, ctx: ctx})
}

// wrappedServerStream wraps a grpc.ServerStream with a custom context
type wrappedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedServerStream) Context() context.Context {
	return w.ctx
}

// jwtUnaryClientInterceptor forwards JWT from incoming request to outgoing gRPC calls
func jwtUnaryClientInterceptor(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	// Get JWT from context (set by server interceptor)
	jwtToken, ok := ctx.Value(ctxKeyJWT{}).(string)
	if !ok || jwtToken == "" {
		// No JWT in context, invoke without adding headers
		return invoker(ctx, method, req, reply, cc, opts...)
	}

	// Check if compression is enabled
	if IsJWTCompressionEnabled() {
		// Decompose JWT for optimized transmission (1 base64 decode)
		components, err := DecomposeJWT(jwtToken)
		if err != nil {
			// Fallback to full JWT
			log.Warnf("Failed to decompose JWT, using full token: %v", err)
			ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+jwtToken)
        } else {
			// Forward as compressed headers: raw JSON payload + signature
			ctx = metadata.AppendToOutgoingContext(ctx,
				"x-jwt-payload", components.Payload,
				"x-jwt-sig", components.Signature)
		}
    } else {
		// JWT COMPRESSION DISABLED: Forward as standard authorization header
		ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+jwtToken)
	}

	return invoker(ctx, method, req, reply, cc, opts...)
}// jwtStreamClientInterceptor forwards JWT from incoming request to outgoing gRPC stream calls
func jwtStreamClientInterceptor(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	// Get JWT from context
	jwtToken, ok := ctx.Value(ctxKeyJWT{}).(string)
	if !ok || jwtToken == "" {
		return streamer(ctx, desc, cc, method, opts...)
	}

	// Check if compression is enabled
	if IsJWTCompressionEnabled() {
		components, err := DecomposeJWT(jwtToken)
		if err != nil {
			log.Warnf("Failed to decompose JWT for stream, using full token: %v", err)
			ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+jwtToken)
        } else {
			// Forward as compressed headers: raw JSON payload + signature
			ctx = metadata.AppendToOutgoingContext(ctx,
				"x-jwt-payload", components.Payload,
				"x-jwt-sig", components.Signature)
		}
    } else {
		// JWT COMPRESSION DISABLED: Forward as standard authorization header
		ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+jwtToken)
	}

	return streamer(ctx, desc, cc, method, opts...)
}