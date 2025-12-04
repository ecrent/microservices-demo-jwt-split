using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Grpc.Core;
using Grpc.Core.Interceptors;

namespace cartservice.interceptors
{
    public class JwtLoggingInterceptor : Interceptor
    {
        // JWT Header constant - RS256 algorithm, JWT type
        // Base64URL encoded: {"alg":"RS256","typ":"JWT"}
        private const string JWTHeaderB64 = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9";
        
        // Threshold for using stackalloc vs ArrayPool (512 bytes is safe for stack)
        private const int StackAllocThreshold = 512;

        private bool IsCompressionEnabled => 
            Environment.GetEnvironmentVariable("ENABLE_JWT_COMPRESSION") == "true";

        public override async Task<TResponse> UnaryServerHandler<TRequest, TResponse>(
            TRequest request,
            ServerCallContext context,
            UnaryServerMethod<TRequest, TResponse> continuation)
        {
            // Check for compressed JWT header (x-jwt-payload)
            var payloadHeader = context.RequestHeaders.FirstOrDefault(h => h.Key == "x-jwt-payload");
            if (payloadHeader != null)
            {
                // Compressed format: raw JSON payload + signature
                var sigHeader = context.RequestHeaders.FirstOrDefault(h => h.Key == "x-jwt-sig");
                
                if (sigHeader != null)
                {
                    // Reassemble JWT for validation/claims extraction
                    var jwt = ReassembleJWT(payloadHeader.Value, sigHeader.Value);
                    // JWT available for use (validation, claims, etc.)
                    _ = jwt;
                }
            }
            // Standard format: authorization header handled implicitly

            return await continuation(request, context);
        }

        /// <summary>
        /// Reassemble JWT from raw JSON payload and signature.
        /// Operations: 1 base64 encode (payload only)
        /// Optimized to minimize string allocations.
        /// </summary>
        private string ReassembleJWT(string payloadJson, string signature)
        {
            // Get payload bytes
            int byteCount = Encoding.UTF8.GetByteCount(payloadJson);
            
            // Use stackalloc for small payloads, ArrayPool for larger ones
            byte[]? rentedArray = null;
            Span<byte> payloadBytes = byteCount <= StackAllocThreshold 
                ? stackalloc byte[byteCount]
                : (rentedArray = ArrayPool<byte>.Shared.Rent(byteCount)).AsSpan(0, byteCount);
            
            try
            {
                Encoding.UTF8.GetBytes(payloadJson, payloadBytes);
                
                // Base64Url encode directly without intermediate strings
                string payloadB64 = Base64UrlEncodeOptimized(payloadBytes);
                
                // Use string.Create for efficient concatenation (single allocation)
                int totalLength = JWTHeaderB64.Length + 1 + payloadB64.Length + 1 + signature.Length;
                return string.Create(totalLength, (JWTHeaderB64, payloadB64, signature), (span, state) =>
                {
                    int pos = 0;
                    state.Item1.AsSpan().CopyTo(span);
                    pos += state.Item1.Length;
                    span[pos++] = '.';
                    state.Item2.AsSpan().CopyTo(span.Slice(pos));
                    pos += state.Item2.Length;
                    span[pos++] = '.';
                    state.Item3.AsSpan().CopyTo(span.Slice(pos));
                });
            }
            finally
            {
                if (rentedArray != null)
                {
                    ArrayPool<byte>.Shared.Return(rentedArray);
                }
            }
        }

        /// <summary>
        /// Optimized Base64Url encoding that minimizes allocations.
        /// Converts directly to Base64Url without intermediate string operations.
        /// </summary>
        private static string Base64UrlEncodeOptimized(ReadOnlySpan<byte> input)
        {
            // Calculate the base64 length (without padding)
            int base64Len = ((input.Length + 2) / 3) * 4;
            
            // For Base64Url, we remove padding, so actual length might be less
            int unpaddedLen = base64Len;
            int remainder = input.Length % 3;
            if (remainder == 1) unpaddedLen -= 2;
            else if (remainder == 2) unpaddedLen -= 1;
            
            // Use string.Create to build result directly
            return string.Create(unpaddedLen, input.ToArray(), (span, bytes) =>
            {
                // Convert to base64
                Span<char> base64Chars = stackalloc char[((bytes.Length + 2) / 3) * 4];
                Convert.TryToBase64Chars(bytes, base64Chars, out int charsWritten);
                
                // Copy and convert to Base64Url format in one pass
                int writePos = 0;
                for (int i = 0; i < charsWritten && writePos < span.Length; i++)
                {
                    char c = base64Chars[i];
                    if (c == '=') break; // Skip padding
                    span[writePos++] = c switch
                    {
                        '+' => '-',
                        '/' => '_',
                        _ => c
                    };
                }
            });
        }
    }
}
