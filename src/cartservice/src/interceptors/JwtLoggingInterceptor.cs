using System;
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
                    // Reassemble JWT (not used currently, but available for future validation)
                    _ = ReassembleJWT(payloadHeader.Value, sigHeader.Value);
                }
            }
            // Standard format handled implicitly (no action needed)

            return await continuation(request, context);
        }

        /// <summary>
        /// Reassemble JWT from raw JSON payload and signature.
        /// Operations: 1 base64 encode (payload only)
        /// </summary>
        private string ReassembleJWT(string payloadJson, string signature)
        {
            // Base64Url encode the raw JSON payload - ONLY OPERATION
            string payloadB64 = Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));

            // Reconstruct JWT using hardcoded header constant
            return $"{JWTHeaderB64}.{payloadB64}.{signature}";
        }

        private string Base64UrlEncode(byte[] input)
        {
            string base64 = Convert.ToBase64String(input);
            // Convert to Base64Url format (remove padding and replace characters)
            return base64.TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }
    }
}
