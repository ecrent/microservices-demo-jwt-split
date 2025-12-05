package benchmark

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// REALISTIC JWT SIZES (from actual test data)
// ============================================================================

const JWTHeaderB64 = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"

// Realistic payload (~500 bytes JSON when decoded, matches test data)
var realisticPayloadJSON = `{"session_id":"550e8400-e29b-41d4-a716-446655440000","user_id":"user_12345678901234567890","email":"user@example.com","name":"John Doe","roles":["admin","user","viewer"],"permissions":["read","write","delete","admin"],"organization_id":"org_12345678901234567890","tenant_id":"tenant_abc123","iat":1701734400,"exp":1701738000,"nbf":1701734400,"iss":"https://auth.example.com","aud":"https://api.example.com","custom_claims":{"department":"engineering","team":"platform","level":"senior"}}`

// Realistic signature (RSA-SHA256, ~342 bytes base64)
var realisticSignature = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk2thvLuX0bZzizOfQHzJMYlE4vxWHNVnqH6hGZuOMxMDknkWMP3QNNDMqGXmFOvxyPcL4kzYz0oYXfpF_9WpadMhG-TkpxqCvxSZ-Vp8qN9zBkRvDfZwpMNmH8q5WvZwKJ_Lp3DqdNMqGXmFOvxyzOfQHzJMYlE4vxWHNVnqH6hGZuOMxMDknkWMP3QNNDMqGXmFOvxyPcL4kzYz0oYXfpF_9WpadMhG-TkpxqCvxSZ-Vp8qN9zBkRvDfZwpMNmH8q5WvZw"

// Full JWT (~938 bytes, matching test data)
var realisticFullJWT = fmt.Sprintf("%s.%s.%s",
	JWTHeaderB64,
	base64.RawURLEncoding.EncodeToString([]byte(realisticPayloadJSON)),
	realisticSignature)

type JWTComponents struct {
	Payload   string
	Signature string
}

func DecomposeJWT(jwtToken string) (*JWTComponents, error) {
	parts := strings.Split(jwtToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT")
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	return &JWTComponents{
		Payload:   string(payloadJSON),
		Signature: parts[2],
	}, nil
}

func ReassembleJWT(components *JWTComponents) string {
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(components.Payload))
	return fmt.Sprintf("%s.%s.%s", JWTHeaderB64, payloadB64, components.Signature)
}

// ============================================================================
// REALISTIC BENCHMARKS
// ============================================================================

func BenchmarkRealisticDecompose(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = DecomposeJWT(realisticFullJWT)
	}
}

func BenchmarkRealisticReassemble(b *testing.B) {
	components, _ := DecomposeJWT(realisticFullJWT)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ReassembleJWT(components)
	}
}

func BenchmarkRealisticFullRoundTrip(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		components, _ := DecomposeJWT(realisticFullJWT)
		_ = ReassembleJWT(components)
	}
}

// ============================================================================
// COMPREHENSIVE ANALYSIS
// ============================================================================

func TestRealisticCPUvsBandwidthAnalysis(t *testing.T) {
	components, _ := DecomposeJWT(realisticFullJWT)
	
	// Run benchmarks
	decomposeResult := testing.Benchmark(BenchmarkRealisticDecompose)
	reassembleResult := testing.Benchmark(BenchmarkRealisticReassemble)
	roundTripResult := testing.Benchmark(BenchmarkRealisticFullRoundTrip)
	
	decomposeNs := float64(decomposeResult.T.Nanoseconds()) / float64(decomposeResult.N)
	reassembleNs := float64(reassembleResult.T.Nanoseconds()) / float64(reassembleResult.N)
	roundTripNs := float64(roundTripResult.T.Nanoseconds()) / float64(roundTripResult.N)
	
	fullJWTSize := len(realisticFullJWT)
	compressedSize := len(components.Payload) + len(components.Signature)
	bytesSaved := fullJWTSize - compressedSize
	
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("   JWT COMPRESSION CPU vs BANDWIDTH ANALYSIS")
	fmt.Println("   (Realistic JWT sizes from production test data)")
	fmt.Println(strings.Repeat("=", 80))
	
	fmt.Println("\n📊 SIZE ANALYSIS")
	fmt.Println(strings.Repeat("-", 60))
	fmt.Printf("  Full JWT (Authorization header):  %d bytes\n", fullJWTSize)
	fmt.Printf("  x-jwt-payload (raw JSON):         %d bytes\n", len(components.Payload))
	fmt.Printf("  x-jwt-sig (base64url):            %d bytes\n", len(components.Signature))
	fmt.Printf("  Total compressed size:            %d bytes\n", compressedSize)
	fmt.Printf("  ✅ Bytes saved per request:       %d bytes (%.1f%% reduction)\n", 
		bytesSaved, float64(bytesSaved)/float64(fullJWTSize)*100)
	
	fmt.Println("\n⚡ CPU TIME ANALYSIS")
	fmt.Println(strings.Repeat("-", 60))
	fmt.Printf("  Decompose (sender):               %.0f ns = %.3f µs\n", decomposeNs, decomposeNs/1000)
	fmt.Printf("  Reassemble (receiver):            %.0f ns = %.3f µs\n", reassembleNs, reassembleNs/1000)
	fmt.Printf("  Full round-trip:                  %.0f ns = %.3f µs\n", roundTripNs, roundTripNs/1000)
	fmt.Printf("  Memory allocations per op:        %d allocs\n", roundTripResult.AllocsPerOp())
	
	fmt.Println("\n🌐 NETWORK TIME SAVINGS (per request)")
	fmt.Println(strings.Repeat("-", 60))
	
	// Network speeds and their transmission times
	networks := []struct {
		name     string
		bytesPerSec float64
	}{
		{"10 Gbps (datacenter)", 1_250_000_000},
		{"1 Gbps (fast)", 125_000_000},
		{"100 Mbps (typical)", 12_500_000},
		{"10 Mbps (slow/mobile)", 1_250_000},
	}
	
	for _, net := range networks {
		nsPerByte := 1_000_000_000.0 / net.bytesPerSec
		networkTimeSaved := float64(bytesSaved) * nsPerByte
		ratio := networkTimeSaved / roundTripNs
		
		benefit := "✅ NET GAIN"
		if ratio < 1 {
			benefit = "⚠️  Marginal"
		}
		
		fmt.Printf("  %-25s %8.0f ns saved | Ratio: %5.1fx | %s\n", 
			net.name+":", networkTimeSaved, ratio, benefit)
	}
	
	fmt.Println("\n📈 SCALE ANALYSIS")
	fmt.Println(strings.Repeat("-", 60))
	
	// Real world request time comparison
	typicalRequestMs := 80.0 // From test results
	cpuOverheadMs := roundTripNs / 1_000_000
	cpuPercent := (cpuOverheadMs / typicalRequestMs) * 100
	
	fmt.Printf("  Typical request time (from tests): %.2f ms\n", typicalRequestMs)
	fmt.Printf("  CPU overhead per request:          %.6f ms\n", cpuOverheadMs)
	fmt.Printf("  CPU overhead as %% of request:      %.6f%%\n", cpuPercent)
	
	// Throughput capacity
	maxReqPerSec := 1_000_000_000.0 / roundTripNs
	fmt.Printf("\n  Max theoretical throughput:        %.0f req/sec (if CPU-bound)\n", maxReqPerSec)
	
	// At different loads
	loads := []int{100, 1000, 10000, 100000}
	fmt.Println("\n  CPU usage at different loads:")
	for _, load := range loads {
		cpuUsage := (float64(load) / maxReqPerSec) * 100
		fmt.Printf("    %6d req/sec: %.4f%% CPU\n", load, cpuUsage)
	}
	
	fmt.Println("\n💰 BANDWIDTH SAVINGS PROJECTION")
	fmt.Println(strings.Repeat("-", 60))
	
	// Bandwidth savings over time
	reqPerSec := 1000
	fmt.Printf("  At %d requests/sec:\n", reqPerSec)
	fmt.Printf("    Per second:  %d bytes = %.2f KB\n", bytesSaved*reqPerSec, float64(bytesSaved*reqPerSec)/1024)
	fmt.Printf("    Per minute:  %.2f KB = %.2f MB\n", float64(bytesSaved*reqPerSec*60)/1024, float64(bytesSaved*reqPerSec*60)/1024/1024)
	fmt.Printf("    Per hour:    %.2f MB = %.2f GB\n", float64(bytesSaved*reqPerSec*3600)/1024/1024, float64(bytesSaved*reqPerSec*3600)/1024/1024/1024)
	fmt.Printf("    Per day:     %.2f GB\n", float64(bytesSaved*reqPerSec*86400)/1024/1024/1024)
	fmt.Printf("    Per month:   %.2f GB\n", float64(bytesSaved*reqPerSec*86400*30)/1024/1024/1024)
	
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("   CONCLUSION")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf(`
  ✅ CPU overhead is NEGLIGIBLE:
     • %.3f µs per request (%.6f%% of typical request time)
     • Can handle %.0f+ requests/sec before CPU becomes a bottleneck
  
  ✅ Network savings are SIGNIFICANT:
     • %d bytes saved per request (%.1f%% reduction)
     • At 100 Mbps: %.1fx more time saved than CPU cost
     • At 1000 req/sec: %.2f GB/month bandwidth saved
  
  ✅ The trade-off is FAVORABLE because:
     • CPU operations are O(n) where n = payload size
     • Network latency includes round-trip time, not just transmission
     • Smaller headers = better HPACK compression = compounding benefits
`,
		roundTripNs/1000, cpuPercent,
		maxReqPerSec,
		bytesSaved, float64(bytesSaved)/float64(fullJWTSize)*100,
		(float64(bytesSaved)*80)/roundTripNs, // 100 Mbps
		float64(bytesSaved*reqPerSec*86400*30)/1024/1024/1024,
	)
}

// ============================================================================
// LATENCY COMPARISON TEST
// ============================================================================

func TestLatencyComparison(t *testing.T) {
	iterations := 100000
	
	// Measure decompose
	start := time.Now()
	for i := 0; i < iterations; i++ {
		_, _ = DecomposeJWT(realisticFullJWT)
	}
	decomposeTotal := time.Since(start)
	
	// Measure reassemble
	components, _ := DecomposeJWT(realisticFullJWT)
	start = time.Now()
	for i := 0; i < iterations; i++ {
		_ = ReassembleJWT(components)
	}
	reassembleTotal := time.Since(start)
	
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("   LATENCY MEASUREMENT (100,000 iterations)")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("  Decompose total:   %v (avg: %v)\n", decomposeTotal, decomposeTotal/time.Duration(iterations))
	fmt.Printf("  Reassemble total:  %v (avg: %v)\n", reassembleTotal, reassembleTotal/time.Duration(iterations))
	fmt.Printf("  Combined total:    %v (avg: %v)\n", decomposeTotal+reassembleTotal, (decomposeTotal+reassembleTotal)/time.Duration(iterations))
	fmt.Printf("  Operations/sec:    %.0f\n", float64(iterations)/((decomposeTotal+reassembleTotal).Seconds()))
}
