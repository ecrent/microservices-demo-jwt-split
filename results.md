
Comparing:
  ENABLED:  jwt-compression-results-on-150-20251206_215041
  DISABLED: jwt-compression-results-off-150-20251206_221314

======================================================================
  K6 Load Test Results
======================================================================

--- ENABLED ---
  Iterations:        434
  Rate:              1.24 iter/s
  Data sent:         6279.70 KB (6430413 bytes)
  Data received:     41416.35 KB (42410344 bytes)
  Avg response time: 20.40 ms
  P95 response time: 76.01 ms
  P99 response time: 0.00 ms
  Failed requests:   0 (0.00%)
  Passed checks:     2965
  Failed checks:     0

--- DISABLED ---
  Iterations:        410
  Rate:              1.17 iter/s
  Data sent:         6190.40 KB (6338969 bytes)
  Data received:     40684.70 KB (41661136 bytes)
  Avg response time: 35.85 ms
  P95 response time: 82.34 ms
  P99 response time: 0.00 ms
  Failed requests:   0 (0.00%)
  Passed checks:     2961
  Failed checks:     0

======================================================================
  Performance Improvements
======================================================================

Data Sent (Upload):
  Compression OFF:   6338969 bytes
  Compression ON:    6430413 bytes
  Bytes difference:  -91444 bytes

Data Received (Download):
  Compression OFF:   41661136 bytes
  Compression ON:    42410344 bytes
  Bytes difference:  -749208 bytes

Response Time:
  Compression OFF:   35.85 ms (avg), 82.34 ms (p95)
  Compression ON:    20.40 ms (avg), 76.01 ms (p95)
  Avg improvement:   15.45 ms faster
  P95 improvement:   6.33 ms faster

======================================================================
  Network Traffic Analysis (PCAP)
======================================================================

--- ENABLED ---
  Total packets:     10068
  HTTP/2 packets:    7506
  Total traffic:     2996327 bytes (2926.10 KB)
  x-jwt-payload frames: 3753
  x-jwt-sig frames:     3753
  authorization frames: 0

  \033[0;36mHPACK Header Analysis:\033[0m
    x-jwt-payload size: ~1799 bytes (raw JSON)
    x-jwt-sig size:     ~1799 bytes (base64url)

--- DISABLED ---
  Total packets:     9867
  HTTP/2 packets:    7314
  Total traffic:     3336671 bytes (3258.47 KB)
  x-jwt-payload frames: 0
  x-jwt-sig frames:     0
  authorization frames: 3667

  \033[0;36mAuthorization Header Analysis:\033[0m
    authorization size: ~8359 bytes (full JWT)

Network Traffic Comparison:
  Traffic saved:     340344 bytes (332.37 KB)
  Reduction:         10.20%

======================================================================
  gRPC Latency Analysis (Frontend ↔ CartService)
======================================================================

--- ENABLED ---
  gRPC streams analyzed: 3701
  Latency (request → response):
    Min:     0.315 ms
    Avg:     1.101 ms
    P50:     0.591 ms
    P95:     1.336 ms
    P99:     2.525 ms
    Max:     726.841 ms

--- DISABLED ---
  gRPC streams analyzed: 3587
  Latency (request → response):
    Min:     0.317 ms
    Avg:     1.731 ms
    P50:     0.607 ms
    P95:     1.433 ms
    P99:     3.420 ms
    Max:     989.443 ms

gRPC Latency Comparison (Frontend → CartService):

  Metric       Compression ON Compression OFF   Difference
  ------       -------------- ---------------   ----------
  Avg                1.101 ms       1.731 ms 0.630 ms faster
  P50                0.591 ms       0.607 ms 0.016 ms faster
  P95                1.336 ms       1.433 ms 0.097 ms faster
  P99                2.525 ms       3.420 ms 0.895 ms faster

======================================================================
  JWT Header Analysis
======================================================================

Implementation Details:
  Compression ON (2-header format):
    • x-jwt-payload: Raw JSON payload (not base64 encoded)
    • x-jwt-sig:     Base64url signature only
    • JWT header:    Hardcoded constant (eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9)

  Compression OFF (standard format):
    • authorization: Bearer <header>.<payload>.<signature>

Header Usage Verification:
  Compression ON:
    • x-jwt-payload frames: 3753
    • x-jwt-sig frames:     3753
  Compression OFF:
    • authorization frames: 3667

======================================================================
  Summary
======================================================================

✓ JWT Compression Results (2-Header Format):

  📊 Data Transfer:
     • Upload bandwidth saved:   -1.44%
     • Download bandwidth saved: -1.80%
     • Total network reduction:  10.20%

  ⚡ Performance:
     • Average response time:    0.630 ms faster
     • P95 response time:        0.097 ms faster

  🔧 Implementation Optimizations:
     • Operations reduced:       14 → 2 (86% reduction)
     • Headers sent:             4 → 2 (50% reduction)
     • JWT header:               Hardcoded (eliminated from wire)
     • Payload encoding:         Raw JSON (vs base64)
For detailed packet analysis:
  wireshark jwt-compression-results-on-150-20251206_215041/frontend-cart-traffic.pcap &
  wireshark jwt-compression-results-off-150-20251206_221314/frontend-cart-traffic.pcap &
