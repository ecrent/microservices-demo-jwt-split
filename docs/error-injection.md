# Error Injection Feature

This feature allows you to simulate packet delivery failures and network issues between the frontend service and cart service gRPC calls for testing resilience and observing system behavior under failure conditions.

## Overview

The error injection system is implemented as a gRPC client interceptor in the frontend service that can artificially fail requests before they reach the cart service. This simulates various network and service failures including:

- Service unavailability
- Network timeouts
- Packet loss
- Connection failures
- Internal errors

## Architecture

```
┌──────────────┐                    ┌──────────────┐
│              │                    │              │
│   Frontend   │───────────────────▶│ Cart Service │
│              │  gRPC Call         │              │
│              │                    │              │
└──────────────┘                    └──────────────┘
       │
       │ Error Injection
       │ Interceptor
       │
       ▼
   [Randomly Fail X%]
   - Unavailable
   - Timeout
   - Internal Error
   - Packet Loss
```

## Configuration

Error injection is controlled via environment variables on the frontend deployment:

| Environment Variable | Description | Default | Example |
|---------------------|-------------|---------|---------|
| `ENABLE_ERROR_INJECTION` | Enable/disable error injection | `false` | `true` |
| `ERROR_INJECTION_RATE` | Failure rate (0.0 to 1.0) | `0.1` | `0.2` (20%) |
| `ERROR_INJECTION_TYPE` | Type of error to inject | `unavailable` | `timeout` |
| `ERROR_INJECTION_TARGET` | Target service(s) | `CartService` | `CartService,CheckoutService` |

### Error Types

- **`unavailable`**: Service unavailable (simulates connection issues)
- **`timeout`**: Request timeout (simulates slow network with 100ms delay)
- **`internal`**: Internal server error
- **`deadline_exceeded`**: Deadline exceeded
- **`packet_loss`**: Packet loss simulation
- **`connection_refused`**: Connection refused
- **`random`**: Randomly selects one of the above error types for each failure

### Target Services

You can target specific services or all services:

- **`CartService`**: Only inject errors for cart service calls (default)
- **`CheckoutService`**: Only inject errors for checkout service calls
- **`CartService,CheckoutService`**: Multiple services (comma-separated)
- **`all`**: Inject errors for all gRPC calls

## Usage

### Quick Start - Enable Error Injection

```bash
# Enable with default settings (10% failure rate, unavailable errors, CartService only)
./enable_error_injection.sh

# Enable with custom error rate (20% failures)
./enable_error_injection.sh 0.2

# Enable with custom error rate and type (30% failures, timeout errors)
./enable_error_injection.sh 0.3 timeout
```

### Manual Configuration

You can also manually configure error injection using kubectl:

```bash
# Enable error injection with 15% failure rate and random error types
kubectl set env deployment/frontend \
    ENABLE_ERROR_INJECTION=true \
    ERROR_INJECTION_RATE=0.15 \
    ERROR_INJECTION_TYPE=random \
    ERROR_INJECTION_TARGET=CartService

# Wait for rollout
kubectl rollout status deployment/frontend
```

### Disable Error Injection

```bash
# Disable error injection
./disable_error_injection.sh
```

### Testing Error Injection

```bash
# Run automated test to verify error injection is working
./test_error_injection.sh
```

## Monitoring

### View Error Injection Logs

Error injection events are logged with the `[ERROR-INJECTION]` prefix:

```bash
# Watch error injection in real-time
kubectl logs -f deployment/frontend | grep ERROR-INJECTION

# View last 50 error injection events
kubectl logs deployment/frontend --tail=100 | grep ERROR-INJECTION
```

Example log output:
```
[ERROR-INJECTION] Error injection is ENABLED
[ERROR-INJECTION] Configuration loaded - Rate: 10.0%, Type: unavailable, Target: CartService
[ERROR-INJECTION] 🔴 Injecting unavailable error for method: /hipstershop.CartService/AddItem
[ERROR-INJECTION] 🔴 Injecting timeout error for method: /hipstershop.CartService/GetCart
```

### View Current Configuration

```bash
# Check current error injection settings
kubectl get deployment frontend -o jsonpath='{.spec.template.spec.containers[0].env}' | jq
```

## Use Cases

### 1. Testing Resilience

Test how your application handles cart service failures:

```bash
# Enable 30% failure rate with unavailable errors
./enable_error_injection.sh 0.3 unavailable

# Run your load test
./run-jwt-compression-test.sh

# Analyze results
# - Did the frontend handle errors gracefully?
# - Were users shown appropriate error messages?
# - Did the system recover properly?
```

### 2. Testing Timeout Handling

Test timeout scenarios:

```bash
# Enable 20% failure rate with timeout errors
./enable_error_injection.sh 0.2 timeout

# Monitor frontend behavior
kubectl logs -f deployment/frontend
```

### 3. Chaos Engineering

Create realistic failure scenarios:

```bash
# Random errors at 15% rate
./enable_error_injection.sh 0.15 random

# Run extended load test
k6 run --duration 5m k6-user-journey-test.js
```

### 4. JWT Compression Testing Under Failures

Test JWT compression behavior when some requests fail:

```bash
# Enable error injection
./enable_error_injection.sh 0.1 unavailable

# Run JWT compression test
./run-jwt-compression-test.sh

# Compare HPACK behavior:
# - Does HPACK table stay consistent?
# - Do failed requests affect compression?
# - How do retries behave?
```

## Integration with k6 Load Tests

The error injection feature works seamlessly with existing k6 tests:

```bash
# 1. Enable error injection
./enable_error_injection.sh 0.1 unavailable

# 2. Run load test
k6 run k6-user-journey-test.js

# 3. Check metrics
# The k6 test will report failed requests in the http_req_failed metric
# Failed requests will show up in the summary
```

Example k6 output with error injection:
```
✗ add item with new JWT successful
  ↳  85% — ✓ 340 / ✗ 60
✓ http_req_failed....................: 10.2%  ✓ 102 ✗ 898
```

## Troubleshooting

### Error injection not working

1. **Check if enabled:**
   ```bash
   kubectl get deployment frontend -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="ENABLE_ERROR_INJECTION")].value}'
   ```

2. **Check logs for initialization:**
   ```bash
   kubectl logs deployment/frontend | grep "ERROR-INJECTION"
   ```

3. **Verify pod restart:**
   ```bash
   kubectl get pods -l app=frontend
   # Check the AGE column - should be recent
   ```

### All requests failing

If all requests are failing, the error rate might be too high or incorrectly set:

```bash
# Check current rate
kubectl get deployment frontend -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="ERROR_INJECTION_RATE")].value}'

# Lower the rate
./enable_error_injection.sh 0.05  # 5% instead of 100%
```

### No errors in logs

The error rate might be too low for small sample sizes:

```bash
# Increase error rate for testing
./enable_error_injection.sh 0.5  # 50% failure rate

# Or run more requests
for i in {1..100}; do curl -X POST http://localhost:8080/cart -d "product_id=OLJCESPC7Z&quantity=1"; done
```

## Implementation Details

The error injection feature is implemented in three files:

1. **`src/frontend/error_injection.go`**: Core error injection logic
   - Configuration loading
   - Random failure decision
   - Error generation
   - Interceptor implementation

2. **`src/frontend/main.go`**: Integration point
   - Adds error injection interceptor to gRPC client chain
   - Interceptor order: Error Injection → JWT → OpenTelemetry

3. **Scripts**: Management utilities
   - `enable_error_injection.sh`: Enable with configuration
   - `disable_error_injection.sh`: Disable error injection
   - `test_error_injection.sh`: Automated testing

## Performance Impact

When disabled (`ENABLE_ERROR_INJECTION=false` or not set):
- **Zero performance impact**: The interceptor performs a simple boolean check and returns immediately
- **No additional latency**: No random number generation or error logic execution

When enabled:
- **Minimal overhead**: ~1-2μs per request for random number generation and comparison
- **Negligible impact**: Much smaller than typical network latency (1-10ms)

## Security Considerations

- **Production Use**: Not recommended for production unless explicitly testing resilience
- **Access Control**: Ensure only authorized personnel can enable error injection
- **Monitoring**: Always monitor error injection settings to prevent accidental enablement

## Examples

### Example 1: Light Chaos Testing (5% failures)

```bash
./enable_error_injection.sh 0.05 random
k6 run --duration 2m k6-user-journey-test.js
./disable_error_injection.sh
```

### Example 2: Heavy Failure Testing (40% failures)

```bash
./enable_error_injection.sh 0.4 unavailable
./test_error_injection.sh
./disable_error_injection.sh
```

### Example 3: Timeout Scenario Testing

```bash
./enable_error_injection.sh 0.2 timeout
kubectl logs -f deployment/frontend | grep -E "(ERROR-INJECTION|timeout)"
./disable_error_injection.sh
```

## Future Enhancements

Possible future improvements:

- **Latency injection**: Add variable delays without failing requests
- **Partial failures**: Fail only specific gRPC methods (e.g., AddItem but not GetCart)
- **Time-based patterns**: Enable failures only during specific time windows
- **Metrics endpoint**: Expose error injection statistics via HTTP endpoint
- **Dynamic control**: Change settings without pod restart via ConfigMap

## Support

For issues or questions:
1. Check logs: `kubectl logs deployment/frontend | grep ERROR-INJECTION`
2. Verify configuration: `kubectl describe deployment frontend`
3. Review this documentation
