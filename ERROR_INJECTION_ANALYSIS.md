# Frontend Error Handling and Retry Analysis

## Executive Summary

**Answer: NO, the frontend service does NOT have retry logic for failed gRPC calls.**

When a POST request (like adding items to cart) fails, the error is immediately returned to the user without any retry attempts.

---

## Current Error Handling Flow

### 1. **User Action** (e.g., Add to Cart)
```
User clicks "Add to Cart" → HTTP POST /cart
```

### 2. **Frontend Handler** (`addToCartHandler`)
```go
func (fe *frontendServer) addToCartHandler(w http.ResponseWriter, r *http.Request) {
    // ... validation ...
    
    // Makes gRPC call to Cart Service (NO RETRY)
    if err := fe.insertCart(r.Context(), sessionID(r), p.GetId(), int32(payload.Quantity)); err != nil {
        // IMMEDIATELY returns error to user - NO RETRY
        renderHTTPError(log, r, w, errors.Wrap(err, "failed to add to cart"), http.StatusInternalServerError)
        return
    }
    
    // Success: redirect to cart page
    w.Header().Set("location", baseUrl + "/cart")
    w.WriteHeader(http.StatusFound)
}
```

### 3. **gRPC Call** (`insertCart` → `CartService.AddItem`)
```go
func (fe *frontendServer) insertCart(ctx context.Context, userID, productID string, quantity int32) error {
    // Direct gRPC call - NO RETRY LOGIC
    _, err := pb.NewCartServiceClient(fe.cartSvcConn).AddItem(ctx, &pb.AddItemRequest{
        UserId: userID,
        Item: &pb.CartItem{
            ProductId: productID,
            Quantity:  quantity
        },
    })
    return err
}
```

### 4. **Error Rendering**
```go
func renderHTTPError(log logrus.FieldLogger, r *http.Request, w http.ResponseWriter, err error, code int) {
    log.WithField("error", err).Error("request error")
    errMsg := fmt.Sprintf("%+v", err)
    
    w.WriteHeader(code)  // Returns 500 Internal Server Error
    
    // Shows error page to user
    templates.ExecuteTemplate(w, "error", map[string]interface{}{
        "error":       errMsg,
        "status_code": code,
        "status":      http.StatusText(code),
    })
}
```

---

## What Happens When Error Injection is Enabled

### Scenario: User tries to add item to cart with 30% error rate

```
┌─────────────┐
│    USER     │
│  Clicks     │
│ "Add to     │
│  Cart"      │
└──────┬──────┘
       │
       │ HTTP POST /cart
       │
       v
┌─────────────────────────────────────────────────┐
│         Frontend Service (addToCartHandler)     │
│                                                  │
│  1. Validates input                              │
│  2. Gets product details                         │
│  3. Calls insertCart() → gRPC to CartService     │
└──────────────┬──────────────────────────────────┘
               │
               v
┌──────────────────────────────────────────────────┐
│    gRPC Interceptor Chain                        │
│                                                   │
│  ┌─────────────────────────────────────────┐    │
│  │  1. Error Injection Interceptor         │    │
│  │     (CART_ERROR_RATE=0.3)              │    │
│  │                                         │    │
│  │  → Random check: if rand() < 0.3       │    │
│  │     YES (30% chance):                   │    │
│  │       ✗ Return error immediately        │    │
│  │       ✗ DO NOT send to CartService      │    │
│  │       ✗ Error: "Simulated network       │    │
│  │           failure (UNAVAILABLE)"        │    │
│  │                                         │    │
│  │     NO (70% chance):                    │    │
│  │       ✓ Continue to next interceptor   │    │
│  └─────────────┬───────────────────────────┘    │
│                │ (70% of requests)               │
│  ┌─────────────v───────────────────────────┐    │
│  │  2. JWT Interceptor                     │    │
│  │     → Adds JWT headers                  │    │
│  └─────────────┬───────────────────────────┘    │
│                │                                 │
│  ┌─────────────v───────────────────────────┐    │
│  │  3. OpenTelemetry Interceptor           │    │
│  │     → Adds tracing                       │    │
│  └─────────────┬───────────────────────────┘    │
└────────────────┼─────────────────────────────────┘
                 │
                 │ gRPC call (70% succeed)
                 v
┌─────────────────────────────────────────────────┐
│         CartService (C#)                        │
│                                                  │
│  → Processes AddItem request                    │
│  → Returns success                              │
└─────────────────┬───────────────────────────────┘
                  │
                  │ Response
                  v
┌──────────────────────────────────────────────────┐
│         Frontend Service                         │
│                                                   │
│  IF ERROR (30%):                                 │
│    → renderHTTPError()                           │
│    → Return HTTP 500 to user                     │
│    → Show error page: "failed to add to cart"   │
│    → NO RETRY - User must click again           │
│                                                   │
│  IF SUCCESS (70%):                               │
│    → Redirect to /cart                           │
│    → HTTP 303 (See Other)                        │
└──────────────────┬───────────────────────────────┘
                   │
                   v
┌─────────────────────────────────────────────────┐
│              USER'S BROWSER                      │
│                                                   │
│  ERROR (30%): Shows error page                   │
│    "An error occurred: failed to add to cart     │
│     rpc error: code = Unavailable                │
│     desc = Simulated network failure"            │
│                                                   │
│  SUCCESS (70%): Redirected to cart page          │
│    Shows item in cart                            │
└──────────────────────────────────────────────────┘
```

---

## Impact on User Experience

### ❌ **With Error Injection Enabled (CART_ERROR_RATE=0.3)**

| Attempt | Outcome | User Experience |
|---------|---------|-----------------|
| 1st click | 30% chance of error | Error page shown, item NOT added |
| 2nd click | 30% chance of error | Error page shown, item NOT added |
| 3rd click | 30% chance of error | Error page shown, item NOT added |
| Eventually | Success | Item added to cart |

**User must manually retry by clicking "Add to Cart" again.**

### Why No Automatic Retry?

1. **No retry logic in handlers** - Errors are immediately returned to user
2. **No retry logic in gRPC client** - No `grpc.WithRetry()` or retry interceptor
3. **Short context timeout** - Only 3 seconds for gRPC dial context
4. **Stateless HTTP design** - Frontend doesn't track failed operations

---

## Comparison: Current State vs. Retry-Enabled

### Current Implementation (No Retry)
```go
// User clicks → Request → gRPC Call → Error → Show Error Page
//                                         ↓
//                               User must click again
```

**Characteristics:**
- ❌ Poor UX when errors occur
- ✅ Simple implementation
- ✅ Fast failure detection
- ❌ No resilience to transient failures

### If Retry Were Implemented
```go
// User clicks → Request → gRPC Call (Attempt 1) → Error
//                               ↓
//                         gRPC Call (Attempt 2) → Error
//                               ↓
//                         gRPC Call (Attempt 3) → Success!
//                               ↓
//                         Show success (user never saw errors)
```

**Would require:**
- Retry interceptor in gRPC client
- Exponential backoff logic
- Idempotency guarantees in CartService
- Timeout management

---

## Testing Error Injection

### 1. Enable Error Injection (30% failure rate)
```bash
./enable_error_injection.sh 0.3
```

### 2. User Flow Test
```bash
# Navigate to store
curl http://localhost:8080/

# Try to add item to cart
curl -X POST http://localhost:8080/cart \
  -d "product_id=OLJCESPC7Z&quantity=1" \
  -L -v

# Expected outcomes:
# - 30% of requests: HTTP 500 with error page
# - 70% of requests: HTTP 303 redirect to /cart
```

### 3. Observe Behavior
```bash
# Check frontend logs for injected errors
kubectl logs -f deployment/frontend | grep "ERROR_INJECTION"

# Example output:
# [ERROR_INJECTION] ⚠️  Injecting error for CartService.AddItem (failure rate: 30.0%)
# [ERROR_INJECTION] 💥 Simulated error: Unavailable - network failure
```

### 4. Disable Error Injection
```bash
./disable_error_injection.sh
```

---

## Key Findings

### ✅ What Works
1. **Error injection successfully simulates failures** at the gRPC layer
2. **Errors are logged** with clear messages
3. **Users see error pages** with descriptive messages
4. **No data corruption** - failed operations don't partially update state

### ❌ What's Missing
1. **No automatic retry logic** - users must manually retry
2. **No exponential backoff** - immediate failure
3. **No circuit breaker** - continues trying even if service is down
4. **No fallback mechanism** - no degraded mode

### 💡 Recommendations

If you want to improve resilience, consider adding:

1. **Client-side retry logic**
   ```go
   // Example: Retry up to 3 times with exponential backoff
   for i := 0; i < 3; i++ {
       err := fe.insertCart(ctx, ...)
       if err == nil {
           break // Success!
       }
       if i < 2 {
           time.Sleep(time.Duration(math.Pow(2, float64(i))) * 100 * time.Millisecond)
       }
   }
   ```

2. **gRPC retry policy** (via service config)
   ```go
   grpc.WithDefaultServiceConfig(`{
       "methodConfig": [{
           "name": [{"service": "hipstershop.CartService"}],
           "retryPolicy": {
               "maxAttempts": 3,
               "initialBackoff": "0.1s",
               "maxBackoff": "1s",
               "backoffMultiplier": 2,
               "retryableStatusCodes": ["UNAVAILABLE", "DEADLINE_EXCEEDED"]
           }
       }]
   }`)
   ```

3. **Circuit breaker pattern** (e.g., using `github.com/sony/gobreaker`)

---

## Conclusion

**The frontend service does NOT retry failed requests.** When error injection is enabled:

- ✅ Errors are successfully injected at the gRPC layer
- ✅ Users immediately see error pages
- ❌ No automatic retry - users must manually retry operations
- ❌ No resilience to transient failures

This makes error injection a **great testing tool** to:
- Validate error handling paths
- Test monitoring/alerting
- Measure impact of failures on user experience
- Identify services that need retry logic

**For production resilience, consider implementing retry logic at the gRPC client level.**
