#!/bin/bash

# Test script to validate error injection is working
# This script runs a simple load test and checks for injected errors

set -e

echo "======================================================================"
echo "  Testing Error Injection Feature"
echo "======================================================================"
echo ""

# Check if frontend service is accessible
if ! kubectl get deployment frontend > /dev/null 2>&1; then
    echo "Error: Frontend deployment not found"
    exit 1
fi

# Check if port-forward is already running
if ! pgrep -f "kubectl.*port-forward.*8080:80" > /dev/null; then
    echo "Starting port-forward to frontend service..."
    kubectl port-forward service/frontend 8080:80 > /dev/null 2>&1 &
    PORT_FORWARD_PID=$!
    sleep 3
    echo "Port-forward started (PID: ${PORT_FORWARD_PID})"
else
    echo "Port-forward already running"
    PORT_FORWARD_PID=""
fi

echo ""
echo "Running test requests to cart service (100 requests)..."
echo ""

SUCCESS_COUNT=0
ERROR_COUNT=0
INJECTED_ERROR_COUNT=0

# Get frontend pod name for live log monitoring
FRONTEND_POD=$(kubectl get pods -l app=frontend -o jsonpath='{.items[0].metadata.name}')

# Start tailing logs in background to capture retry and error injection activity
kubectl logs -f $FRONTEND_POD --tail=0 2>/dev/null | grep -E "ERROR-INJECTION|RETRY" > /tmp/test_logs.txt &
LOG_TAIL_PID=$!

for i in {1..100}; do
    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST http://localhost:8080/cart \
        -d "product_id=OLJCESPC7Z&quantity=1" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        --cookie-jar /tmp/test_cookies_$i.txt \
        --cookie /tmp/test_cookies_$i.txt 2>&1 || echo "000")
    
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    
    if [ "$HTTP_CODE" = "303" ] || [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "200" ]; then
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        echo "  Request $i: ✓ Success (HTTP $HTTP_CODE)"
    else
        ERROR_COUNT=$((ERROR_COUNT + 1))
        echo "  Request $i: ✗ Failed (HTTP $HTTP_CODE)"
        if [ "$HTTP_CODE" = "500" ]; then
            echo "             ^ Likely an injected error that exhausted all retries"
        fi
    fi
    
    # Small delay between requests
    sleep 0.1
done

# Stop log tailing
kill $LOG_TAIL_PID 2>/dev/null || true
sleep 1

echo "======================================================================"
echo "  Test Results"
echo "======================================================================"
echo ""
echo "Total Requests:   100"
echo "Successful:       $SUCCESS_COUNT"
echo "Failed:           $ERROR_COUNT"
echo "Success Rate:     $((SUCCESS_COUNT * 100 / 100))%"
echo "Failure Rate:     $((ERROR_COUNT * 100 / 100))%"
echo ""

# Check frontend logs for error injection messages
echo "Analyzing error injection and retry activity..."
echo ""

# Count error injections and retries from logs
ERROR_INJECTION_COUNT=$(kubectl logs $FRONTEND_POD --tail=500 | grep -c "ERROR-INJECTION.*Injecting" || echo "0")
RETRY_COUNT=$(kubectl logs $FRONTEND_POD --tail=500 | grep -c "RETRY.*Attempt" || echo "0")

echo "Error Injections:  $ERROR_INJECTION_COUNT (errors injected)"
echo "Retry Attempts:    $RETRY_COUNT (retries triggered)"
echo ""

if [ -f /tmp/test_logs.txt ]; then
    LIVE_ERROR_COUNT=$(grep -c "ERROR-INJECTION" /tmp/test_logs.txt || echo "0")
    LIVE_RETRY_COUNT=$(grep -c "RETRY" /tmp/test_logs.txt || echo "0")
    echo "During test run:"
    echo "  - Error injections detected: $LIVE_ERROR_COUNT"
    echo "  - Retry attempts detected:   $LIVE_RETRY_COUNT"
    echo ""
fi

if [ $ERROR_COUNT -gt 0 ] && [ $SUCCESS_COUNT -gt 0 ]; then
    echo "✓ Error injection with retry is working!"
    echo ""
    echo "Analysis:"
    echo "  - Errors were injected during the test"
    echo "  - Most errors were recovered by retry mechanism"
    echo "  - $ERROR_COUNT request(s) failed after exhausting all retries"
    echo "  - This simulates real-world transient network failures"
    echo ""
    echo "Sample error injection and retry logs:"
    kubectl logs $FRONTEND_POD --tail=100 | grep -E "ERROR-INJECTION|RETRY" | head -20
elif [ $ERROR_COUNT -gt 0 ] && [ $SUCCESS_COUNT -eq 0 ]; then
    echo "⚠ All requests failed - this may indicate a configuration issue,"
    echo "  not error injection working correctly."
elif [ $SUCCESS_COUNT -eq 100 ]; then
    if [ $ERROR_INJECTION_COUNT -gt 0 ]; then
        echo "✓ Retry mechanism is working perfectly!"
        echo ""
        echo "Analysis:"
        echo "  - $ERROR_INJECTION_COUNT errors were injected"
        echo "  - All injected errors were successfully recovered by retry"
        echo "  - This demonstrates resilience to transient failures"
        echo ""
        echo "Sample error injection and retry logs:"
        kubectl logs $FRONTEND_POD --tail=100 | grep -E "ERROR-INJECTION|RETRY" | head -20
    else
        echo "⚠ No errors were injected during the test."
        echo "  Error injection may not be enabled or the sample size is too small."
        echo ""
        echo "Current error injection settings:"
        kubectl get deployment frontend -o jsonpath='{.spec.template.spec.containers[0].env}' | grep -o 'ERROR[^}]*' || echo "  Not configured"
    fi
else
    echo "⚠ No errors were observed. Error injection may not be enabled or"
    echo "  the error rate is too low for this sample size."
    echo ""
    echo "Current error injection settings:"
    kubectl get deployment frontend -o jsonpath='{.spec.template.spec.containers[0].env}' | grep -o 'ERROR[^}]*' || echo "  Not configured"
fi

echo ""

# Cleanup
rm -f /tmp/test_cookies_*.txt
rm -f /tmp/test_logs.txt

# Stop port-forward if we started it
if [ ! -z "${PORT_FORWARD_PID}" ]; then
    echo "Stopping port-forward (PID: ${PORT_FORWARD_PID})..."
    kill ${PORT_FORWARD_PID} 2>/dev/null || true
fi

echo ""
echo "======================================================================"
echo "Test complete!"
echo "======================================================================"
