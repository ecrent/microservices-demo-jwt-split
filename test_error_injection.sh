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
echo "Running test requests to cart service (20 requests)..."
echo ""

SUCCESS_COUNT=0
ERROR_COUNT=0
INJECTED_ERROR_COUNT=0

for i in {1..20}; do
    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST http://localhost:8080/cart \
        -d "product_id=OLJCESPC7Z&quantity=1" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        --cookie-jar /tmp/test_cookies_$i.txt \
        --cookie /tmp/test_cookies_$i.txt 2>&1 || echo "000")
    
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    
    if [ "$HTTP_CODE" = "303" ] || [ "$HTTP_CODE" = "200" ]; then
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        echo "  Request $i: ✓ Success (HTTP $HTTP_CODE)"
    else
        ERROR_COUNT=$((ERROR_COUNT + 1))
        echo "  Request $i: ✗ Failed (HTTP $HTTP_CODE)"
    fi
    
    # Small delay between requests
    sleep 0.1
done

echo ""
echo "======================================================================"
echo "  Test Results"
echo "======================================================================"
echo ""
echo "Total Requests:   20"
echo "Successful:       $SUCCESS_COUNT"
echo "Failed:           $ERROR_COUNT"
echo "Success Rate:     $(echo "scale=1; $SUCCESS_COUNT * 100 / 20" | bc)%"
echo "Failure Rate:     $(echo "scale=1; $ERROR_COUNT * 100 / 20" | bc)%"
echo ""

# Check frontend logs for error injection messages
echo "Checking frontend logs for error injection activity..."
echo ""
FRONTEND_POD=$(kubectl get pods -l app=frontend -o jsonpath='{.items[0].metadata.name}')
INJECTION_LOGS=$(kubectl logs $FRONTEND_POD --tail=100 | grep -c "ERROR-INJECTION" || echo "0")

echo "Found $INJECTION_LOGS error injection log entries in frontend pod"
echo ""

if [ $ERROR_COUNT -gt 0 ]; then
    echo "✓ Error injection appears to be working!"
    echo ""
    echo "Sample error injection logs:"
    kubectl logs $FRONTEND_POD --tail=50 | grep "ERROR-INJECTION" | tail -5
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

# Stop port-forward if we started it
if [ ! -z "${PORT_FORWARD_PID}" ]; then
    echo "Stopping port-forward (PID: ${PORT_FORWARD_PID})..."
    kill ${PORT_FORWARD_PID} 2>/dev/null || true
fi

echo ""
echo "Test complete!"
