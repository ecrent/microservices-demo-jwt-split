#!/bin/bash

# Script to enable error injection for cart service calls in frontend
# This simulates packet delivery failures and network issues

set -e

# Default values
ERROR_RATE=${1:-0.1}  # Default 10% error rate
ERROR_TYPE=${2:-unavailable}  # Default error type

echo "======================================================================"
echo "  Enabling Error Injection for Frontend → Cart Service"
echo "======================================================================"
echo ""
echo "Configuration:"
echo "  Error Rate: ${ERROR_RATE} ($(echo "$ERROR_RATE * 100" | bc)%)"
echo "  Error Type: ${ERROR_TYPE}"
echo ""
echo "Available error types:"
echo "  - unavailable       : Service unavailable (simulates connection issues)"
echo "  - timeout          : Request timeout (simulates slow network)"
echo "  - internal         : Internal server error"
echo "  - deadline_exceeded: Deadline exceeded"
echo "  - packet_loss      : Packet loss simulation"
echo "  - random           : Random error type for each failure"
echo ""

# Get current frontend deployment
DEPLOYMENT="frontend"

# Check if deployment exists
if ! kubectl get deployment ${DEPLOYMENT} > /dev/null 2>&1; then
    echo "Error: Deployment '${DEPLOYMENT}' not found"
    exit 1
fi

echo "Updating ${DEPLOYMENT} deployment with error injection settings..."

# Update environment variables
kubectl set env deployment/${DEPLOYMENT} \
    ENABLE_ERROR_INJECTION=true \
    ERROR_INJECTION_RATE=${ERROR_RATE} \
    ERROR_INJECTION_TYPE=${ERROR_TYPE} \
    ERROR_INJECTION_TARGET=CartService

echo ""
echo "Waiting for deployment to roll out..."
kubectl rollout status deployment/${DEPLOYMENT}

echo ""
echo "======================================================================"
echo "  ✓ Error Injection ENABLED"
echo "======================================================================"
echo ""
echo "The frontend service will now randomly fail ${ERROR_RATE} of cart"
echo "service calls with '${ERROR_TYPE}' errors."
echo ""
echo "To monitor errors in real-time:"
echo "  kubectl logs -f deployment/${DEPLOYMENT} | grep ERROR-INJECTION"
echo ""
echo "To disable error injection:"
echo "  ./disable_error_injection.sh"
echo ""
echo "Current environment variables:"
kubectl get deployment/${DEPLOYMENT} -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="ENABLE_ERROR_INJECTION")]}' | grep -o '"name":"[^"]*","value":"[^"]*"' || echo "  (checking...)"
echo ""
