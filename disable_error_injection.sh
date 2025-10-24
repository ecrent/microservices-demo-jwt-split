#!/bin/bash

# Script to disable error injection for cart service calls in frontend

set -e

echo "======================================================================"
echo "  Disabling Error Injection for Frontend → Cart Service"
echo "======================================================================"
echo ""

# Get current frontend deployment
DEPLOYMENT="frontend"

# Check if deployment exists
if ! kubectl get deployment ${DEPLOYMENT} > /dev/null 2>&1; then
    echo "Error: Deployment '${DEPLOYMENT}' not found"
    exit 1
fi

echo "Updating ${DEPLOYMENT} deployment to disable error injection..."

# Remove error injection environment variables
kubectl set env deployment/${DEPLOYMENT} \
    ENABLE_ERROR_INJECTION=false

echo ""
echo "Waiting for deployment to roll out..."
skaffold run

echo ""
echo "======================================================================"
echo "  ✓ Error Injection DISABLED"
echo "======================================================================"
echo ""
echo "The frontend service will now operate normally without injecting errors."
echo ""
