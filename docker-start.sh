#!/bin/bash
# RawrZ Security Platform - Docker Startup Wrapper
# This script handles both "Npm" and "npm" commands for compatibility

set -e

echo "RawrZ Security Platform - Starting with Docker wrapper..."

# Check if this is being called as "Npm" or "npm"
if [[ "$0" == *"Npm"* ]] || [[ "${1:-}" == "Npm" ]]; then
    echo "Detected Npm command, redirecting to npm..."
    exec npm start
elif [[ "$0" == *"npm"* ]] || [[ "${1:-}" == "npm" ]]; then
    echo "Detected npm command, running npm start..."
    exec npm start
else
    echo "Starting application directly..."
    exec node api-server-no-cli.js
fi