#!/bin/bash

echo "🔍 Testing RawrZ Platform Endpoints"
echo "===================================="

BASE_URL="http://localhost:8080"

# Test HTML endpoints
echo ""
echo "📄 Testing HTML Endpoints:"
echo "-------------------------"

declare -a html_endpoints=(
    "/"
    "/panel"
    "/dashboard"
    "/main"
    "/home"
    "/unified"
    "/encrypt"
    "/advanced-encryption"
    "/stub-generator"
    "/stub-gen"
    "/encryptor-only"
    "/encryptor"
    "/executable-generator"
    "/payload-generator"
    "/terminal"
    "/cli"
    "/encryption-with-stubs"
    "/compact"
    "/ultra"
)

for endpoint in "${html_endpoints[@]}"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL$endpoint")
    if [ "$status" = "200" ]; then
        echo "✅ $endpoint - OK"
    else
        echo "❌ $endpoint - FAILED (Status: $status)"
    fi
done

# Test API endpoints
echo ""
echo "🔌 Testing API Endpoints:"
echo "-------------------------"

# Health check
health_status=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/health")
if [ "$health_status" = "200" ]; then
    echo "✅ /health - OK"
else
    echo "❌ /health - FAILED (Status: $health_status)"
fi

# Test API endpoints that don't require auth
declare -a api_endpoints=(
    "/api/list-generated-stubs"
    "/api/stub-info?stubName=test"
)

for endpoint in "${api_endpoints[@]}"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL$endpoint")
    if [ "$status" = "200" ] || [ "$status" = "400" ]; then
        echo "✅ $endpoint - OK (Status: $status)"
    else
        echo "❌ $endpoint - FAILED (Status: $status)"
    fi
done

# Test file upload endpoint
echo ""
echo "📤 Testing File Upload Endpoint:"
echo "-------------------------------"

# Create a test file
echo "test content" > test_file.txt

# Test file upload
upload_status=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    -F "file=@test_file.txt" \
    -F "algorithm=aes-256-gcm" \
    -F "extension=.encrypted" \
    -F "autoKey=true" \
    -F "saveKey=false" \
    -F "compress=false" \
    -F "obfuscate=false" \
    -F "stubType=basic" \
    -F "stubName=test" \
    "$BASE_URL/api/encrypt-file")

if [ "$upload_status" = "200" ]; then
    echo "✅ /api/encrypt-file - OK"
else
    echo "❌ /api/encrypt-file - FAILED (Status: $upload_status)"
fi

# Clean up test file
rm -f test_file.txt

# Test stub generation
echo ""
echo "🔧 Testing Stub Generation:"
echo "---------------------------"

stub_status=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    -H "Content-Type: application/json" \
    -d '{
        "name": "test-stub",
        "type": "basic",
        "platform": "windows",
        "compiler": "gcc",
        "options": {
            "obfuscate": false,
            "hotPatch": false
        }
    }' \
    "$BASE_URL/api/generate-stub")

if [ "$stub_status" = "200" ]; then
    echo "✅ /api/generate-stub - OK"
else
    echo "❌ /api/generate-stub - FAILED (Status: $stub_status)"
fi

# Test executable generation
echo ""
echo "⚙️ Testing Executable Generation:"
echo "---------------------------------"

exec_status=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    -H "Content-Type: application/json" \
    -d '{
        "name": "test-exe",
        "extension": ".exe",
        "platform": "windows",
        "type": "executable",
        "functionality": "http-bot",
        "code": "",
        "compiler": "gcc",
        "options": {}
    }' \
    "$BASE_URL/api/generate-executable")

if [ "$exec_status" = "200" ]; then
    echo "✅ /api/generate-executable - OK"
else
    echo "❌ /api/generate-executable - FAILED (Status: $exec_status)"
fi

echo ""
echo "🎯 Summary:"
echo "==========="
echo "All HTML endpoints should return 200 OK"
echo "API endpoints may return 200 (success) or 400 (expected error)"
echo "File upload and generation endpoints tested with sample data"
echo ""
echo "🌐 Access the platform at: $BASE_URL"
echo "🎯 Unified interface: $BASE_URL/unified"
echo "📊 Main dashboard: $BASE_URL/panel"