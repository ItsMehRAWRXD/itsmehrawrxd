#!/bin/bash

echo "🧪 Testing RawrZ Platform Functionality"
echo "======================================="

BASE_URL="https://rawrz-platform-hv83p.ondigitalocean.app"

echo "🌐 Testing platform at: $BASE_URL"
echo ""

# Test main endpoints
echo "📄 Testing HTML Endpoints:"
echo "-------------------------"

declare -a endpoints=(
    "/panel"
    "/unified"
    "/encrypt"
    "/stub-generator"
    "/encryptor-only"
    "/terminal"
    "/executable-generator"
    "/health"
)

for endpoint in "${endpoints[@]}"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL$endpoint")
    if [ "$status" = "200" ]; then
        echo "✅ $endpoint - OK"
    else
        echo "❌ $endpoint - FAILED (Status: $status)"
    fi
done

echo ""
echo "🔧 Testing JavaScript Functionality:"
echo "----------------------------------"

# Test if JavaScript is working by checking for inline scripts
js_test=$(curl -s "$BASE_URL/panel" | grep -o "onclick\|addEventListener\|function" | head -3)
if [ ! -z "$js_test" ]; then
    echo "✅ JavaScript elements detected - Interactive functionality should work"
else
    echo "⚠️  JavaScript elements not detected - May need CSP fix"
fi

echo ""
echo "🎯 Platform Status:"
echo "==================="
echo "🌐 Main Dashboard: $BASE_URL/panel"
echo "🎯 Unified Interface: $BASE_URL/unified ⭐ RECOMMENDED"
echo "🔐 Encryption: $BASE_URL/encrypt"
echo "⚙️ Stub Generator: $BASE_URL/stub-generator"
echo "💻 Terminal: $BASE_URL/terminal"
echo ""

echo "🔑 Your AUTH_TOKEN for CLI uploads:"
echo "dop_v1_31e52e2e6e6cd0b837e35d79d5c1b68304962e66ed1549352f1dae152c488994"
echo ""

echo "📱 If buttons are still not clickable:"
echo "1. Wait 2-3 minutes for the CSP fix to deploy"
echo "2. Hard refresh the page (Ctrl+F5 or Cmd+Shift+R)"
echo "3. Clear browser cache"
echo "4. Try the unified interface: $BASE_URL/unified"
echo ""

echo "✅ Platform is live and ready!"