#!/bin/bash
set -euo pipefail

echo '🔍 Security Headers Audit'
echo '========================'

URL="https://localhost:8789/health"

REQUIRED_HEADERS=(
  'X-Frame-Options'
  'X-Content-Type-Options'
  'X-XSS-Protection'
  'Strict-Transport-Security'
  'Content-Security-Policy'
  'Referrer-Policy'
)

RESPONSE=$(curl -k -s -I "$URL" 2>&1 || true)
for HEADER in "${REQUIRED_HEADERS[@]}"; do
  if echo "$RESPONSE" | grep -qi "$HEADER"; then
    VALUE=$(echo "$RESPONSE" | grep -i "$HEADER" | head -1 | cut -d' ' -f2-)
    echo "✅ $HEADER: $VALUE"
  else
    echo "❌ $HEADER: MISSING"
  fi
done

echo ''
echo 'Full headers:'
curl -k -s -I "$URL"
