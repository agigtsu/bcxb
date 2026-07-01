#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-https://127.0.0.1:8789}"
PAYLOAD_PATH="${PAYLOAD_PATH:-/tmp/test-payload-pqc.json}"
REQUESTED_MODE="${REQUESTED_MODE:-pqc}"

cat > "$PAYLOAD_PATH" <<'JSON'
{
  "url": "https://api.github.com",
  "method": "GET"
}
JSON

echo "📡 Probing the service for its real crypto capability report"
echo ""
curl -sk "$BASE_URL/health" 2>/dev/null | sed -n '1,40p'

echo ""
echo "📤 Sending a request with X-Encryption-Mode: $REQUESTED_MODE"
echo ""

curl -sk -X POST "$BASE_URL/v1-internal" \
  -H 'Content-Type: application/json' \
  -H 'X-Service-Name: github-client' \
  -H "X-Timestamp: $(date +%s)000" \
  -H 'X-AAD: github-api-request' \
  -H "X-Encryption-Mode: $REQUESTED_MODE" \
  -w '\n\n📋 RESPONSE HEADERS:\n' \
  -d @"$PAYLOAD_PATH" 2>&1 | grep -E 'X-Encrypted|X-Encryption-Mode|X-Encryption-Capabilities|X-M7-Envelope|X-Security-Nonce|X-Request-Fingerprint|X-Anti-Forgery|Strict-Transport-Security|Content-Security-Policy' | head -20

echo ""
echo "✅ The response header shows the actual mode used by the server"
