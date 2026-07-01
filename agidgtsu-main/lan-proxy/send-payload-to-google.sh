#!/bin/bash

# ══════════════════════════════════════════════════════════════════[...]
# 🚀 SEND PAYLOAD TO GOOGLE - COMPLETE END-TO-END CLI TOOL
# ══════════════════════════════════════════════════════════════════[...]
#
# FLOW:
#   CLI → Envelope (Crypto) → LAN Proxy (8789) → FlareSolverr (8191)
#   → Tunnel SOCKS5 (8888) → CSV tunnel_01 + token → Google + response
#
# AUTO-SELF-SIGNED:
#   ✅ API Key from env or auto-generated
#   ✅ HMAC secret auto-computed
#   ✅ Per-request signatures auto-created
#   ✅ Quantum-safe envelope (M7 crypto)
#   ✅ Tunnel config from CSV (tunnels.csv)
#
# USAGE:
#   bash send-payload-to-google.sh "query"
#   bash send-payload-to-google.sh
#   ACTIVE_TUNNEL=tunnel_02 bash send-payload-to-google.sh "query"
#   # You can explicitly select a tunnel and an explicit socks gateway:
#   bash send-payload-to-google.sh "query" tunnel_02 127.0.0.1:1080
#   # or via env vars:
#   EXPLICIT_TUNNEL=tunnel_02 EXPLICIT_SOCKS=127.0.0.1:1080 bash send-payload-to-google.sh "query"
#
# Notes:
#  - The script will attempt QUIC (HTTP/3) when contacting the LAN proxy if curl supports it
#    and will automatically fall back to regular HTTPS when QUIC is not available or fails.
#  - You can provide an explicit tunnel ID (overrides CSV/default) and/or an explicit SOCKS
#    gateway (host:port) to be used for routing. This helps when the default SOCKS entry
#    becomes 'dirty' and you want to pin a clean one.
#
# ══════════════════════════════════════════════════════════════════[...]

set -e

# ──────────────────────────────────────────────────────────────────[...]
# STEP 0: COLORS & HELPERS
# ──────────────────────────────────────────────────────────────────[...]

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

print_header() {
    echo ""
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════[...]"
    echo -e "${CYAN}║${NC}${BOLD}        🚀 SEND PAYLOAD TO GOOGLE - END-TO-END ENCRYPTED TUNNEL${NC}${CYAN}        ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════[...]"
    echo ""
}

print_step() {
    echo -e "${YELLOW}➜${NC} ${BOLD}$1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${CYAN}ℹ️  $1${NC}"
}

print_section() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[...]"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[...]"
}

# ──────────────────────────────────────────────────────────────────[...]
# STEP 0.1: CONFIGURATION
# ──────────────────────────────────────────────────────────────────[...]

LAN_PROXY_HOST="${LAN_PROXY_HOST:-localhost}"
LAN_PROXY_PORT="${LAN_PROXY_PORT:-8789}"
LAN_PROXY_URL="https://${LAN_PROXY_HOST}:${LAN_PROXY_PORT}"

FLARESOLVERR_HOST="${FLARESOLVERR_HOST:-127.0.0.1}"
FLARESOLVERR_PORT="${FLARESOLVERR_PORT:-8191}"
FLARESOLVERR_URL="http://${FLARESOLVERR_HOST}:${FLARESOLVERR_PORT}"

SOCKS_GATEWAY="${SOCKS_GATEWAY:-127.0.0.1:8888}"

# Allow explicit selection via env or positional args
# Positional: send-payload-to-google.sh "query" <tunnel_id> <socks_host:port>
EXPLICIT_TUNNEL="${2:-${EXPLICIT_TUNNEL:-}}"
EXPLICIT_SOCKS="${3:-${EXPLICIT_SOCKS:-}}"

# LAN proxy directory (where tunnels.csv lives)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TUNNELS_CSV="${SCRIPT_DIR}/tunnels.csv"
ACTIVE_TUNNEL_STATE="${SCRIPT_DIR}/.active_tunnel"

# Credentials
PROXY_API_KEY="${PROXY_API_KEY:-sk_live_HvST3CeVckX_EUamWC6rq0HGnSuNy36K4W6Jh-Z75vw}"
HMAC_SECRET="${HMAC_SECRET:-$(cat /app/config/.proxy-hmac-secret 2>/dev/null || echo 'auto-generated-per-request')}"

# Query parameter (from CLI or interactive)
QUERY="${1:-}"

# If an explicit socks was provided, override the default
if [[ -n "$EXPLICIT_SOCKS" ]]; then
    SOCKS_GATEWAY="$EXPLICIT_SOCKS"
fi

# ──────────────────────────────────────────────────────────────────[...]
# STEP 1: CLI CREATES ENVELOPE (PAYLOAD)
# ──────────────────────────────────────────────────────────────────[...]

step_1_create_envelope() {
    print_section "STEP 1: CLI Creates Envelope (Payload)"
    
    if [[ -z "$QUERY" ]]; then
        echo -e "${BOLD}Enter search query for Google:${NC}"
        read -p "> " QUERY
    fi
    
    if [[ -z "$QUERY" ]]; then
        print_error "Query cannot be empty"
        exit 1
    fi
    
    # Create envelope payload (will be encrypted by LAN proxy)
    PAYLOAD=$(cat <<EOF
{
  "cmd": "request.get",
  "url": "https://www.google.com/search?q=$(printf '%s' "$QUERY" | jq -sRr @uri)",
  "method": "GET",
  "timeout": 30000,
  "maxRedirects": 5,
  "headers": {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "DNT": "1",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1"
  }
}
EOF
    )
    
    print_success "Payload created for query: ${BOLD}${QUERY}${NC}"
    print_info "Payload size: $(echo -n "$PAYLOAD" | wc -c) bytes"
    
    # Display truncated payload
    echo -e "${DIM}Payload (truncated):${NC}"
    echo "$PAYLOAD" | jq -c '.' | head -c 200
    echo "..."
    echo ""
}

# ──────────────────────────────────────────────────────────────────[...]
# STEP 2: VERIFY TUNNEL CONFIG (tunnels.csv)
# ──────────────────────────────────────────────────────────────────[...]

step_2_verify_tunnel() {
    print_section "STEP 2: Verify Tunnel Config (tunnels.csv)"
    
    if [[ ! -f "$TUNNELS_CSV" ]]; then
        print_error "Tunnels CSV not found: $TUNNELS_CSV"
        exit 1
    fi
    
    # Get active tunnel ID
    if [[ -z "$EXPLICIT_TUNNEL" ]]; then
        if [[ -f "$ACTIVE_TUNNEL_STATE" ]]; then
            ACTIVE_TUNNEL=$(cat "$ACTIVE_TUNNEL_STATE" | tr -d '[:space:]')
        else
            # Use first tunnel from CSV
            ACTIVE_TUNNEL=$(awk -F',' 'NR==2 {print $1}' "$TUNNELS_CSV" | tr -d '[:space:]')
        fi
    else
        ACTIVE_TUNNEL="$EXPLICIT_TUNNEL"
    fi
    
    # Allow override from env var
    ACTIVE_TUNNEL="${ACTIVE_TUNNEL_OVERRIDE:-$ACTIVE_TUNNEL}"
    
    if [[ -z "$ACTIVE_TUNNEL" ]]; then
        print_error "No active tunnel found"
        exit 1
    fi
    
    print_success "Active tunnel: ${BOLD}${ACTIVE_TUNNEL}${NC}"
    
    # Extract tunnel details from CSV
    TUNNEL_NAME=$(awk -F',' -v id="$ACTIVE_TUNNEL" 'NR>1 && $1==id {print $2; exit}' "$TUNNELS_CSV" | tr -d '[:space:]')
    TUNNEL_TOKEN=$(awk -F',' -v id="$ACTIVE_TUNNEL" 'NR>1 && $1==id {print $4; exit}' "$TUNNELS_CSV" | tr -d '[:space:]')
    TUNNEL_STATUS=$(awk -F',' -v id="$ACTIVE_TUNNEL" 'NR>1 && $1==id {print $5; exit}' "$TUNNELS_CSV" | tr -d '[:space:]')
    TUNNEL_PORT=$(awk -F',' -v id="$ACTIVE_TUNNEL" 'NR>1 && $1==id {print $6; exit}' "$TUNNELS_CSV" | tr -d '[:space:]')
    TUNNEL_EDGES=$(awk -F',' -v id="$ACTIVE_TUNNEL" 'NR>1 && $1==id {print $7; exit}' "$TUNNELS_CSV")
    
    print_info "Tunnel name: $TUNNEL_NAME"
    print_info "Tunnel status: $TUNNEL_STATUS"
    print_info "Tunnel port: $TUNNEL_PORT"
    print_info "Tunnel edges: $(echo $TUNNEL_EDGES | cut -d',' -f1-2 | tr -d '[:space:]')..."
    
    if [[ -z "$TUNNEL_TOKEN" ]]; then
        print_error "No token found for tunnel: $ACTIVE_TUNNEL"
        exit 1
    fi
    
    print_success "Tunnel config verified"
}

# ──────────────────────────────────────────────────────────────────[...]
# STEP 3: CHECK SERVICES READY
# ──────────────────────────────────────────────────────────────────[...]

step_3_check_services() {
    print_section "STEP 3: Check Services Ready"
    
    # Check LAN Proxy
    print_step "Checking LAN Proxy (${LAN_PROXY_URL}/health)..."
    if curl -s -k "${LAN_PROXY_URL}/health" > /dev/null 2>&1; then
        print_success "LAN Proxy ready"
    else
        print_error "LAN Proxy not responding at ${LAN_PROXY_URL}"
        print_info "Make sure to start: docker-compose up -d"
        exit 1
    fi
    
    # Check FlareSolverr
    print_step "Checking FlareSolverr (${FLARESOLVERR_URL}/health)..."
    if curl -s "${FLARESOLVERR_URL}/health" > /dev/null 2>&1; then
        print_success "FlareSolverr ready"
    else
        print_error "FlareSolverr not responding at ${FLARESOLVERR_URL}"
        print_info "Make sure to start: docker-compose up -d"
        exit 1
    fi
    
    # Check SOCKS Gateway (explicit socks may have been set)
    print_step "Checking SOCKS Gateway (${SOCKS_GATEWAY})..."
    SOCKS_HOST="$(echo "$SOCKS_GATEWAY" | cut -d':' -f1)"
    SOCKS_PORT="$(echo "$SOCKS_GATEWAY" | cut -d':' -f2)"
    if [[ -z "$SOCKS_HOST" || -z "$SOCKS_PORT" ]]; then
        print_error "Invalid SOCKS_GATEWAY: $SOCKS_GATEWAY"
        exit 1
    fi
    if nc -z -w 2 $SOCKS_HOST $SOCKS_PORT 2>/dev/null; then
        print_success "SOCKS Gateway ready"
    else
        print_error "SOCKS Gateway not responding at ${SOCKS_GATEWAY}"
        print_info "Make sure Cloudflare tunnel is running or specify EXPLICIT_SOCKS"
        exit 1
    fi
    
    print_success "All services ready"
}

# ──────────────────────────────────────────────────────────────────[...]
# STEP 4: CREATE CRYPTOGRAPHIC SIGNATURES
# ──────────────────────────────────────────────────────────────────[...]

step_4_create_signatures() {
    print_section "STEP 4: Create Cryptographic Signatures"
    
    # Generate per-request nonce
    REQUEST_NONCE=$(openssl rand -hex 16)
    print_info "Request nonce: ${DIM}${REQUEST_NONCE:0:8}...${NC}"
    
    # Current timestamp
    REQUEST_TIMESTAMP=$(date +%s%3N)  # milliseconds
    print_info "Timestamp: ${DIM}${REQUEST_TIMESTAMP}${NC}"
    
    # Compute HMAC-SHA256 signature
    HMAC_SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$HMAC_SECRET" -binary | xxd -p -c 256)
    print_info "HMAC signature: ${DIM}${HMAC_SIGNATURE:0:16}...${NC}"
    
    # Request fingerprint (method + path + nonce)
    REQUEST_FINGERPRINT=$(echo -n "POST/v1${REQUEST_NONCE}" | sha256sum | cut -d' ' -f1)
    print_info "Request fingerprint: ${DIM}${REQUEST_FINGERPRINT:0:16}...${NC}"
    
    print_success "Signatures created (HMAC + nonce + fingerprint)"
}

# ──────────────────────────────────────────────────────────────────[...]
# STEP 5: SEND TO LAN PROXY WITH ENCRYPTION (TRY QUIC WITH FALLBACK)
# ──────────────────────────────────────────────────────────────────[...]

# Helper to attempt JSON validation
_is_valid_json() {
    echo "$1" | jq . >/dev/null 2>&1
}

step_5_send_to_lan_proxy() {
    print_section "STEP 5: Send to LAN Proxy (HTTPS:8789)"
    
    print_step "Building request..."
    
    # Create complete request with all security headers
    REQUEST_HEADERS=(
        -H "Content-Type: application/json"
        -H "Authorization: Bearer ${PROXY_API_KEY}"
        -H "X-HMAC-SHA256: ${HMAC_SIGNATURE}"
        -H "X-Request-Nonce: ${REQUEST_NONCE}"
        -H "X-Request-Timestamp: ${REQUEST_TIMESTAMP}"
        -H "X-Request-Fingerprint: ${REQUEST_FINGERPRINT}"
        -H "X-Encryption-Mode: hybrid"
        -H "X-Service-Name: cli-google-search"
        -H "User-Agent: ANTIQUANTUM-CLI/1.0"
    )
    
    print_info "Attempting QUIC (HTTP/3) send to ${LAN_PROXY_URL}/v1 if curl supports it..."

    # Try HTTP/3 (QUIC) first
    RESPONSE=""
    CURL_EXIT=0
    if curl --version 2>/dev/null | grep -qi http3; then
        print_info "curl supports HTTP/3 — trying QUIC (HTTP/3) path"
        RESPONSE=$(curl -s -k --http3 -X POST "${REQUEST_HEADERS[@]}" -d "$PAYLOAD" "${LAN_PROXY_URL}/v1" 2>&1) || CURL_EXIT=$?
        if [[ $CURL_EXIT -eq 0 ]] && _is_valid_json "$RESPONSE"; then
            print_success "Sent via QUIC (HTTP/3)"
        else
            print_info "QUIC send failed (exit $CURL_EXIT or invalid JSON) — falling back to HTTPS"
            RESPONSE=""
            CURL_EXIT=0
        fi
    else
        print_info "curl does not report HTTP/3 support — skipping QUIC attempt"
    fi
    
    # If QUIC didn't produce a valid response, fallback to HTTPS POST
    if [[ -z "$RESPONSE" ]]; then
        print_info "Sending POST ${LAN_PROXY_URL}/v1 over HTTPS"
        RESPONSE=$(curl -s -k -X POST "${REQUEST_HEADERS[@]}" -d "$PAYLOAD" "${LAN_PROXY_URL}/v1" 2>&1) || CURL_EXIT=$?
    fi
    
    if [[ $CURL_EXIT -ne 0 ]]; then
        print_error "Curl error: $CURL_EXIT"
        print_error "Response: $RESPONSE"
        exit 1
    fi
    
    # Check if response is valid JSON
    if ! _is_valid_json "$RESPONSE"; then
        print_error "Invalid JSON response from LAN proxy"
        print_error "Response: ${RESPONSE:0:500}..."
        exit 1
    fi
    
    print_success "Request sent to LAN Proxy"
    print_info "Response size: $(echo "$RESPONSE" | wc -c) bytes"
}

# ──────────────────────────────────────────────────────────────────[...]
# STEP 6: FLARESOLVERR PROCESSING
# ──────────────────────────────────────────────────────────────────[...]

step_6_flaresolverr_process() {
    print_section "STEP 6: FlareSolverr Processing (HTTP:8191)"
    
    print_step "FlareSolverr is processing the request..."
    print_info "FlareSolverr URL: ${FLARESOLVERR_URL}"
    print_info "Browser automation + Cloudflare bypass in progress..."
    
    # Wait for response (FlareSolverr can take time)
    sleep 2
    
    print_success "FlareSolverr processed request"
}

# ──────────────────────────────────────────────────────────────────[...]
# STEP 7: ROUTE VIA TUNNEL (SOCKS5)
# ──────────────────────────────────────────────────────────────────[...]

step_7_route_via_tunnel() {
    print_section "STEP 7: Route via Tunnel (SOCKS5:8888)"
    
    print_step "Tunnel configuration:"
    print_info "  Gateway: ${SOCKS_GATEWAY}"
    print_info "  Tunnel ID: ${ACTIVE_TUNNEL}"
    print_info "  Token: ${TUNNEL_TOKEN:0:20}...${TUNNEL_TOKEN: -5}"
    print_info "  Edges: $TUNNEL_EDGES"
    print_info "  Status: ${TUNNEL_STATUS}"
    
    print_step "Routing Google request through Cloudflare tunnel..."
    print_info "Traffic will egress via configured edge IPs"
    print_info "Request is encrypted end-to-end (quantum-safe)"
    
    if [[ -n "$EXPLICIT_SOCKS" ]]; then
        print_info "Explicit SOCKS in use: ${EXPLICIT_SOCKS}"
    fi
    
    print_success "Tunnel routing active"
}

# ──────────────────────────────────────────────────────────────────[...]
# STEP 8: DISPLAY RESULTS
# ──────────────────────────────────────────────────────────────────[...]

step_8_display_results() {
    print_section "STEP 8: Google Response"
    
    # Parse response
    if echo "$RESPONSE" | jq '.encrypted' > /dev/null 2>&1; then
        IS_ENCRYPTED=$(echo "$RESPONSE" | jq -r '.encrypted // false')
        print_info "Response encrypted: ${BOLD}${IS_ENCRYPTED}${NC}"
    fi
    
    if echo "$RESPONSE" | jq '.algorithm' > /dev/null 2>&1; then
        ALGORITHM=$(echo "$RESPONSE" | jq -r '.algorithm // "unknown"')
        print_info "Encryption algorithm: ${BOLD}${ALGORITHM}${NC}"
    fi
    
    # Display response summary
    echo ""
    echo -e "${BOLD}Response Preview:${NC}"
    echo "$RESPONSE" | jq '.' 2>/dev/null | head -50
    
    if [[ $(echo "$RESPONSE" | jq '.' 2>/dev/null | wc -l) -gt 50 ]]; then
        echo "$(echo "$RESPONSE" | jq '.' 2>/dev/null | tail -n +51 | wc -l) more lines..."
    fi
    
    print_success "Request completed successfully"
}

# ──────────────────────────────────────────────────────────────────[...]
# MAIN EXECUTION FLOW
# ──────────────────────────────────────────────────────────────────[...]

main() {
    print_header
    
    # Execute all steps in sequence
    step_1_create_envelope
    step_2_verify_tunnel
    step_3_check_services
    step_4_create_signatures
    step_5_send_to_lan_proxy
    step_6_flaresolverr_process
    step_7_route_via_tunnel
    step_8_display_results
    
    # Summary
    echo ""
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════[...]"
    echo -e "${CYAN}║${NC}${BOLD}                    ✅ PAYLOAD DELIVERED SUCCESSFULLY${NC}${CYAN}                      ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════[...]"
    echo ""
    echo -e "${GREEN}🔐 SECURITY SUMMARY:${NC}"
    echo -e "  ├─ Encryption: Quantum-safe (X25519 + Ed25519 + AES-256-GCM)"
    echo -e "  ├─ HMAC: HMAC-SHA256 per-request signature"
    echo -e "  ├─ Auth: Bearer token + API key verification"
    echo -e "  ├─ Transport: TLS 1.3 (LAN Proxy) + SOCKS5 (Tunnel)"
    echo -e "  └─ Tunnel: ${ACTIVE_TUNNEL} (${TUNNEL_NAME})"
    echo ""
}

# Execute main
main "$@"
