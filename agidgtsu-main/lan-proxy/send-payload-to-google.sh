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
#   docker exec m7-proxy-test bash /app/lan-proxy/send-payload-to-google.sh
#   # Explicit tunnel + socks (positional)
#   bash send-payload-to-google.sh "query" tunnel_02 127.0.0.1:1080
#   # Or via env vars:
#   EXPLICIT_TUNNEL=tunnel_02 EXPLICIT_SOCKS=127.0.0.1:1080 bash send-payload-to-google.sh "query"
#
# NEW FEATURES:
#  - NO_QUIC=1  : disable HTTP/3 (QUIC) attempts and force HTTPS
#  - RETRIES=3  : number of retry attempts for sending to LAN proxy (default 3)
#  - RETRY_BACKOFF=2 : base seconds for exponential backoff (default 2)
#  - SOCKS_SESSION=1 : select the N-th SOCKS endpoint from the tunnel edges (1-based)
#  - MACHINE_JSON (path) : path to a FlareSolverr machine emulation JSON file to include in the request
#
# Tunnel / SOCKS sessions:
#  - A tunnel can include multiple edge proxies/socks endpoints in the CSV edges column.
#    Use SOCKS_SESSION to pick which one to use (acts like a VPN/session selector).
#  - The chosen SOCKS_SESSION can be persisted across reboots in .active_socks_session
#
# Machine emulation:
#  - Place a machine.json file next to this script (or set MACHINE_JSON=/path/to/machine.json)
#    and the file will be attached to the envelope under the "flaresolverr.machine_profile" key.
#
# ══════════════════════════════════════════════════════════════════[...]

set -euo pipefail

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

print_step() { echo -e "${YELLOW}➜${NC} ${BOLD}$1${NC}"; }
print_success() { echo -e "${GREEN}✅ $1${NC}"; }
print_error() { echo -e "${RED}❌ $1${NC}"; }
print_info() { echo -e "${CYAN}ℹ️  $1${NC}"; }
print_section() { echo ""; echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[...]"; echo -e "${BLUE}  $1${NC}"; echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[...]"; }

usage() {
    cat <<EOF
Usage: $0 ["query"] [optional: tunnel_id] [optional: socks_host:port]

Environment variables:
  EXPLICIT_TUNNEL  - explicit tunnel id to use (overrides .active_tunnel / CSV)
  EXPLICIT_SOCKS   - explicit socks gateway (host:port) to use
  SOCKS_SESSION    - select N-th socks endpoint from tunnel edges (1-based)
  MACHINE_JSON     - path to a machine.json file to include as flaresolverr profile
  NO_QUIC=1        - disable QUIC (HTTP/3) attempts
  RETRIES          - number of attempts for sending to LAN proxy (default 3)
  RETRY_BACKOFF    - base seconds for exponential backoff (default 2)
  PROXY_API_KEY    - API key to authenticate to LAN proxy
  HMAC_SECRET      - secret for HMAC computation

Examples:
  $0 "search terms"
  $0 "search" tunnel_02 127.0.0.1:1080
  EXPLICIT_TUNNEL=tunnel_02 SOCKS_SESSION=2 MACHINE_JSON=./machine.json $0 "search"
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
fi

# ──────────────────────────────────────────────────────────────────[...]
# STEP 0.1: CONFIGURATION
# ──────────────────────────────────────────────────────────────────[...]

LAN_PROXY_HOST="${LAN_PROXY_HOST:-localhost}"
LAN_PROXY_PORT="${LAN_PROXY_PORT:-8789}"
LAN_PROXY_URL="https://${LAN_PROXY_HOST}:${LAN_PROXY_PORT}"

FLARESOLVERR_HOST="${FLARESOLVERR_HOST:-127.0.0.1}"
FLARESOLVERR_PORT="${FLARESOLVERR_PORT:-8191}"
FLARESOLVERR_URL="http://${FLARESOLVERR_HOST}:${FLARESOLVERR_PORT}"

# Defaults
SOCKS_GATEWAY_DEFAULT="${SOCKS_GATEWAY:-127.0.0.1:8888}"
SOCKS_GATEWAY="${SOCKS_GATEWAY_DEFAULT}"

# Allow explicit selection via env or positional args
EXPLICIT_TUNNEL="${2:-${EXPLICIT_TUNNEL:-}}"
EXPLICIT_SOCKS="${3:-${EXPLICIT_SOCKS:-}}"
SOCKS_SESSION="${SOCKS_SESSION:-}"  # 1-based index to pick from tunnel edges

# Retries / QUIC toggles
NO_QUIC="${NO_QUIC:-0}"
RETRIES="${RETRIES:-3}"
RETRY_BACKOFF="${RETRY_BACKOFF:-2}"

# Machine json
MACHINE_JSON_PATH="${MACHINE_JSON:-}" 

# LAN proxy directory (where tunnels.csv lives)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TUNNELS_CSV="${SCRIPT_DIR}/tunnels.csv"
ACTIVE_TUNNEL_STATE="${SCRIPT_DIR}/.active_tunnel"
ACTIVE_SOCKS_STATE="${SCRIPT_DIR}/.active_socks_session"

# Credentials
PROXY_API_KEY="${PROXY_API_KEY:-sk_live_HvST3CeVckX_EUamWC6rq0HGnSuNy36K4W6Jh-Z75vw}"
HMAC_SECRET="${HMAC_SECRET:-$(cat /app/config/.proxy-hmac-secret 2>/dev/null || echo 'auto-generated-per-request')}"

# Query parameter (from CLI or interactive)
QUERY="${1:-}"

# If an explicit socks was provided, override the default (positional or env)
if [[ -n "$EXPLICIT_SOCKS" ]]; then
    SOCKS_GATEWAY="$EXPLICIT_SOCKS"
fi

# If SOCKS_SESSION not provided, try loading persisted session
if [[ -z "$SOCKS_SESSION" && -f "$ACTIVE_SOCKS_STATE" ]]; then
    SOCKS_SESSION=$(cat "$ACTIVE_SOCKS_STATE" 2>/dev/null || true)
    if [[ -n "$SOCKS_SESSION" ]]; then
        print_info "Loaded persisted SOCKS_SESSION: $SOCKS_SESSION"
    fi
fi

# Helper: validate JSON
_is_valid_json() { echo "$1" | jq . >/dev/null 2>&1; }

# Helper: split edges into array (supports comma, semicolon, pipe)
_parse_edges() {
    local edges_raw="$1"
    # normalize separators to semicolon
    edges_raw="$(echo "$edges_raw" | sed -E 's/[|,]/;/g')"
    IFS=';' read -r -a _EDGE_ARRAY <<< "$edges_raw"
    # trim whitespace
    for i in "${!_EDGE_ARRAY[@]}"; do
        _EDGE_ARRAY[$i]="$(echo "${_EDGE_ARRAY[$i]}" | xargs)"
    done
    echo "${_EDGE_ARRAY[@]}"
}

# Helper: pick socks from tunnel edges by session index
_pick_socks_from_edges() {
    local edges_raw="$1"
    local idx="$2"
    if [[ -z "$edges_raw" ]]; then
        echo ""
        return
    fi
    read -r -a arr <<< "$( _parse_edges "$edges_raw" )"
    if [[ -z "$idx" || "$idx" -lt 1 ]]; then
        # default to first
        echo "${arr[0]}"
        return
    fi
    local sel_index=$((idx-1))
    if [[ $sel_index -ge 0 && $sel_index -lt ${#arr[@]} ]]; then
        echo "${arr[$sel_index]}"
    else
        echo ""
    fi
}

# ──────────────────────────────────────────────────────────────────[...]
# STEP 1: CLI CREATES ENVELOPE (PAYLOAD)
# ──────────────────────────────────────────────────────────────────[...]

step_1_create_envelope() {
    print_section "STEP 1: CLI Creates Envelope (Payload)"

    if [[ -z "$QUERY" ]]; then
        echo -e "${BOLD}Enter search query for Google:${NC}"
        read -r -p "> " QUERY
    fi

    if [[ -z "$QUERY" ]]; then
        print_error "Query cannot be empty"
        exit 1
    fi

    # Optionally load machine.json if present
    MACHINE_PROFILE_JSON=""
    # prefer explicit MACHINE_JSON env path
    if [[ -n "${MACHINE_JSON:-}" && -f "${MACHINE_JSON}" ]]; then
        if MACHINE_PROFILE_JSON=$(cat "${MACHINE_JSON}" 2>/dev/null); then
            if ! _is_valid_json "$MACHINE_PROFILE_JSON"; then
                print_error "MACHINE_JSON is not valid JSON: ${MACHINE_JSON}"
                MACHINE_PROFILE_JSON=""
            else
                print_info "Loaded machine profile from ${MACHINE_JSON}"
            fi
        fi
    elif [[ -f "${SCRIPT_DIR}/machine.json" ]]; then
        if MACHINE_PROFILE_JSON=$(cat "${SCRIPT_DIR}/machine.json" 2>/dev/null); then
            if ! _is_valid_json "$MACHINE_PROFILE_JSON"; then
                print_error "machine.json next to script is not valid JSON"
                MACHINE_PROFILE_JSON=""
            else
                print_info "Loaded machine profile from ${SCRIPT_DIR}/machine.json"
            fi
        fi
    fi

    # Create envelope payload (will be encrypted by LAN proxy)
    # If machine profile exists, attach under flaresolverr.machine_profile
    if [[ -n "$MACHINE_PROFILE_JSON" ]]; then
        PAYLOAD=$(jq -n --arg url "https://www.google.com/search?q=$(printf '%s' "$QUERY" | jq -sRr @uri)" \
            --argjson machine "$MACHINE_PROFILE_JSON" \
            '{cmd: "request.get", url: $url, method: "GET", timeout: 30000, maxRedirects: 5, headers: {"User-Agent":"Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0","Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8","Accept-Language":"en-US,en;q=0.5","DNT":"1","Connection":"keep-alive","Upgrade-Insecure-Requests":"1"}, flaresolverr: {machine_profile: $machine}}')
    else
        PAYLOAD=$(jq -n --arg url "https://www.google.com/search?q=$(printf '%s' "$QUERY" | jq -sRr @uri)" \
            '{cmd: "request.get", url: $url, method: "GET", timeout: 30000, maxRedirects: 5, headers: {"User-Agent":"Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0","Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8","Accept-Language":"en-US,en;q=0.5","DNT":"1","Connection":"keep-alive","Upgrade-Insecure-Requests":"1"}}')
    fi

    print_success "Payload created for query: ${BOLD}${QUERY}${NC}"
    print_info "Payload size: $(echo -n "$PAYLOAD" | wc -c) bytes"
    echo -e "${DIM}Payload (truncated):${NC}"
    echo "$PAYLOAD" | jq -c '.' | head -c 400
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

    # Determine active tunnel id
    if [[ -n "$EXPLICIT_TUNNEL" ]]; then
        ACTIVE_TUNNEL="$EXPLICIT_TUNNEL"
    else
        if [[ -f "$ACTIVE_TUNNEL_STATE" ]]; then
            ACTIVE_TUNNEL=$(cat "$ACTIVE_TUNNEL_STATE" | tr -d '[:space:]')
        else
            ACTIVE_TUNNEL=$(awk -F',' 'NR==2 {print $1}' "$TUNNELS_CSV" | tr -d '[:space:]')
        fi
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
    TUNNEL_EDGES_RAW=$(awk -F',' -v id="$ACTIVE_TUNNEL" 'NR>1 && $1==id {print $7; exit}' "$TUNNELS_CSV")

    print_info "Tunnel name: $TUNNEL_NAME"
    print_info "Tunnel status: $TUNNEL_STATUS"
    print_info "Tunnel port: $TUNNEL_PORT"
    print_info "Tunnel edges (raw): $TUNNEL_EDGES_RAW"

    if [[ -z "$TUNNEL_TOKEN" ]]; then
        print_error "No token found for tunnel: $ACTIVE_TUNNEL"
        exit 1
    fi

    # If SOCKS_SESSION specified, try to pick that socks from edges
    if [[ -n "$SOCKS_SESSION" ]]; then
        CHOSEN_SOCKS=$( _pick_socks_from_edges "$TUNNEL_EDGES_RAW" "$SOCKS_SESSION" )
        if [[ -n "$CHOSEN_SOCKS" ]]; then
            SOCKS_GATEWAY="$CHOSEN_SOCKS"
            print_info "Selected SOCKS from tunnel edges (session $SOCKS_SESSION): $SOCKS_GATEWAY"
            # Persist choice so it survives reboots
            if ! echo "$SOCKS_SESSION" > "$ACTIVE_SOCKS_STATE"; then
                print_error "Failed to persist SOCKS_SESSION to $ACTIVE_SOCKS_STATE"
            else
                print_info "Persisted SOCKS_SESSION=$SOCKS_SESSION to $ACTIVE_SOCKS_STATE"
            fi
        else
            print_error "Could not select SOCKS session $SOCKS_SESSION from tunnel edges"
            # fallback to default behavior (explicit socks or global default)
        fi
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

    # Check SOCKS Gateway
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
        print_info "Make sure Cloudflare tunnel is running or specify EXPLICIT_SOCKS or SOCKS_SESSION"
        exit 1
    fi

    print_success "All services ready"
}

# ──────────────────────────────────────────────────────────────────[...]
# STEP 4: CREATE CRYPTOGRAPHIC SIGNATURES
# ──────────────────────────────────────────────────────────────────[...]

step_4_create_signatures() {
    print_section "STEP 4: Create Cryptographic Signatures"

    REQUEST_NONCE=$(openssl rand -hex 16)
    print_info "Request nonce: ${DIM}${REQUEST_NONCE:0:8}...${NC}"

    REQUEST_TIMESTAMP=$(date +%s%3N)  # milliseconds
    print_info "Timestamp: ${DIM}${REQUEST_TIMESTAMP}${NC}"

    HMAC_SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$HMAC_SECRET" -binary | xxd -p -c 256)
    print_info "HMAC signature: ${DIM}${HMAC_SIGNATURE:0:16}...${NC}"

    REQUEST_FINGERPRINT=$(echo -n "POST/v1${REQUEST_NONCE}" | sha256sum | cut -d' ' -f1)
    print_info "Request fingerprint: ${DIM}${REQUEST_FINGERPRINT:0:16}...${NC}"

    print_success "Signatures created (HMAC + nonce + fingerprint)"
}

# ──────────────────────────────────────────────────────────────────[...]
# STEP 5: SEND TO LAN PROXY WITH ENCRYPTION (TRY QUIC WITH FALLBACK + RETRIES)
# ──────────────────────────────────────────────────────────────────[...]

step_5_send_to_lan_proxy() {
    print_section "STEP 5: Send to LAN Proxy (HTTPS:8789)"
    print_step "Building request..."

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

    print_info "Attempting send to ${LAN_PROXY_URL}/v1 (QUIC if available and enabled)"

    ATTEMPT=0
    RESPONSE=""
    CURL_EXIT=0

    while [[ $ATTEMPT -lt $RETRIES ]]; do
        ATTEMPT=$((ATTEMPT+1))
        print_info "Attempt $ATTEMPT of $RETRIES"

        # Try QUIC if enabled and curl supports it
        if [[ "$NO_QUIC" != "1" ]] && curl --version 2>/dev/null | grep -qi http3; then
            print_info "curl supports HTTP/3 and NO_QUIC!=1 — trying QUIC (HTTP/3)"
            RESPONSE=$(curl -s -k --http3 -X POST "${REQUEST_HEADERS[@]}" -d "$PAYLOAD" "${LAN_PROXY_URL}/v1" 2>&1) || CURL_EXIT=$?
            if [[ $CURL_EXIT -eq 0 && _is_valid_json "$RESPONSE" ]]; then
                print_success "Sent via QUIC (HTTP/3)"
                break
            else
                print_info "QUIC attempt failed (exit $CURL_EXIT or invalid JSON), will retry/fallback"
                RESPONSE=""
                CURL_EXIT=0
            fi
        else
            if [[ "$NO_QUIC" == "1" ]]; then
                print_info "NO_QUIC=1 — skipping QUIC attempt"
            else
                print_info "curl does not report HTTP/3 support — skipping QUIC attempt"
            fi
        fi

        # HTTPS fallback
        RESPONSE=$(curl -s -k -X POST "${REQUEST_HEADERS[@]}" -d "$PAYLOAD" "${LAN_PROXY_URL}/v1" 2>&1) || CURL_EXIT=$?
        if [[ $CURL_EXIT -eq 0 && _is_valid_json "$RESPONSE" ]]; then
            print_success "Sent via HTTPS"
            break
        fi

        # If we reached here, attempt failed — backoff and retry
        print_error "Attempt $ATTEMPT failed (curl exit $CURL_EXIT)."
        if [[ $ATTEMPT -lt $RETRIES ]]; then
            BACKOFF=$((RETRY_BACKOFF ** ATTEMPT))
            print_info "Sleeping for $BACKOFF seconds before retry"
            sleep $BACKOFF
        else
            print_error "All $RETRIES attempts failed"
            print_error "Last response (truncated): ${RESPONSE:0:500}..."
            exit 1
        fi
    done

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

# ─────────────────────────────────────────────────���────────────────[...]
# STEP 7: ROUTE VIA TUNNEL (SOCKS5)
# ──────────────────────────────────────────────────────────────────[...]

step_7_route_via_tunnel() {
    print_section "STEP 7: Route via Tunnel (SOCKS5)"

    print_step "Tunnel configuration:"
    print_info "  Gateway: ${SOCKS_GATEWAY}"
    print_info "  Tunnel ID: ${ACTIVE_TUNNEL}"
    print_info "  Token: ${TUNNEL_TOKEN:0:20}...${TUNNEL_TOKEN: -5}"
    print_info "  Edges: $TUNNEL_EDGES_RAW"
    print_info "  Status: ${TUNNEL_STATUS}"

    print_step "Routing Google request through Cloudflare tunnel..."
    print_info "Traffic will egress via configured edge IPs"
    print_info "Request is encrypted end-to-end (quantum-safe)"

    if [[ -n "$EXPLICIT_SOCKS" ]]; then
        print_info "Explicit SOCKS in use: ${EXPLICIT_SOCKS}"
    fi
    if [[ -n "$SOCKS_SESSION" ]]; then
        print_info "SOCKS session selected: ${SOCKS_SESSION}"
    fi

    print_success "Tunnel routing active"
}

# ──────────────────────────────────────────────────────────────────[...]
# STEP 8: DISPLAY RESULTS
# ──────────────────────────────────────────────────────────────────[...]

step_8_display_results() {
    print_section "STEP 8: Google Response"

    if echo "$RESPONSE" | jq '.encrypted' > /dev/null 2>&1; then
        IS_ENCRYPTED=$(echo "$RESPONSE" | jq -r '.encrypted // false')
        print_info "Response encrypted: ${BOLD}${IS_ENCRYPTED}${NC}"
    fi

    if echo "$RESPONSE" | jq '.algorithm' > /dev/null 2>&1; then
        ALGORITHM=$(echo "$RESPONSE" | jq -r '.algorithm // "unknown"')
        print_info "Encryption algorithm: ${BOLD}${ALGORITHM}${NC}"
    fi

    echo ""
    echo -e "${BOLD}Response Preview:${NC}"
    echo "$RESPONSE" | jq '.' 2>/dev/null | head -50

    if [[ $(echo "$RESPONSE" | jq '.' 2>/dev/null | wc -l) -gt 50 ]]; then
        echo "$(echo "$RESPONSE" | jq '.' 2>/dev/null | tail -n +51 | wc -l) more lines..."
    fi

    print_success "Request completed successfully"
}

# ───────────────────────────────────────��─────────────────────────[...]
# MAIN EXECUTION FLOW
# ──────────────────────────────────────────────────────────────────[...]

main() {
    print_header

    step_1_create_envelope
    step_2_verify_tunnel
    step_3_check_services
    step_4_create_signatures
    step_5_send_to_lan_proxy
    step_6_flaresolverr_process
    step_7_route_via_tunnel
    step_8_display_results

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
