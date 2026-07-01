#!/bin/bash

################################################################################
# HYBRID PAYLOAD FALLBACK SCRIPT
# ────────────────────────────────────────────────────────────────────────────
# Attempts request sequence:
#   1. TRY PRIMARY:   Post-quantum encrypted (m7-crypto) → 8789/request
#   2. FAIL/REJECT:   Return error details
#   3. TRY FALLBACK:  Hybrid HTTP Proxy (old method) → 8789/proxy
#   4. FINAL FAIL:    Return both error logs
#
# Entry: cat <payload.json> | bash hybrid-payload-fallback.sh
################################################################################

set -e

# ═══════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

PROXY_HOST="${PROXY_HOST:-localhost}"
PROXY_PORT="${PROXY_PORT:-8789}"
PROXY_API_KEY="${PROXY_API_KEY:-sk_live_HvST3CeVckX_EUamWC6rq0HGnSuNy36K4W6Jh-Z75vw}"
HMAC_SECRET="${HMAC_SECRET:-/app/config/.proxy-hmac-secret}"

# Timeouts
TIMEOUT_REQUEST=30
TIMEOUT_FALLBACK=30

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Logging
LOG_DIR="${LOG_DIR:-.}"
LOG_FILE="$LOG_DIR/hybrid-fallback-$(date +%s).log"
REQUEST_ID="$(date +%s%N | md5sum | cut -c1-16)"

# ═══════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

log_header() {
    echo -e "${CYAN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} ${BLUE}═══${NC} $1" | tee -a "$LOG_FILE"
}

log_info() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} ${GREEN}✓${NC} $1" | tee -a "$LOG_FILE"
}

log_warn() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} ${YELLOW}⚠${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} ${RED}✗${NC} $1" | tee -a "$LOG_FILE"
}

log_debug() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} ${CYAN}→${NC} $1" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} ${GREEN}✅ SUCCESS${NC} $1" | tee -a "$LOG_FILE"
}

# ═══════════════════════════════════════════════════════════════════════════
# PAYLOAD HANDLING
# ═══════════════════════════════════════════════════════════════════════════

read_payload() {
    # Read from stdin or file argument
    if [ -n "$1" ]; then
        cat "$1"
    else
        cat -
    fi
}

validate_payload() {
    local payload="$1"
    
    # Check if valid JSON
    if ! echo "$payload" | jq . >/dev/null 2>&1; then
        log_error "Invalid JSON payload"
        return 1
    fi
    
    # Check required fields
    local url=$(echo "$payload" | jq -r '.url // empty')
    if [ -z "$url" ]; then
        log_error "Missing required field: url"
        return 1
    fi
    
    return 0
}

extract_url() {
    echo "$1" | jq -r '.url' 2>/dev/null || echo ""
}

# ═══════════════════════════════════════════════════════════════════════════
# PRIMARY: POST-QUANTUM ENCRYPTED (m7-crypto)
# ═══════════════════════════════════════════════════════════════════════════

attempt_quantum_safe() {
    local payload="$1"
    local url=$(extract_url "$payload")
    
    log_header "ATTEMPT 1: POST-QUANTUM ENCRYPTED (m7-crypto)"
    log_info "URL: $url"
    log_info "Entry Point: https://$PROXY_HOST:$PROXY_PORT/request"
    log_debug "Request ID: $REQUEST_ID"
    log_debug "Payload size: $(echo -n "$payload" | wc -c) bytes"
    
    # Create temporary response file
    local response_file=$(mktemp)
    local http_code_file=$(mktemp)
    local error_file=$(mktemp)
    
    trap "rm -f $response_file $http_code_file $error_file" RETURN
    
    # Attempt POST request with m7-crypto encryption header
    log_info "Sending encrypted POST request..."
    
    local http_code=$(curl \
        -s -w "%{http_code}" \
        -o "$response_file" \
        -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $PROXY_API_KEY" \
        -H "X-Request-ID: $REQUEST_ID" \
        -H "X-Quantum-Safe: true" \
        -H "X-Encryption-Type: m7-crypto" \
        --max-time "$TIMEOUT_REQUEST" \
        --connect-timeout 5 \
        -k \
        --data "$payload" \
        "https://$PROXY_HOST:$PROXY_PORT/request" 2>"$error_file")
    
    local curl_exit=$?
    
    # Log curl errors if any
    if [ -f "$error_file" ] && [ -s "$error_file" ]; then
        log_debug "Curl errors: $(cat $error_file)"
    fi
    
    # Parse response
    if [ $curl_exit -eq 0 ]; then
        log_debug "HTTP Status: $http_code"
        
        if [ "$http_code" = "200" ] || [ "$http_code" = "201" ]; then
            log_success "Quantum-safe encryption succeeded!"
            
            if [ -f "$response_file" ] && [ -s "$response_file" ]; then
                local response=$(cat "$response_file")
                log_info "Response received: $(echo "$response" | jq -r '.status // "ok"' 2>/dev/null)"
                
                # Output result
                cat "$response_file"
                echo "" >> "$LOG_FILE"
                log_success "REQUEST COMPLETED (POST-QUANTUM)"
                echo "---" >> "$LOG_FILE"
                
                return 0
            fi
        elif [ "$http_code" = "401" ] || [ "$http_code" = "403" ]; then
            log_error "Authentication/Authorization failed (HTTP $http_code)"
            log_debug "Response: $(cat $response_file 2>/dev/null | head -c 200)"
            
            return 1
        elif [ "$http_code" = "400" ]; then
            log_error "Bad request/Encryption validation failed (HTTP $http_code)"
            log_debug "Response: $(cat $response_file 2>/dev/null | head -c 200)"
            
            return 1
        else
            log_warn "Server error or timeout (HTTP $http_code)"
            log_debug "Response: $(cat $response_file 2>/dev/null | head -c 200)"
            
            return 1
        fi
    else
        log_error "Connection failed (curl exit code: $curl_exit)"
        log_debug "Curl error output: $(cat $error_file 2>/dev/null)"
        
        return 1
    fi
}

# ═══════════════════════════════════════════════════════════════════════════
# FALLBACK: HYBRID HTTP PROXY (Old Method)
# ═══════════════════════════════════════════════════════════════════════════

attempt_hybrid_proxy() {
    local payload="$1"
    local url=$(extract_url "$payload")
    
    log_header "ATTEMPT 2: HYBRID HTTP PROXY (Old Method - Fallback)"
    log_warn "Post-quantum method failed/rejected. Falling back to hybrid mode..."
    log_info "URL: $url"
    log_info "Proxy Entry Point: http://$PROXY_HOST:$PROXY_PORT"
    log_debug "Request ID: $REQUEST_ID"
    
    # Set environment for hybrid mode
    export http_proxy="http://$PROXY_HOST:$PROXY_PORT"
    export https_proxy="http://$PROXY_HOST:$PROXY_PORT"
    export HTTP_PROXY="$http_proxy"
    export HTTPS_PROXY="$https_proxy"
    export NO_PROXY="127.0.0.1,localhost"
    
    log_debug "HTTP_PROXY set to: $http_proxy"
    
    # Create temporary files
    local response_file=$(mktemp)
    local headers_file=$(mktemp)
    local error_file=$(mktemp)
    
    trap "rm -f $response_file $headers_file $error_file" RETURN
    
    # Attempt via HTTP proxy (old-style, no encryption wrapper)
    log_info "Sending request through HTTP proxy..."
    
    local http_code=$(curl \
        -s -w "%{http_code}" \
        -o "$response_file" \
        -D "$headers_file" \
        -X GET \
        -H "User-Agent: Mozilla/5.0 (Hybrid Fallback)" \
        -H "Accept: */*" \
        --max-time "$TIMEOUT_FALLBACK" \
        --connect-timeout 5 \
        --proxy "http://$PROXY_HOST:$PROXY_PORT" \
        --proxy-auth "" \
        "$url" 2>"$error_file")
    
    local curl_exit=$?
    
    # Log curl errors if any
    if [ -f "$error_file" ] && [ -s "$error_file" ]; then
        log_debug "Curl errors: $(cat $error_file)"
    fi
    
    # Parse response
    if [ $curl_exit -eq 0 ]; then
        log_debug "HTTP Status: $http_code"
        
        if [ "$http_code" = "200" ] || [ "$http_code" = "301" ] || [ "$http_code" = "302" ]; then
            log_success "Hybrid proxy succeeded!"
            
            if [ -f "$response_file" ] && [ -s "$response_file" ]; then
                local response=$(cat "$response_file")
                local content_type=$(grep -i "content-type" "$headers_file" 2>/dev/null | head -1 || echo "unknown")
                
                log_info "Response received: HTTP $http_code"
                log_debug "Content-Type: $content_type"
                log_debug "Response size: $(wc -c < $response_file) bytes"
                
                # Output result with metadata
                cat > /tmp/hybrid-response.json << RESPONSE_JSON
{
  "success": true,
  "method": "hybrid-http-proxy",
  "http_code": $http_code,
  "request_id": "$REQUEST_ID",
  "url": "$url",
  "content_length": $(wc -c < $response_file),
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "response_preview": "$(cat $response_file 2>/dev/null | head -c 200 | jq -Rs . 2>/dev/null || echo '')"
}
RESPONSE_JSON
                
                cat /tmp/hybrid-response.json
                echo "" >> "$LOG_FILE"
                log_success "REQUEST COMPLETED (HYBRID PROXY)"
                echo "---" >> "$LOG_FILE"
                
                return 0
            fi
        else
            log_error "Proxy returned error (HTTP $http_code)"
            log_debug "Response headers: $(head -5 $headers_file 2>/dev/null)"
            
            return 1
        fi
    else
        log_error "Proxy connection failed (curl exit code: $curl_exit)"
        log_debug "Curl error output: $(cat $error_file 2>/dev/null)"
        
        return 1
    fi
}

# ═══════════════════════════════════════════════════════════════════════════
# SOCKS5 DIRECT (Second Fallback - if hybrid also fails)
# ═══════════════════════════════════════════════════════════════════════════

attempt_socks5_direct() {
    local payload="$1"
    local url=$(extract_url "$payload")
    
    log_header "ATTEMPT 3: SOCKS5 DIRECT (Second Fallback)"
    log_warn "Hybrid proxy also failed. Trying SOCKS5 direct..."
    log_info "URL: $url"
    log_info "SOCKS5 Gateway: 127.0.0.1:8888"
    log_debug "Request ID: $REQUEST_ID"
    
    # Create temporary files
    local response_file=$(mktemp)
    local error_file=$(mktemp)
    
    trap "rm -f $response_file $error_file" RETURN
    
    # Attempt via SOCKS5 (no proxy wrapper)
    log_info "Sending request through SOCKS5..."
    
    local http_code=$(curl \
        -s -w "%{http_code}" \
        -o "$response_file" \
        -X GET \
        -H "User-Agent: Mozilla/5.0 (SOCKS5 Direct)" \
        --max-time "$TIMEOUT_FALLBACK" \
        --connect-timeout 5 \
        --socks5 "127.0.0.1:8888" \
        "$url" 2>"$error_file")
    
    local curl_exit=$?
    
    # Log curl errors if any
    if [ -f "$error_file" ] && [ -s "$error_file" ]; then
        log_debug "Curl errors: $(cat $error_file)"
    fi
    
    # Parse response
    if [ $curl_exit -eq 0 ]; then
        log_debug "HTTP Status: $http_code"
        
        if [ "$http_code" = "200" ]; then
            log_success "SOCKS5 direct succeeded!"
            
            if [ -f "$response_file" ] && [ -s "$response_file" ]; then
                log_info "Response received: HTTP $http_code"
                log_debug "Response size: $(wc -c < $response_file) bytes"
                
                # Output result
                cat > /tmp/socks5-response.json << RESPONSE_JSON
{
  "success": true,
  "method": "socks5-direct",
  "http_code": $http_code,
  "request_id": "$REQUEST_ID",
  "url": "$url",
  "content_length": $(wc -c < $response_file),
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
RESPONSE_JSON
                
                cat /tmp/socks5-response.json
                echo "" >> "$LOG_FILE"
                log_success "REQUEST COMPLETED (SOCKS5 DIRECT)"
                echo "---" >> "$LOG_FILE"
                
                return 0
            fi
        else
            log_error "SOCKS5 returned error (HTTP $http_code)"
            return 1
        fi
    else
        log_error "SOCKS5 connection failed (curl exit code: $curl_exit)"
        return 1
    fi
}

# ═══════════════════════════════════════════════════════════════════════════
# MAIN ORCHESTRATION
# ═══════════════════════════════════════════════════════════════════════════

main() {
    log_header "HYBRID FALLBACK PAYLOAD PROCESSOR"
    log_info "Request ID: $REQUEST_ID"
    log_info "Proxy Host: $PROXY_HOST"
    log_info "Proxy Port: $PROXY_PORT"
    log_info "Log File: $LOG_FILE"
    echo "" | tee -a "$LOG_FILE"
    
    # Read and validate payload
    local payload
    payload=$(read_payload "$1")
    
    if ! validate_payload "$payload"; then
        log_error "FATAL: Payload validation failed"
        exit 1
    fi
    
    log_info "Payload validated"
    echo "" | tee -a "$LOG_FILE"
    
    # ATTEMPT 1: Post-Quantum Encrypted (m7-crypto)
    if attempt_quantum_safe "$payload"; then
        exit 0
    fi
    
    echo "" | tee -a "$LOG_FILE"
    
    # ATTEMPT 2: Hybrid HTTP Proxy (Fallback)
    if attempt_hybrid_proxy "$payload"; then
        exit 0
    fi
    
    echo "" | tee -a "$LOG_FILE"
    
    # ATTEMPT 3: SOCKS5 Direct (Second Fallback)
    if attempt_socks5_direct "$payload"; then
        exit 0
    fi
    
    # ALL ATTEMPTS FAILED
    echo "" | tee -a "$LOG_FILE"
    log_header "FATAL: ALL METHODS FAILED"
    
    cat > /tmp/fallback-failure.json << FAILURE_JSON
{
  "success": false,
  "error": "All fallback methods failed",
  "request_id": "$REQUEST_ID",
  "attempts": [
    {
      "method": "post-quantum-m7-crypto",
      "status": "failed",
      "endpoint": "https://$PROXY_HOST:$PROXY_PORT/request"
    },
    {
      "method": "hybrid-http-proxy",
      "status": "failed",
      "endpoint": "http://$PROXY_HOST:$PROXY_PORT"
    },
    {
      "method": "socks5-direct",
      "status": "failed",
      "endpoint": "socks5://127.0.0.1:8888"
    }
  ],
  "log_file": "$LOG_FILE",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
FAILURE_JSON
    
    cat /tmp/fallback-failure.json
    echo "" | tee -a "$LOG_FILE"
    log_error "All fallback methods exhausted. Check $LOG_FILE for details."
    
    exit 1
}

# ═══════════════════════════════════════════════════════════════════════════
# EXECUTION
# ═══════════════════════════════════════════════════════════════════════════

main "$@"
