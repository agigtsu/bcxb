#!/bin/bash
# Entrypoint: Manages cloudflared tunnel + Python SOCKS5 server
# Handles process supervision and graceful shutdown

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} ${GREEN}✓${NC} $1"
}

log_warn() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} ${YELLOW}⚠${NC} $1"
}

log_error() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} ${RED}✗${NC} $1"
}

# ═══════════════════════════════════════════════════════════════════════════
# VALIDATION
# ═══════════════════════════════════════════════════════════════════════════

validate_environment() {
    log_info "Validating environment..."
    
    if [ -z "$CLOUDFLARE_TUNNEL_TOKEN" ]; then
        log_error "CLOUDFLARE_TUNNEL_TOKEN is not set"
        return 1
    fi
    
    if [ ! -f /app/socks5_server.py ]; then
        log_error "SOCKS5 server script not found: /app/socks5_server.py"
        return 1
    fi
    
    if ! command -v cloudflared &> /dev/null; then
        log_error "cloudflared binary not found"
        return 1
    fi
    
    if ! command -v python3 &> /dev/null; then
        log_error "python3 not found"
        return 1
    fi
    
    log_info "✓ All requirements validated"
    return 0
}

# ═══════════════════════════════════════════════════════════════════════════
# SIGNAL HANDLERS
# ═══════════════════════════════════════════════════════════════════════════

trap_sigterm() {
    log_warn "🛑 Received SIGTERM - graceful shutdown..."
    
    # Kill supervisor which manages both processes
    if [ -n "$SUPERVISORD_PID" ]; then
        kill -TERM "$SUPERVISORD_PID" 2>/dev/null || true
        
        # Wait for graceful shutdown (10s timeout)
        local wait_count=0
        while kill -0 "$SUPERVISORD_PID" 2>/dev/null && [ $wait_count -lt 10 ]; do
            sleep 1
            wait_count=$((wait_count + 1))
        done
        
        # Force kill if still running
        if kill -0 "$SUPERVISORD_PID" 2>/dev/null; then
            log_warn "Force killing supervisor..."
            kill -9 "$SUPERVISORD_PID" 2>/dev/null || true
        fi
    fi
    
    log_info "✅ Shutdown complete"
    exit 0
}

trap trap_sigterm SIGTERM SIGINT

# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

case "${1:-start}" in
    start)
        log_info "╔════════════════════════════════════════════════════════════════╗"
        log_info "║   🌍 CLOUDFLARE TUNNEL SOCKS5 GATEWAY                         ║"
        log_info "╚════════════════════════════════════════════════════════════════╝"
        echo ""
        
        validate_environment || exit 1
        
        log_info "📍 Configuration:"
        log_info "   SOCKS5 Server: $SOCKS_HOST:$SOCKS_PORT"
        log_info "   Tunnel Token: ${CLOUDFLARE_TUNNEL_TOKEN:0:20}..."
        log_info "   Log Level: $LOG_LEVEL"
        echo ""
        
        log_info "🚀 Starting supervisor..."
        
        # Start supervisord (manages cloudflared + SOCKS5 server)
        exec /usr/bin/supervisord -c /etc/supervisord.conf
        ;;
    
    validate)
        validate_environment
        ;;
    
    *)
        log_error "Unknown command: $1"
        log_info "Available commands:"
        log_info "  • start (default) - Start supervisor with both services"
        log_info "  • validate - Validate environment only"
        exit 1
        ;;
esac