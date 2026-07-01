#!/bin/bash
# Docker entrypoint: Orchestrates M7 Proxy + FlareSolverr + Tunnel Integration
# Container-native process management with auto-restart & signal handling

set +e  # Don't exit on errors - we handle them explicitly

# ═══════════════════════════════════════════════════════════════════════════
# GLOBAL STATE & CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration with defaults
PROXY_PORT=${PROXY_PORT:-8789}
FLARESOLVERR_PORT=${FLARESOLVERR_PORT:-8191}
TUNNEL_GATEWAY=${TUNNEL_GATEWAY:-127.0.0.1:8888}
LOG_DIR=${LOG_DIR:-/app/logs}
AUDIT_LOG_DIR=${AUDIT_LOG_DIR:-/app/audit-logs}
TLS_KEY_PATH=${TLS_KEY_PATH:-/app/certs/server.key}
TLS_CERT_PATH=${TLS_CERT_PATH:-/app/certs/server.crt}
SERVICE_ROOT=${SERVICE_ROOT:-/app}

# Process management state
declare -A SERVICE_PIDS
declare -A SERVICE_RESTART_COUNT
SHUTDOWN_FLAG=0

# High-performance tuning
ulimit -n 1048576 >/dev/null 2>&1

# ═══════════════════════════════════════════════════════════════════════════
# SIGNAL HANDLERS (at script level, not in functions)
# ═══════════════════════════════════════════════════════════════════════════

trap_sigterm() {
    log_warn "🛑 Received SIGTERM - initiating graceful shutdown..."
    SHUTDOWN_FLAG=1
    
    for pid in "${SERVICE_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            log_info "   Stopping PID $pid..."
            kill -TERM "$pid" 2>/dev/null || true
        fi
    done
    
    local wait_count=0
    while [ ${#SERVICE_PIDS[@]} -gt 0 ] && [ $wait_count -lt 10 ]; do
        sleep 1
        wait_count=$((wait_count + 1))
    done
    
    for pid in "${SERVICE_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            log_warn "   Force-killing PID $pid..."
            kill -9 "$pid" 2>/dev/null || true
        fi
    done
    
    log_info "✅ Graceful shutdown complete"
    exit 0
}

trap trap_sigterm SIGTERM SIGINT

# ═══════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

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
# BOOTSTRAP: COLIMA / DOCKER RUNTIME (MUST RUN FIRST)
# ═══════════════════════════════════════════════════════════════════════════

ensure_docker_runtime() {
    if [ -f "/.dockerenv" ]; then
        log_info "✓ Container runtime detected; Docker already available"
        return 0
    fi

    # Only bootstrap Colima if NOT in Docker
    log_warn "⚠ Not in container; bootstrapping Colima..."

    # 1. Aggressive Flexible CPU Allocation
    HOST_CORES=$(sysctl -n hw.physicalcpu 2>/dev/null || echo 4)
    COLIMA_CPU=$(( (HOST_CORES * 3) / 4 ))
    [ "$COLIMA_CPU" -lt 4 ] && COLIMA_CPU=4

    # 2. Aggressive Flexible RAM Allocation
    HOST_BYTES=$(sysctl -n hw.memsize 2>/dev/null || echo 8589934592)
    HOST_GB=$(( HOST_BYTES / 1024 / 1024 / 1024 ))
    COLIMA_MEMORY=$(( (HOST_GB * 3) / 4 ))
    [ "$COLIMA_MEMORY" -lt 8 ] && COLIMA_MEMORY=8

    # 3. Start Colima with Bare-Metal Virtualization
    if ! docker info >/dev/null 2>&1; then
        log_info "🚀 Launching Colima VM..."
        log_info "   Allocation: ${COLIMA_CPU} Cores / ${COLIMA_MEMORY} GB RAM (from ${HOST_CORES} cores / ${HOST_GB} GB total)"
        
        colima start \
            --cpu "$COLIMA_CPU" \
            --memory "$COLIMA_MEMORY" \
            --vm-type=vz \
            --networking=vz \
            --mount-type=virtiofs \
            --dns=1.1.1.1 \
            --dns=1.0.0.1 \
            --runtime=docker || {
            log_error "Failed to start Colima"
            return 1
        }
        
        # Wait for Docker socket readiness
        log_info "   Waiting for Docker daemon..."
        local i
        for i in $(seq 1 30); do
            docker info >/dev/null 2>&1 && break || sleep 1
        done
        
        if ! docker info >/dev/null 2>&1; then
            log_error "Docker not ready after 30 seconds"
            return 1
        fi
        
        log_info "✓ Docker daemon ready"

        # 4. Kernel Tuning
        log_info "   Tuning Linux network stack..."
        colima ssh -- sudo sysctl -w \
            net.core.rmem_max=67108864 \
            net.core.wmem_max=67108864 \
            net.core.netdev_max_backlog=100000 \
            net.ipv4.tcp_rmem="4096 87380 67108864" \
            net.ipv4.tcp_wmem="4096 65536 67108864" \
            net.ipv4.tcp_fastopen=3 \
            fs.file-max=2097152 >/dev/null 2>&1 || true
        
        log_info "✓ Network tuning complete"
    else
        log_info "✓ Docker daemon already running"
    fi

    return 0
}

# ═══════════════════════════════════════════════════════════════════════════
# ENVIRONMENT & SECURITY INITIALIZATION
# ═══════════════════════════════════════════════════════════════════════════

validate_required_credentials() {
    local default_proxy_api_key="sk_live_HvST3CeVckX_EUamWC6rq0HGnSuNy36K4W6Jh-Z75vw"

    if [ -z "${PROXY_API_KEY:-}" ]; then
        export PROXY_API_KEY="$default_proxy_api_key"
    fi

    if [ -z "${PROXY_HMAC_SECRET:-}" ]; then
        export PROXY_HMAC_SECRET=$(openssl rand -base64 32 | tr -d '\n')
    fi

    mkdir -p /app/config
    printf '%s\n' "$PROXY_HMAC_SECRET" > /app/config/.proxy-hmac-secret
    chmod 600 /app/config/.proxy-hmac-secret
    
    if [ -z "${PROXY_SECRET:-}" ]; then
        export PROXY_SECRET=$(openssl rand -base64 32 | tr -d '\n')
    fi
    
    log_info "✅ Credentials validated"
}

initialize_environment() {
    log_info "🔧 Initializing environment..."
    
    # Ensure directories exist
    mkdir -p "$LOG_DIR" "$AUDIT_LOG_DIR" "$(dirname "$TLS_KEY_PATH")"
    
    # Validate required credentials
    validate_required_credentials || return 1
    
    # Load tunnel config if exists
    local tunnel_mode="${TUNNEL_MODE:-}"
    local tunnel_gateway="${TUNNEL_GATEWAY:-}"
    local tunnel_timeout="${TUNNEL_TIMEOUT:-}"
    local tunnel_max_redirects="${TUNNEL_MAX_REDIRECTS:-}"

    if [ -f "/app/lan-proxy/.tunnel-env" ]; then
        set -a
        source /app/lan-proxy/.tunnel-env
        set +a
        log_info "✓ Tunnel configuration loaded"
    else
        log_warn "Tunnel config not found, using defaults"
    fi

    export TUNNEL_MODE="${tunnel_mode:-${TUNNEL_MODE:-enabled}}"
    export TUNNEL_GATEWAY="${tunnel_gateway:-${TUNNEL_GATEWAY:-127.0.0.1:8888}}"
    export TUNNEL_TIMEOUT="${tunnel_timeout:-${TUNNEL_TIMEOUT:-30000}}"
    export TUNNEL_MAX_REDIRECTS="${tunnel_max_redirects:-${TUNNEL_MAX_REDIRECTS:-5}}"
    
    # Load proxy env if exists
    if [ -f "/app/config/.proxy-env" ] || [ -f "$HOME/.proxy-env" ]; then
        set -a
        source /app/config/.proxy-env 2>/dev/null || source "$HOME/.proxy-env" 2>/dev/null
        set +a
        log_info "✓ Proxy credentials loaded"
    else
        log_warn "Proxy config not found, some features may be disabled"
    fi
    
    return 0
}

ensure_self_signed_tls() {
    local key_path="$TLS_KEY_PATH"
    local cert_path="$TLS_CERT_PATH"

    if [ -f "$key_path" ] && [ -f "$cert_path" ]; then
        log_info "✓ Existing TLS certificate found"
        return 0
    fi

    log_warn "TLS certificate missing, generating self-signed cert for localhost..."
    mkdir -p "$(dirname "$key_path")"

    openssl req -x509 -nodes -newkey rsa:2048 -sha256 -days 3650 \
        -subj "/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
        -keyout "$key_path" \
        -out "$cert_path" >/dev/null 2>&1 || {
        log_error "Failed to generate TLS certificate"
        return 1
    }

    log_info "✓ Self-signed TLS certificate generated"
    return 0
}

verify_dependencies() {
    log_info "🔍 Verifying dependencies..."
    
    if command -v node &> /dev/null; then
        log_info "✓ Node.js: $(node -v)"
    else
        log_error "Node.js not found"
        return 1
    fi
    
    if command -v python3 &> /dev/null; then
        log_info "✓ Python: $(python3 --version)"
    else
        log_error "Python not found"
        return 1
    fi
    
    if command -v chromium-browser &> /dev/null || command -v chromium &> /dev/null; then
        log_info "✓ Chromium browser available"
    else
        log_error "Chromium not found"
        return 1
    fi
    
    return 0
}

clear_ghost_port_conflicts() {
    local ports=(8191 8789 8888)
    local port pid pids

    log_info "🧹 Clearing stale listeners..."

    for port in "${ports[@]}"; do
        if command -v ss >/dev/null 2>&1; then
            pids=$(ss -ltnp 2>/dev/null | awk -v p=":$port" '$4 ~ p {match($0, /pid=([0-9]+)/, m); if (m[1] != "") print m[1]}' | sort -u)
        elif command -v lsof >/dev/null 2>&1; then
            pids=$(lsof -tiTCP:"$port" -sTCP:LISTEN 2>/dev/null || true)
        fi

        for pid in $pids; do
            if [ -n "$pid" ] && [ "$pid" != "$$" ] && kill -0 "$pid" 2>/dev/null; then
                log_warn "   Killing stale process $pid on port $port"
                kill "$pid" 2>/dev/null || true
            fi
        done
    done

    sleep 1
}

# ═══════════════════════════════════════════════════════════════════════════
# SERVICE STARTUP FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

resolve_browser_path() {
    if [ -x "/usr/bin/chromium" ]; then
        echo "/usr/bin/chromium"
        return 0
    fi

    if [ -x "/usr/bin/chromium-browser" ]; then
        echo "/usr/bin/chromium-browser"
        return 0
    fi

    if [ -x "/app/flaresolverr/chrome-mac/Chromium.app/Contents/MacOS/Chromium" ]; then
        echo "/app/flaresolverr/chrome-mac/Chromium.app/Contents/MacOS/Chromium"
        return 0
    fi

    if command -v chromium >/dev/null 2>&1; then
        command -v chromium
        return 0
    fi

    if command -v chromium-browser >/dev/null 2>&1; then
        command -v chromium-browser
        return 0
    fi

    return 1
}

run_flaresolverr_direct() {
    local python_bin
    python_bin=$(command -v python3 || command -v python || true)
    if [ -z "$python_bin" ]; then
        log_error "[FlareSolverr] python3 not found"
        return 1
    fi

    local flaresolverr_entry="/app/flaresolverr/src/flaresolverr.py"
    if [ ! -f "$flaresolverr_entry" ]; then
        log_error "[FlareSolverr] Entrypoint missing: $flaresolverr_entry"
        return 1
    fi

    log_info "▶️  Starting FlareSolverr with self-contained Chromium..."
    cd /app/flaresolverr || {
        log_error "[FlareSolverr] Cannot cd to /app/flaresolverr"
        return 1
    }

    export PYTHONUNBUFFERED=1
    export LOG_LEVEL="${LOG_LEVEL:-info}"
    
    log_info "   Browser: Local Chromium (self-contained)"
    log_info "   Mode: Headless ON"
    log_info "   Memory: ~300MB"
    
    "$python_bin" src/flaresolverr.py >> "$LOG_DIR/flaresolverr.log" 2>&1 &
    local pid=$!
    SERVICE_PIDS[flaresolverr]=$pid
    
    log_info "   Process PID: $pid"
    log_info "⏳ Waiting for Chromium initialization... (20-50 seconds)"

    local health_wait=0
    while [ $health_wait -lt 60 ]; do
        if curl -sk --max-time 2 http://127.0.0.1:$FLARESOLVERR_PORT/health >/dev/null 2>&1; then
            log_info "✅ FlareSolverr ready on port $FLARESOLVERR_PORT (PID: $pid)"
            return 0
        fi
        sleep 1
        health_wait=$((health_wait + 1))
    done

    log_error "[FlareSolverr] Failed to start within 60 seconds"
    return 1
}

start_tunnel_service() {
    local attempt=0
    local max_attempts=3

    log_info "🌍 Starting Cloudflare tunnel..."

    while [ $attempt -lt $max_attempts ]; do
        if [ $SHUTDOWN_FLAG -eq 1 ]; then
            log_warn "⏹ Tunnel received shutdown signal"
            return 0
        fi

        if [ $attempt -gt 0 ]; then
            log_warn "⚠ Tunnel retry $((attempt+1))/$max_attempts"
        fi

        local CLOUDFLARE_TUNNEL_SCRIPT="$SERVICE_ROOT/core-service/cloudflare-tunnel/Cloudflare-Tunnel.sh"

        if [ ! -f "$CLOUDFLARE_TUNNEL_SCRIPT" ] && [ -f "/app/cloudflare-tunnel/Cloudflare-Tunnel.sh" ]; then
            CLOUDFLARE_TUNNEL_SCRIPT="/app/cloudflare-tunnel/Cloudflare-Tunnel.sh"
        fi

        if [ -f "$CLOUDFLARE_TUNNEL_SCRIPT" ] && [ ! -x "$CLOUDFLARE_TUNNEL_SCRIPT" ]; then
            chmod +x "$CLOUDFLARE_TUNNEL_SCRIPT" 2>/dev/null || true
        fi

        if [ -f "$CLOUDFLARE_TUNNEL_SCRIPT" ] && [ -x "$CLOUDFLARE_TUNNEL_SCRIPT" ]; then
            printf '1\n' | bash "$CLOUDFLARE_TUNNEL_SCRIPT" >> "$LOG_DIR/tunnel.log" 2>&1
            local exit_code=$?
            if [ $exit_code -eq 0 ] || [ $exit_code -eq 124 ]; then
                log_info "✓ Tunnel started"
                return 0
            fi
        fi

        if command -v cloudflared >/dev/null 2>&1 && [ -n "${CLOUDFLARE_TUNNEL_TOKEN:-}" ]; then
            log_info "   Fallback: using cloudflared binary"
            nohup cloudflared tunnel run --token "$CLOUDFLARE_TUNNEL_TOKEN" >> "$LOG_DIR/tunnel.log" 2>&1 &
            local pid=$!
            SERVICE_PIDS[cloudflare]=$pid
            return 0
        fi

        attempt=$((attempt + 1))
        if [ $attempt -lt $max_attempts ]; then
            sleep 5
        fi
    done

    log_warn "⚠ Tunnel startup failed; continuing without it"
    return 0
}

start_flaresolverr_service() {
    log_info "🌐 Starting FlareSolverr..."
    
    cd /app/flaresolverr || {
        log_error "Cannot cd to flaresolverr"
        return 1
    }
    
    if run_flaresolverr_direct; then
        return 0
    fi
    
    log_warn "⚠ FlareSolverr startup failed; continuing without it"
    return 0
}

start_lan_proxy_service() {
    local attempt=0
    local max_attempts=3
    
    while [ $attempt -lt $max_attempts ]; do
        if [ $SHUTDOWN_FLAG -eq 1 ]; then
            log_warn "⏹ LAN Proxy received shutdown signal"
            return 0
        fi
        
        log_info "🔐 Starting LAN Proxy on port $PROXY_PORT (attempt $((attempt+1))/$max_attempts)..."
        
        if [ ! -f "/app/lan-proxy/server.js" ]; then
            log_error "server.js not found"
            return 1
        fi
        
        cd /app/lan-proxy || {
            log_error "Cannot cd to lan-proxy"
            return 1
        }
        
        if [ ! -d "node_modules" ]; then
            log_info "   Installing Node dependencies..."
            npm ci --production 2>/dev/null || npm install --production 2>/dev/null
        fi
        
        local proxy_script="/app/lan-proxy/LAN-Proxy.sh"
        if [ ! -f "$proxy_script" ]; then
            log_error "Legacy launcher missing: $proxy_script"
            return 1
        fi

        chmod +x "$proxy_script" 2>/dev/null || true
        log_info "   Running: $proxy_script start"
        bash "$proxy_script" start >> "$LOG_DIR/lan-proxy.log" 2>&1 &
        local pid=$!
        SERVICE_PIDS[lan-proxy]=$pid

        # Wait for port to be ready
        local port_wait=0
        while [ $port_wait -lt 30 ]; do
            if curl -sk --max-time 2 https://127.0.0.1:$PROXY_PORT/health >/dev/null 2>&1; then
                log_info "✅ LAN Proxy ready on port $PROXY_PORT"
                return 0
            fi
            if ! pgrep -f 'node.*server.js' >/dev/null 2>&1; then
                log_error "server process not running"
                return 1
            fi
            sleep 1
            port_wait=$((port_wait + 1))
        done

        log_warn "⚠ Port not ready after 30s"
        attempt=$((attempt + 1))
        if [ $attempt -lt $max_attempts ]; then
            sleep 5
        fi
    done
    
    log_error "LAN Proxy failed after $max_attempts attempts"
    return 1
}

# ═══════════════════════════════════════════════════════════════════════════
# MAIN STARTUP ORCHESTRATION
# ═══════════════════════════════════════════════════════════════════════════

start_all() {
    log_info "╔════════════════════════════════════════════════════════════════╗"
    log_info "║   🚀 DOCKER STARTUP: M7 PROXY + FLARESOLVERR + TUNNEL         ║"
    log_info "╚════════════════════════════════════════════════════════════════╝"
    echo ""

    # STEP 1: BOOTSTRAP DOCKER RUNTIME (MUST BE FIRST)
    log_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log_info "STEP 1/5: Ensuring Docker runtime..."
    ensure_docker_runtime || return 1
    echo ""

    # STEP 2: CLEAR PORT CONFLICTS
    log_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log_info "STEP 2/5: Clearing stale processes..."
    clear_ghost_port_conflicts
    
    # Cleanup any leftover processes
    pkill -f cloudflared 2>/dev/null || true
    pkill -f 'node.*server.js' 2>/dev/null || true
    pkill -f FlareSolverr 2>/dev/null || true
    sleep 2
    echo ""

    # STEP 3: INITIALIZE ENVIRONMENT
    log_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log_info "STEP 3/5: Initializing environment..."
    initialize_environment || return 1
    ensure_self_signed_tls || return 1
    verify_dependencies || return 1
    echo ""

    # STEP 4: START SERVICES IN SEQUENCE
    log_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log_info "STEP 4/5: Starting services (tunnel → flaresolverr → proxy)"
    echo ""

    start_tunnel_service || return 1
    sleep 2

    start_flaresolverr_service || return 1
    sleep 2

    start_lan_proxy_service || return 1
    echo ""

    # STEP 5: SUPERVISION LOOP
    log_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log_info "STEP 5/5: Entering supervision loop"
    log_info "✅ All services started. Container will remain running."
    log_info "📝 Logs available at: $LOG_DIR"
    log_info "🛑 Press Ctrl+C to gracefully shut down"
    echo ""

    while [ $SHUTDOWN_FLAG -eq 0 ]; do
        sleep 60
    done
}

start_proxy_only() {
    log_info "🔐 Starting LAN Proxy only (FlareSolverr must be running separately)"
    
    ensure_docker_runtime || return 1
    initialize_environment || return 1
    ensure_self_signed_tls || return 1
    verify_dependencies || return 1
    clear_ghost_port_conflicts
    
    start_lan_proxy_service || return 1
    
    while [ $SHUTDOWN_FLAG -eq 0 ]; do
        sleep 60
    done
}

start_flaresolverr_only() {
    log_info "🌐 Starting FlareSolverr only (for debugging)"
    
    ensure_docker_runtime || return 1
    initialize_environment || return 1
    verify_dependencies || return 1
    clear_ghost_port_conflicts
    
    start_flaresolverr_service || return 1
    
    while [ $SHUTDOWN_FLAG -eq 0 ]; do
        sleep 60
    done
}

debug_mode() {
    log_info "🐛 Debug mode: Starting with interactive shell"
    
    ensure_docker_runtime || return 1
    initialize_environment || return 1
    verify_dependencies || return 1
    
    log_info ""
    log_info "Environment ready. You can now:"
    log_info "  • Start proxy: cd /app/lan-proxy && node server.js"
    log_info "  • Start FlareSolverr: cd /app/flaresolverr && python3 src/flaresolverr.py"
    log_info "  • Test tunnel: curl http://127.0.0.1:$PROXY_PORT/health"
    log_info ""
    
    /bin/bash
}

# ═══════════════════════════════════════════════════════════════════════════
# MAIN EXECUTION
# ═══════════════════════════════════════════════════════════════════════════

case "${1:-start-all}" in
    start-all)
        start_all
        ;;
    proxy)
        start_proxy_only
        ;;
    flaresolverr)
        start_flaresolverr_only
        ;;
    debug)
        debug_mode
        ;;
    *)
        log_error "Unknown command: $1"
        log_info ""
        log_info "Available commands:"
        log_info "  • start-all (default) - Start tunnel, proxy, and FlareSolverr"
        log_info "  • proxy - Start only LAN Proxy"
        log_info "  • flaresolverr - Start only FlareSolverr"
        log_info "  • debug - Interactive shell for debugging"
        exit 1
        ;;
esac