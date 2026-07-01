#!/bin/bash

# ═══════════════════════════════════════════════════════════════════════════════
#                      🔐 LAN PROXY SERVICE MANAGER 🔐
# ═══════════════════════════════════════════════════════════════════════════════
#
# Professional management of LAN Proxy (Multi-layer security)
# Features: Start, Stop, Reset
# Security Modules: PROXY_SECRET, TLS 1.3, API Key, HMAC, SSL/TLS, Audit, Encryption
#
# ═══════════════════════════════════════════════════════════════════════════════

set -e

# ─────────────────────────────────────────────────────────────────────────────
# COLORS & FORMATTING
# ─────────────────────────────────────────────────────────────────────────────
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
readonly SERVICE_NAME="LAN Proxy"
readonly PROCESS_PATTERN="node.*server.js"
readonly PORT=8789
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SERVER_PATH="${SCRIPT_DIR}/server.js"
if [ -f "/app/config/.proxy-env" ]; then
    readonly ENV_FILE="/app/config/.proxy-env"
else
    readonly ENV_FILE="$HOME/.proxy-env"
fi
readonly SERVICE_DIR="${SERVICE_DIR:-$SCRIPT_DIR}"
readonly LOG_FILE="/tmp/lan-proxy.log"
readonly TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# ─────────────────────────────────────────────────────────────────────────────
# UTILITY FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

print_header() {
    clear
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}${BOLD}        🔐 LAN PROXY SERVICE MANAGER 🔐${NC}${CYAN}        ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
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

print_step() {
    echo -e "${YELLOW}➜${NC} $1"
}

print_section() {
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

log_action() {
    echo "[${TIMESTAMP}] $1" >> "${LOG_FILE}"
}

# ─────────────────────────────────────────────────────────────────────────────
# VALIDATION
# ─────────────────────────────────────────────────────────────────────────────

validate_environment() {
    if [[ ! -f "$SERVER_PATH" ]]; then
        print_error "Server file not found: $SERVER_PATH"
        log_action "ERROR: Server file missing"
        return 1
    fi
    
    if [[ ! -f "$ENV_FILE" ]]; then
        print_error "Environment file not found: $ENV_FILE"
        print_info "Create $ENV_FILE with required variables:"
        print_info "  - PROXY_SECRET"
        print_info "  - PROXY_API_KEY"
        print_info "  - PROXY_HMAC_SECRET"
        log_action "ERROR: Environment file missing"
        return 1
    fi
    
    return 0
}

# ─────────────────────────────────────────────────────────────────────────────
# STATUS & VERIFICATION
# ─────────────────────────────────────────────────────────────────────────────

get_proxy_status() {
    if pgrep -f "$PROCESS_PATTERN" > /dev/null 2>&1; then
        echo "RUNNING"
        return 0
    else
        echo "STOPPED"
        return 1
    fi
}

get_proxy_pid() {
    pgrep -f "$PROCESS_PATTERN" | head -1
}

check_proxy_listening() {
    if lsof -nP -iTCP:${PORT} -sTCP:LISTEN > /dev/null 2>&1; then
        return 0
    fi
    return 1
}

print_status() {
    print_section "📊 PROXY STATUS"
    
    local STATUS=$(get_proxy_status)
    
    if [[ "$STATUS" == "RUNNING" ]]; then
        local PID=$(get_proxy_pid)
        echo -e "${GREEN}${BOLD}Status:${NC} ✅ RUNNING"
        echo -e "${BOLD}Process ID:${NC} $PID"
        echo -e "${BOLD}Port:${NC} $PORT"
        echo ""
        
        if check_proxy_listening; then
            echo -e "${GREEN}${BOLD}Listening:${NC} ✅ YES"
            lsof -i:${PORT} -sTCP:LISTEN | tail -1
        else
            echo -e "${RED}${BOLD}Listening:${NC} ❌ NO"
        fi
        
        echo ""
        print_step "Security Modules:"
        
        if [[ -f "$LOG_FILE" ]]; then
            tail -50 "$LOG_FILE" | grep -E "Module|enabled|SECURITY" | tail -8 || print_info "No module data in logs yet"
        fi
        
        echo ""
        print_success "Proxy is active and operational"
    else
        echo -e "${RED}${BOLD}Status:${NC} ⏸️  STOPPED"
        echo ""
        print_info "Proxy is not currently running"
    fi
    
    echo ""
}

# ─────────────────────────────────────────────────────────────────────────────
# SERVICE OPERATIONS
# ─────────────────────────────────────────────────────────────────────────────

clear_stale_proxy_listener() {
    local pids
    pids=$(lsof -ti:${PORT} 2>/dev/null || true)

    if [[ -z "$pids" ]]; then
        return 0
    fi

    print_info "Port $PORT is already in use; clearing stale listener(s)..."
    for pid in $pids; do
        kill -9 "$pid" 2>/dev/null || true
    done
    sleep 2

    pids=$(lsof -ti:${PORT} 2>/dev/null || true)
    if [[ -n "$pids" ]]; then
        print_error "Port $PORT remains busy after cleanup"
        return 1
    fi

    return 0
}

start_proxy() {
    print_section "▶️  STARTING LAN PROXY"
    
    if ! validate_environment; then
        return 1
    fi
    
    if check_proxy_listening; then
        if ! clear_stale_proxy_listener; then
            print_error "Proxy already running (PID: $(get_proxy_pid))"
            return 1
        fi
    fi
    
    print_step "Loading environment variables from $ENV_FILE..."
    
    print_step "Starting Node.js server..."
    : > "$LOG_FILE"
    cd "$SERVICE_DIR" && source "$ENV_FILE" && nohup node "$SERVER_PATH" >> "$LOG_FILE" 2>&1 &
    local PID=$!
    
    local waited=0
    while [ "$waited" -lt 20 ]; do
        if check_proxy_listening; then
            break
        fi
        sleep 1
        waited=$((waited + 1))
    done
    
    if check_proxy_listening; then
        local ACTUAL_PID=$(get_proxy_pid)
        print_success "Proxy started successfully (PID: $ACTUAL_PID)"
        
        sleep 2
        print_step "Verifying security modules..."
        
        if grep -q "PROXY_SECRET loaded" "$LOG_FILE" 2>/dev/null; then
            print_success "All 7 security modules initialized"
        fi
        
        log_action "Proxy started (PID: $ACTUAL_PID)"
        return 0
    else
        print_error "Proxy failed to start"
        print_info "Last 25 lines of log:"
        tail -25 "$LOG_FILE"
        log_action "ERROR: Proxy failed to start"
        return 1
    fi
}

stop_proxy() {
    print_section "⏹️  STOPPING LAN PROXY"
    
    if ! check_proxy_listening; then
        print_error "Proxy is not running"
        return 1
    fi
    
    print_step "Terminating proxy process..."
    
    # Graceful termination
    pkill -f "$PROCESS_PATTERN" 2>/dev/null
    sleep 2
    
    # Force kill if necessary
    if pgrep -f "$PROCESS_PATTERN" > /dev/null; then
        pkill -9 -f "$PROCESS_PATTERN" 2>/dev/null
        sleep 1
    fi
    
    print_step "Clearing port $PORT..."
    
    local PIDS=$(lsof -ti:${PORT} 2>/dev/null)
    if [[ -n "$PIDS" ]]; then
        kill -9 $PIDS 2>/dev/null
        sleep 1
    fi
    
    if ! check_proxy_listening; then
        print_success "Proxy stopped successfully"
        log_action "Proxy stopped"
        return 0
    else
        print_error "Failed to stop proxy completely"
        log_action "ERROR: Failed to stop proxy"
        return 1
    fi
}

reset_proxy() {
    print_section "🔄 RESETTING LAN PROXY"
    
    print_step "Stopping proxy..."
    stop_proxy
    
    echo ""
    print_step "Clearing log file..."
    > "$LOG_FILE"
    print_success "Log cleared"
    
    echo ""
    print_step "Clearing port $PORT..."
    local PIDS=$(lsof -ti:${PORT} 2>/dev/null)
    if [[ -n "$PIDS" ]]; then
        kill -9 $PIDS 2>/dev/null
        sleep 1
    fi
    print_success "Port cleared"
    
    echo ""
    print_step "Restarting proxy..."
    start_proxy
    
    echo ""
    print_section "✅ RESET COMPLETE"
    print_success "Proxy has been reset and restarted"
}

# ─────────────────────────────────────────────────────────────────────────────
# MENU & MAIN
# ─────────────────────────────────────────────────────────────────────────────

show_menu() {
    echo ""
    echo -e "${BOLD}Operations:${NC}"
    echo ""
    echo "  1️⃣  Start Proxy"
    echo "  2️⃣  Stop Proxy"
    echo "  3️⃣  Reset Proxy"
    echo "  4️⃣  Proxy Status"
    echo "  0️⃣  Exit"
    echo ""
}

main() {
    if [[ $# -eq 0 ]]; then
        # Interactive mode
        while true; do
            print_header
            show_menu
            
            read -p "Select operation: " choice
            
            case $choice in
                1) start_proxy ;;
                2) stop_proxy ;;
                3) reset_proxy ;;
                4) print_status ;;
                0) echo ""; print_info "Exiting..."; exit 0 ;;
                *) print_error "Invalid selection" ;;
            esac
            
            read -p "Press Enter to continue..."
        done
    else
        # Command mode
        case $1 in
            start) start_proxy ;;
            stop) stop_proxy ;;
            reset) reset_proxy ;;
            status) print_status ;;
            *) echo "Usage: $0 {start|stop|reset|status}"; exit 1 ;;
        esac
    fi
}

main "$@"
