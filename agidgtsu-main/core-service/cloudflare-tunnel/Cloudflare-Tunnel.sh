#!/bin/bash

# ══════════════════════════════════════════════════════════════════════════════
#                    🌍 CLOUDFLARE TUNNEL SERVICE MANAGER 🌍
# ══════════════════════════════════════════════════════════════════════════════
#
# Professional management of Cloudflare Tunnel with GEO-IP aware socket selection
# Features: Start, Stop, Reset, Tunnel Switcher, Real-time Socket Status, Geo-location
#
# ══════════════════════════════════════════════════════════════════════════════

set -e

# ──────────────────────────────────────────────────────────────────────────────
# COLORS & FORMATTING
# ──────────────────────────────────────────────────────────────────────────────
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly MAGENTA='\033[0;35m'
readonly BOLD='\033[1m'
readonly DIM='\033[2m'
readonly NC='\033[0m'

# ──────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────────────────────────────────────────
readonly SERVICE_NAME="Cloudflare Tunnel"
readonly PROCESS_NAME="cloudflared"
readonly LOG_FILE="/tmp/tunel-portal.log"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly TUNNELS_CSV="$SCRIPT_DIR/tunnels.csv"
readonly ROUTES_CSV="$SCRIPT_DIR/service-routes.csv"
readonly ACTIVE_TUNNEL_STATE="$SCRIPT_DIR/.active_tunnel"
readonly TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# GEO-IP API (Free tier available)
readonly GEOIP_API="https://ipapi.co"
readonly EDGE_CACHE="$SCRIPT_DIR/.edge_cache"

# ──────────────────────────────────────────────────────────────────────────────
# CSV READING FUNCTIONS (Source of Truth)
# ──────────────────────────────────────────────────────────────────────────────

get_active_tunnel_id() {
    if [[ -f "$ACTIVE_TUNNEL_STATE" ]]; then
        cat "$ACTIVE_TUNNEL_STATE" | tr -d '[:space:]'
    else
        # Fallback to first tunnel marked 'active'
        awk -F',' 'NR>1 && $5 ~ /^active$/ {print $1; exit}' "$TUNNELS_CSV" | tr -d '[:space:]'
    fi
}

get_tunnel_by_id() {
    local TUNNEL_ID=$1
    local FIELD=$2
    awk -F',' -v id="$TUNNEL_ID" -v field="$FIELD" '
    NR==1 {
        for(i=1;i<=NF;i++) {
            if($i==field) {field_idx=i; break}
        }
    }
    NR>1 && $1==id {print $field_idx; exit}
    ' "$TUNNELS_CSV" | tr -d '[:space:]'
}

get_tunnel_token() {
    local TUNNEL_ID=$1
    awk -F',' -v id="$TUNNEL_ID" 'NR>1 && $1==id {print $4; exit}' "$TUNNELS_CSV" | tr -d '[:space:]'
}

get_tunnel_name() {
    local TUNNEL_ID=$1
    awk -F',' -v id="$TUNNEL_ID" 'NR>1 && $1==id {print $2; exit}' "$TUNNELS_CSV" | tr -d '[:space:]'
}

get_tunnel_status() {
    local TUNNEL_ID=$1
    awk -F',' -v id="$TUNNEL_ID" 'NR>1 && $1==id {print $5; exit}' "$TUNNELS_CSV" | tr -d '[:space:]'
}

get_tunnel_port() {
    local TUNNEL_ID=$1
    awk -F',' -v id="$TUNNEL_ID" 'NR>1 && $1==id {print $6; exit}' "$TUNNELS_CSV" | tr -d '[:space:]'
}

get_tunnel_edge_ips() {
    local TUNNEL_ID=$1
    awk -F',' -v id="$TUNNEL_ID" 'NR>1 && $1==id {print $7; exit}' "$TUNNELS_CSV"
}

list_all_tunnels() {
    awk -F',' 'NR>1 {print $1}' "$TUNNELS_CSV"
}

# ──────────────────────────────────────────────────────────────────────────────
# GEO-IP & EDGE DETECTION
# ──────────────────────────────────────────────────────────────────────────────

get_geo_info() {
    local IP=$1
    
    # Check cache first
    if [[ -f "$EDGE_CACHE" ]]; then
        local cached=$(grep "^$IP|" "$EDGE_CACHE" 2>/dev/null | head -1)
        if [[ -n "$cached" ]]; then
            echo "$cached" | cut -d'|' -f2-
            return 0
        fi
    fi
    
    # Fetch fresh data
    local geo_data=$(curl -s "${GEOIP_API}/${IP}/json" 2>/dev/null | grep -o '"country_name":"[^"]*"' | cut -d'"' -f4)
    
    if [[ -z "$geo_data" ]]; then
        echo "Unknown"
    else
        echo "$geo_data"
        # Cache it
        echo "$IP|$geo_data" >> "$EDGE_CACHE"
    fi
}

get_edge_emoji() {
    local country=$1
    case "$country" in
        *"United States"*) echo "🇺🇸" ;;
        *"United Kingdom"*) echo "🇬🇧" ;;
        *"Germany"*) echo "🇩🇪" ;;
        *"France"*) echo "🇫🇷" ;;
        *"Japan"*) echo "🇯🇵" ;;
        *"Australia"*) echo "🇦🇺" ;;
        *"Canada"*) echo "🇨🇦" ;;
        *"Singapore"*) echo "🇸🇬" ;;
        *"Netherlands"*) echo "🇳🇱" ;;
        *"Brazil"*) echo "🇧🇷" ;;
        *) echo "🌐" ;;
    esac
}

get_current_tunnel_latency() {
    local EDGE_IP=$1
    if command -v ping &> /dev/null; then
        # Use ping to measure latency (first response)
        local latency=$(ping -c 1 -W 2 "$EDGE_IP" 2>/dev/null | grep "time=" | sed 's/.*time=\([^ ]*\).*/\1/' | head -1)
        if [[ -n "$latency" ]]; then
            echo "$latency"
        else
            echo "N/A"
        fi
    else
        echo "N/A"
    fi
}

# ──────────────────────────────────────────────────────────────────────────────
# UTILITY FUNCTIONS
# ──────────────────────────────────────────────────────────────────────────────

print_header() {
    clear
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}${BOLD}      🌍 CLOUDFLARE TUNNEL SERVICE MANAGER 🌍${NC}${CYAN}      ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════════════════════╝${NC}"
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
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

log_action() {
    echo "[${TIMESTAMP}] $1" >> "${LOG_FILE}"
}

# ──────────────────────────────────────────────────────────────────────────────
# STATUS & VERIFICATION
# ──────────────────────────────────────────────────────────────────────────────

get_tunnel_status_process() {
    if pgrep -f "$PROCESS_NAME" > /dev/null 2>&1; then
        echo "RUNNING"
        return 0
    else
        echo "STOPPED"
        return 1
    fi
}

get_tunnel_pid() {
    pgrep -f "$PROCESS_NAME" | head -1
}

check_tunnel_listening() {
    if pgrep -f "$PROCESS_NAME" > /dev/null 2>&1; then
        return 0
    fi
    return 1
}

print_status() {
    print_section "📊 TUNNEL STATUS"
    
    local STATUS=$(get_tunnel_status_process)
    local ACTIVE_ID=$(get_active_tunnel_id)
    local ACTIVE_NAME=$(get_tunnel_name "$ACTIVE_ID")
    
    if [[ "$STATUS" == "RUNNING" ]]; then
        local PID=$(get_tunnel_pid)
        echo -e "${GREEN}${BOLD}Status:${NC} ✅ RUNNING"
        echo -e "${BOLD}Process ID:${NC} $PID"
        echo -e "${BOLD}Active Tunnel:${NC} $ACTIVE_NAME ($ACTIVE_ID)"
        echo -e "${BOLD}Process Info:${NC}"
        ps aux | grep "$PROCESS_NAME" | grep -v grep | awk '{print "  "$0}'
        echo ""
        print_success "Tunnel is active and operational"
    else
        echo -e "${RED}${BOLD}Status:${NC} ⏸️  STOPPED"
        echo -e "${BOLD}Last Active Tunnel:${NC} $ACTIVE_NAME ($ACTIVE_ID)"
        echo ""
        print_info "Tunnel is not currently running"
    fi
    
    echo ""
}

# ──────────────────────────────────────────────────────────────────────────────
# INTERACTIVE TUNNEL SWITCHER (ExpressVPN-like UI)
# ──────────────────────────────────────────────────────────────────────────────

tunnel_switcher() {
    print_section "🔌 SOCKET SWITCHER - Select Active Tunnel"
    
    local CURRENT_ID=$(get_active_tunnel_id)
    local -a TUNNEL_IDS=()
    local -a TUNNEL_NAMES=()
    local -a TUNNEL_STATUSES=()
    local -a TUNNEL_PORTS=()
    local -a TUNNEL_EDGES=()
    local -a TUNNEL_GEOS=()
    local -a TUNNEL_LATENCIES=()
    local index=1
    
    echo ""
    echo -e "${DIM}Fetching tunnel information...${NC}"
    echo ""
    
    # Read all tunnels and build arrays
    while IFS= read -r tunnel_id; do
        TUNNEL_IDS+=("$tunnel_id")
        local name=$(get_tunnel_name "$tunnel_id")
        local status=$(get_tunnel_status "$tunnel_id")
        local port=$(get_tunnel_port "$tunnel_id")
        local edges=$(get_tunnel_edge_ips "$tunnel_id")
        
        TUNNEL_NAMES+=("$name")
        TUNNEL_STATUSES+=("$status")
        TUNNEL_PORTS+=("$port")
        TUNNEL_EDGES+=("$edges")
        
        # Get geo info for first edge IP
        local first_edge=$(echo "$edges" | cut -d',' -f1 | tr -d '[:space:]')
        if [[ -n "$first_edge" ]]; then
            local geo=$(get_geo_info "$first_edge")
            local emoji=$(get_edge_emoji "$geo")
            TUNNEL_GEOS+=("$emoji $geo")
            local latency=$(get_current_tunnel_latency "$first_edge")
            TUNNEL_LATENCIES+=("$latency")
        else
            TUNNEL_GEOS+=("🌐 Unknown")
            TUNNEL_LATENCIES+=("N/A")
        fi
        
    done < <(list_all_tunnels)
    
    # Display tunnel options
    echo -e "${BOLD}Available Tunnels:${NC}"
    echo ""
    
    local display_index=1
    for i in "${!TUNNEL_IDS[@]}"; do
        local id="${TUNNEL_IDS[$i]}"
        local name="${TUNNEL_NAMES[$i]}"
        local status="${TUNNEL_STATUSES[$i]}"
        local port="${TUNNEL_PORTS[$i]}"
        local geo="${TUNNEL_GEOS[$i]}"
        local latency="${TUNNEL_LATENCIES[$i]}"
        
        # Status indicator
        local status_indicator=""
        if [[ "$status" == "active" ]]; then
            status_indicator="${GREEN}●${NC}"
        else
            status_indicator="${YELLOW}○${NC}"
        fi
        
        # Current selection indicator
        local selector=""
        if [[ "$id" == "$CURRENT_ID" ]]; then
            selector="${MAGENTA}▶${NC} "
        else
            selector="  "
        fi
        
        # Format latency
        local latency_display=""
        if [[ "$latency" != "N/A" ]]; then
            latency_display="${DIM}${latency}ms${NC}"
        else
            latency_display="${DIM}N/A${NC}"
        fi
        
        printf "%s%d) ${BOLD}%s${NC} %s | %s | Port:%s | %s\n" \
            "$selector" \
            "$display_index" \
            "$name" \
            "$status_indicator" \
            "$geo" \
            "$port" \
            "$latency_display"
        
        ((display_index++))
    done
    
    echo ""
    echo -e "${DIM}Legend: ● = active status | ○ = inactive | ▶ = currently selected${NC}"
    echo ""
    
    read -p "Select tunnel (1-${#TUNNEL_IDS[@]}) or 0 to cancel: " selection
    
    if [[ "$selection" == "0" ]]; then
        return 0
    fi
    
    if ! [[ "$selection" =~ ^[0-9]+$ ]] || (( selection < 1 || selection > ${#TUNNEL_IDS[@]} )); then
        print_error "Invalid selection"
        return 1
    fi
    
    local selected_index=$((selection - 1))
    local selected_id="${TUNNEL_IDS[$selected_index]}"
    local selected_name="${TUNNEL_NAMES[$selected_index]}"
    local selected_geo="${TUNNEL_GEOS[$selected_index]}"
    
    # Check if need to stop and restart
    if [[ "$selected_id" != "$CURRENT_ID" ]]; then
        echo ""
        print_step "Switching tunnel to: $selected_name ($selected_geo)"
        echo ""
        
        if check_tunnel_listening; then
            print_step "Stopping current tunnel..."
            stop_tunnel > /dev/null 2>&1 || true
            sleep 2
        fi
        
        # Save new active tunnel
        echo "$selected_id" > "$ACTIVE_TUNNEL_STATE"
        
        print_step "Starting new tunnel: $selected_name"
        start_tunnel
        
        print_success "Successfully switched to: $selected_name"
        log_action "Switched tunnel to: $selected_name ($selected_id)"
    else
        print_info "Already using: $selected_name"
    fi
    
    echo ""
}

# ──────────────────────────────────────────────────────────────────────────────
# SERVICE OPERATIONS
# ──────────────────────────────────────────────────────────────────────────────

start_tunnel() {
    print_section "▶️  STARTING CLOUDFLARE TUNNEL"
    
    if check_tunnel_listening; then
        print_error "Tunnel already running (PID: $(get_tunnel_pid))"
        return 1
    fi
    
    # Read tunnel config from active tunnel state or CSV
    local ACTIVE_ID=$(get_active_tunnel_id)
    local TUNNEL_TOKEN=$(get_tunnel_token "$ACTIVE_ID")
    local TUNNEL_NAME=$(get_tunnel_name "$ACTIVE_ID")
    
    if [[ -z "$TUNNEL_TOKEN" ]]; then
        print_error "No active tunnel found in $TUNNELS_CSV"
        print_info "Make sure you have configured tunnels in the CSV"
        return 1
    fi
    
    print_step "Launching tunnel: $TUNNEL_NAME"
    print_info "Tunnel ID: $ACTIVE_ID"
    print_info "Token source: $TUNNELS_CSV"
    
    nohup cloudflared tunnel run --token "$TUNNEL_TOKEN" > "$LOG_FILE" 2>&1 &
    local PID=$!
    
    sleep 3
    
    if check_tunnel_listening; then
        local ACTUAL_PID=$(get_tunnel_pid)
        print_success "Tunnel started successfully (PID: $ACTUAL_PID)"
        print_info "✅ Using settings from: $TUNNELS_CSV"
        log_action "Tunnel started (PID: $ACTUAL_PID) - Tunnel: $TUNNEL_NAME"
        return 0
    else
        print_error "Tunnel failed to start"
        print_info "Last 20 lines of log:"
        tail -20 "$LOG_FILE"
        log_action "ERROR: Tunnel failed to start - $TUNNEL_NAME"
        return 1
    fi
}

stop_tunnel() {
    print_section "⏹️  STOPPING CLOUDFLARE TUNNEL"
    
    if ! check_tunnel_listening; then
        print_error "Tunnel is not running"
        return 1
    fi
    
    print_step "Terminating tunnel process..."
    
    # Graceful termination
    pkill -f "$PROCESS_NAME" 2>/dev/null
    sleep 2
    
    # Force kill if necessary
    if pgrep -f "$PROCESS_NAME" > /dev/null; then
        pkill -9 -f "$PROCESS_NAME" 2>/dev/null
        sleep 1
    fi
    
    if ! check_tunnel_listening; then
        print_success "Tunnel stopped successfully"
        log_action "Tunnel stopped"
        return 0
    else
        print_error "Failed to stop tunnel completely"
        log_action "ERROR: Failed to stop tunnel"
        return 1
    fi
}

reset_tunnel() {
    print_section "🔄 RESETTING CLOUDFLARE TUNNEL"
    
    print_step "Stopping tunnel..."
    stop_tunnel
    
    echo ""
    print_step "Clearing log file..."
    > "$LOG_FILE"
    print_success "Log cleared"
    
    echo ""
    print_step "Restarting tunnel..."
    start_tunnel
    
    echo ""
    print_section "✅ RESET COMPLETE"
    print_success "Tunnel has been reset and restarted"
}

# ──────────────────────────────────────────────────────────────────────────────
# CSV TUNNEL MANAGEMENT
# ──────────────────────────────────────────────────────────────────────────────

initialize_tunnels_csv() {
    if [[ ! -f "$TUNNELS_CSV" ]]; then
        cat > "$TUNNELS_CSV" << 'EOF'
tunnel_id,tunnel_name,domain,token,status,redirect_port,edge_ips,routes,clients,latency_ms,created_date,notes
tunnel_01,Primary Tunnel,service-proxy-1.md5.workers.dev,eyJhIjoiNzM4NjAwZWE2Mzg2NmJkYTYwNjUwZGI4NGZjMTFjYTMiLCJ0IjoiZTJiOTgxNGMtN2EwYy00YjU5LWIwNWMtNWZiNjFiYTJiYmE3IiwicyI6Ik5XVmhZamt5TW1JdE1HVmtNUzAwWldabUxUZzROekt0WVRreE0yRmhNelV4TVdaaSJ9,active,8089,104.21.23.45;162.159.124.67,localhost:3000,5,45,2024-01-15,US-West Primary
tunnel_02,Secondary Tunnel,service-proxy-2.md5.workers.dev,eyJhIjoiNzM4NjAwZWE2Mzg2NmJkYTYwNjUwZGI4NGZjMTFjYTMiLCJ0IjoiOGI1NTVlMTYtM2M5YS00MzhiLWExMjctODY3NjYxNTg0ZGYxIiwicyI6Ik5qTTVOVFJoTlRNdFlqSXhOe,active,8090,104.16.132.45;162.159.135.42,localhost:3001,3,62,2024-01-20,EU-Central Backup
EOF
        print_success "Created tunnels.csv"
    fi
}

add_tunnel() {
    print_section "➕ ADD NEW TUNNEL"
    
    read -p "Enter tunnel ID (e.g., tunnel_03): " TUNNEL_ID
    read -p "Enter tunnel name: " TUNNEL_NAME
    read -p "Enter domain: " DOMAIN
    read -p "Enter tunnel token: " TUNNEL_TOKEN
    read -p "Enter status (active/inactive): " TUNNEL_STATUS
    read -p "Enter redirect port: " REDIRECT_PORT
    read -p "Enter edge IPs (comma-separated): " EDGE_IPS
    read -p "Enter notes (optional): " TUNNEL_NOTES
    
    local CREATION_DATE=$(date '+%Y-%m-%d')
    
    echo "$TUNNEL_ID,$TUNNEL_NAME,$DOMAIN,$TUNNEL_TOKEN,$TUNNEL_STATUS,$REDIRECT_PORT,$EDGE_IPS,localhost:3000,0,0,$CREATION_DATE,$TUNNEL_NOTES" >> "$TUNNELS_CSV"
    
    print_success "Tunnel added to tunnels.csv"
    echo ""
    echo "Tunnel Details:"
    echo "  ID: $TUNNEL_ID"
    echo "  Name: $TUNNEL_NAME"
    echo "  Domain: $DOMAIN"
    echo "  Status: $TUNNEL_STATUS"
    echo "  Redirect Port: $REDIRECT_PORT"
    echo "  Edge IPs: $EDGE_IPS"
    echo "  Notes: $TUNNEL_NOTES"
    
    log_action "Added tunnel: $TUNNEL_NAME ($TUNNEL_ID)"
}

delete_tunnel() {
    print_section "🗑️  DELETE TUNNEL FROM CSV"
    
    if [[ ! -f "$TUNNELS_CSV" ]]; then
        print_error "Tunnels CSV file not found"
        return 1
    fi
    
    print_info "Available tunnels:"
    echo ""
    awk -F',' 'NR>1 {printf "  %d. %s (ID: %s | Status: %s)\n", NR-1, $2, $1, $5}' "$TUNNELS_CSV"
    echo ""
    
    read -p "Enter tunnel number to delete: " TUNNEL_NUM
    
    local LINE_TO_DELETE=$((TUNNEL_NUM + 1))
    local TUNNEL_NAME=$(sed -n "${LINE_TO_DELETE}p" "$TUNNELS_CSV" | cut -d',' -f2)
    
    if [[ -z "$TUNNEL_NAME" ]]; then
        print_error "Invalid selection"
        return 1
    fi
    
    # Backup and delete
    cp "$TUNNELS_CSV" "${TUNNELS_CSV}.bak"
    sed -i '' "${LINE_TO_DELETE}d" "$TUNNELS_CSV"
    
    print_success "Tunnel '$TUNNEL_NAME' deleted from tunnels.csv"
    print_info "Backup saved to: ${TUNNELS_CSV}.bak"
    
    log_action "Deleted tunnel: $TUNNEL_NAME"
}

list_tunnels() {
    print_section "📋 TUNNELS INVENTORY"
    
    if [[ ! -f "$TUNNELS_CSV" ]]; then
        print_error "Tunnels CSV file not found"
        initialize_tunnels_csv
    fi
    
    local CURRENT_ID=$(get_active_tunnel_id)
    
    echo ""
    echo -e "${BOLD}ID${NC} | ${BOLD}NAME${NC} | ${BOLD}STATUS${NC} | ${BOLD}PORT${NC} | ${BOLD}EDGE IPs${NC} | ${BOLD}NOTES${NC}"
    echo "─────────────────────────────────────────────────────────────────────────────────────"
    
    awk -F',' -v current="$CURRENT_ID" '
    NR>1 {
        indicator = ($1 == current) ? "▶ " : "  "
        printf "%s%-10s | %-20s | %-8s | %-5s | %-25s | %s\n", 
            indicator, $1, $2, $5, $6, substr($7, 1, 25), $12
    }' "$TUNNELS_CSV"
    
    echo ""
    echo -e "${DIM}Legend: ▶ = currently active tunnel${NC}"
    echo "Total tunnels: $(tail -n +2 "$TUNNELS_CSV" | wc -l)"
    echo ""
}

# ──────────────────────────────────────────────────────────────────────────────
# MENU & MAIN
# ──────────────────────────────────────────────────────────────────────────────

show_menu() {
    echo ""
    echo -e "${BOLD}Operations:${NC}"
    echo ""
    echo "  1️⃣  Start Tunnel"
    echo "  2️⃣  Stop Tunnel"
    echo "  3️⃣  Reset Tunnel"
    echo "  4️⃣  Tunnel Status"
    echo ""
    echo -e "${BOLD}Socket Management:${NC}"
    echo "  5️⃣  🔌 Switch Tunnel/Socket (GEO-aware)"
    echo ""
    echo -e "${BOLD}Tunnel Configuration:${NC}"
    echo "  6️⃣  Add New Tunnel"
    echo "  7️⃣  Delete Tunnel"
    echo "  8️⃣  List All Tunnels"
    echo ""
    echo "  0️⃣  Exit"
    echo ""
}

main() {
    # Initialize CSV if needed
    initialize_tunnels_csv
    
    # Ensure active tunnel state exists
    if [[ ! -f "$ACTIVE_TUNNEL_STATE" ]]; then
        local first_tunnel=$(awk -F',' 'NR==2 {print $1}' "$TUNNELS_CSV")
        echo "$first_tunnel" > "$ACTIVE_TUNNEL_STATE"
    fi
    
    if [[ $# -eq 0 ]]; then
        # Interactive mode
        while true; do
            print_header
            show_menu
            
            read -p "Select operation: " choice
            
            case $choice in
                1) start_tunnel ;;
                2) stop_tunnel ;;
                3) reset_tunnel ;;
                4) print_status ;;
                5) tunnel_switcher ;;
                6) add_tunnel ;;
                7) delete_tunnel ;;
                8) list_tunnels ;;
                0) echo ""; print_info "Exiting..."; exit 0 ;;
                *) print_error "Invalid selection" ;;
            esac
            
            read -p "Press Enter to continue..."
        done
    else
        # Command mode
        case $1 in
            start) start_tunnel ;;
            stop) stop_tunnel ;;
            reset) reset_tunnel ;;
            status) print_status ;;
            switch) tunnel_switcher ;;
            add) add_tunnel ;;
            delete) delete_tunnel ;;
            list) list_tunnels ;;
            *) echo "Usage: $0 {start|stop|reset|status|switch|add|delete|list}"; exit 1 ;;
        esac
    fi
}

main "$@"
