#!/bin/bash

# ═══════════════════════════════════════════════════════════════════════════════
#                  🔒 NETWORK PROTECTION & IP WHITELISTING 🔒
# ═══════════════════════════════════════════════════════════════════════════════
#
# Professional multi-port IP whitelisting system for Cloudflare Tunnel
# 
# Architecture:
#   1️⃣  Reads service-routes.csv (port definitions)
#   2️⃣  Reads tunnel-whitelist.csv (LAN IP access control)
#   3️⃣  Creates per-port protection configs
#   4️⃣  Whitelists localhost + approved LAN IPs
#   5️⃣  Blocks all unauthorized IPs with 403 Forbidden
#
# CSV Integration:
#   - service-routes.csv: port,protocol,destination_ip,destination_port,status,description
#   - tunnel-whitelist.csv: lan_ip,device_name,status,created_date,notes
#
# Output:
#   - /tmp/port-*.json: Per-port whitelist configurations
#   - /tmp/network-protect.log: Detailed operation log
#   - /tmp/blocked-ips.log: Access attempt log for blocked IPs
#
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────
# COLORS & FORMATTING
# ─────────────────────────────────────────────────────────────────────────
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'

# ─────────────────────────────────────────────────────────────────────────
# CONFIGURATION - CSV PATHS (SOURCE OF TRUTH)
# ─────────────────────────────────────────────────────────────────────────
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SERVICE_DIR="/Users/rcsp2/Documents/service"
readonly CORE_SERVICE_DIR="${SERVICE_DIR}/core-service"
readonly CLOUDFLARE_TUNNEL_DIR="${CORE_SERVICE_DIR}/cloudflare-tunnel"
readonly LAN_PROXY_DIR="${CORE_SERVICE_DIR}/lan-proxy"

# CSV Files (source of truth)
readonly SERVICE_ROUTES_CSV="${CLOUDFLARE_TUNNEL_DIR}/service-routes.csv"
readonly TUNNEL_WHITELIST_CSV="${CORE_SERVICE_DIR}/tunnel-whitelist.csv"

# Output directories
readonly CONFIG_OUTPUT_DIR="/tmp"
readonly LOG_FILE="${CONFIG_OUTPUT_DIR}/network-protect.log"
readonly BLOCKED_LOG="${CONFIG_OUTPUT_DIR}/blocked-ips.log"

# ─────────────────────────────────────────────────────────────────────────
# UTILITY FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────

print_header() {
    clear
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}${BOLD}   🔒 NETWORK PROTECTION & IP WHITELISTING SYSTEM 🔒${NC}${CYAN}   ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_step() {
    echo -e "${BLUE}▶${NC} $1"
}

print_success() {
    echo -e "${GREEN}✅${NC} $1"
}

print_error() {
    echo -e "${RED}❌${NC} $1" >&2
}

print_warning() {
    echo -e "${YELLOW}⚠️${NC}  $1"
}

log_action() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# ─────────────────────────────────────────────────────────────────────────
# CSV VALIDATION & READING FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────

validate_csv_exists() {
    local csv_file="$1"
    local csv_name="$2"
    
    if [[ ! -f "$csv_file" ]]; then
        print_error "Missing required CSV: $csv_name"
        print_error "Expected at: $csv_file"
        return 1
    fi
    return 0
}

get_user_local_ip() {
    # Detect your local IP (for whitelisting)
    # Works on macOS and Linux
    local ip=$(ifconfig en0 2>/dev/null | grep "inet " | awk '{print $2}' | head -1)
    [ -z "$ip" ] && ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    [ -z "$ip" ] && ip="127.0.0.1"  # Fallback to localhost only
    echo "$ip"
}

get_approved_lan_ips() {
    # Read tunnel-whitelist.csv and return all IPs with status="allowed"
    local ips=()
    
    if [[ ! -f "$TUNNEL_WHITELIST_CSV" ]]; then
        # If whitelist doesn't exist, only allow localhost
        ips+=("127.0.0.1")
    else
        # Skip header, get all rows with status="allowed"
        while IFS=',' read -r lan_ip device_name status created_date notes; do
            # Skip header and empty lines
            [[ "$lan_ip" == "lan_ip" ]] && continue
            [[ -z "$lan_ip" ]] && continue
            
            # Add to approved list if status is "allowed"
            if [[ "$status" == "allowed" ]]; then
                ips+=("$lan_ip")
            fi
        done < "$TUNNEL_WHITELIST_CSV"
    fi
    
    # Always include localhost
    if [[ ! " ${ips[@]} " =~ " 127.0.0.1 " ]]; then
        ips+=("127.0.0.1")
    fi
    
    # Return as space-separated string
    echo "${ips[@]}"
}

get_open_ports() {
    # Read service-routes.csv and return all ports with status="open" or status="forwarding"
    local ports=()
    
    if [[ ! -f "$SERVICE_ROUTES_CSV" ]]; then
        return 0
    fi
    
    # Skip header, get all rows with status="open"
    while IFS=',' read -r port protocol destination_ip destination_port status description; do
        # Skip header and empty lines
        [[ "$port" == "port" ]] && continue
        [[ -z "$port" ]] && continue
        
        # Add to open ports if status is "open"
        if [[ "$status" == "open" ]]; then
            ports+=("$port")
        fi
    done < "$SERVICE_ROUTES_CSV"
    
    # Return as space-separated string
    echo "${ports[@]}"
}

# ─────────────────────────────────────────────────────────────────────────
# PORT PROTECTION CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────

create_port_whitelist_config() {
    local port="$1"
    local approved_ips="$2"
    local config_file="${CONFIG_OUTPUT_DIR}/port-${port}-whitelist.json"
    
    # Create JSON whitelist configuration for this port
    cat > "$config_file" << EOF
{
  "port": $port,
  "protection_type": "ip-whitelist",
  "whitelist": [
EOF
    
    # Add each approved IP to the whitelist
    local first=true
    for ip in $approved_ips; do
        if [[ "$first" == true ]]; then
            echo "    \"$ip\"" >> "$config_file"
            first=false
        else
            echo "    ,\"$ip\"" >> "$config_file"
        fi
    done
    
    # Close JSON
    cat >> "$config_file" << EOF
  ],
  "action": "allow",
  "fallback": "deny_with_403",
  "log_blocked_attempts": true,
  "created_date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "managed_by": "network-protect.sh"
}
EOF
    
    log_action "Created whitelist config for port $port: $config_file"
    return 0
}

# ─────────────────────────────────────────────────────────────────────────
# LAN PROXY INTEGRATION
# ─────────────────────────────────────────────────────────────────────────

integrate_with_lan_proxy() {
    # Create/update network-config.json for LAN Proxy with approved IPs
    local lan_proxy_config="${LAN_PROXY_DIR}/network-config.json"
    local approved_ips="$1"
    
    if [[ ! -d "$LAN_PROXY_DIR" ]]; then
        print_warning "LAN Proxy directory not found at $LAN_PROXY_DIR"
        return 0
    fi
    
    print_step "Creating LAN Proxy network configuration..."
    
    # Create JSON config with whitelisted IPs
    cat > "$lan_proxy_config" << EOF
{
  "security": {
    "ip_filtering": "enabled",
    "whitelist_mode": true
  },
  "whitelisted_ips": [
EOF
    
    # Add approved IPs
    local first=true
    for ip in $approved_ips; do
        if [[ "$first" == true ]]; then
            echo "    \"$ip\"" >> "$lan_proxy_config"
            first=false
        else
            echo "    ,\"$ip\"" >> "$lan_proxy_config"
        fi
    done
    
    # Close JSON
    cat >> "$lan_proxy_config" << EOF
  ],
  "blocked_response": {
    "status_code": 403,
    "message": "Access Forbidden - IP not whitelisted"
  },
  "created_date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "managed_by": "network-protect.sh"
}
EOF
    
    print_success "LAN Proxy network config created at: $lan_proxy_config"
    log_action "Integrated with LAN Proxy - config: $lan_proxy_config"
    return 0
}

# ─────────────────────────────────────────────────────────────────────────
# TUNNEL-WHITELIST CSV INITIALIZATION
# ─────────────────────────────────────────────────────────────────────────

initialize_tunnel_whitelist() {
    if [[ -f "$TUNNEL_WHITELIST_CSV" ]]; then
        return 0  # Already exists
    fi
    
    print_step "Initializing tunnel-whitelist.csv..."
    
    local user_ip=$(get_user_local_ip)
    
    cat > "$TUNNEL_WHITELIST_CSV" << EOF
lan_ip,device_name,status,created_date,notes
127.0.0.1,Localhost,allowed,$(date +%Y-%m-%d),Local machine only - always allowed
$user_ip,Main Device,allowed,$(date +%Y-%m-%d),Primary workstation - tunnel access enabled
EOF
    
    print_success "Created tunnel-whitelist.csv at: $TUNNEL_WHITELIST_CSV"
    log_action "Initialized tunnel-whitelist.csv with user IP: $user_ip"
    return 0
}

# ─────────────────────────────────────────────────────────────────────────
# MAIN PROTECTION SETUP
# ─────────────────────────────────────────────────────────────────────────

setup_network_protection() {
    print_header
    
    # Initialize log file
    > "$LOG_FILE"
    > "$BLOCKED_LOG"
    log_action "Network protection started"
    
    print_step "Validating CSV files..."
    
    # Ensure tunnel-whitelist.csv exists
    initialize_tunnel_whitelist
    
    # Validate service-routes.csv
    if ! validate_csv_exists "$SERVICE_ROUTES_CSV" "service-routes.csv"; then
        print_error "Cannot proceed without service-routes.csv"
        log_action "ERROR: Missing service-routes.csv"
        return 1
    fi
    print_success "service-routes.csv found"
    
    # Validate tunnel-whitelist.csv
    if ! validate_csv_exists "$TUNNEL_WHITELIST_CSV" "tunnel-whitelist.csv"; then
        print_error "Cannot proceed without tunnel-whitelist.csv"
        log_action "ERROR: Missing tunnel-whitelist.csv"
        return 1
    fi
    print_success "tunnel-whitelist.csv found"
    
    echo ""
    print_step "Reading port definitions from service-routes.csv..."
    
    # Get all open ports
    local open_ports_str=$(get_open_ports)
    local open_ports=($open_ports_str)
    
    if [[ ${#open_ports[@]} -eq 0 ]]; then
        print_warning "No ports marked as 'open' in service-routes.csv"
        log_action "No open ports found in service-routes.csv"
        return 0
    fi
    
    echo -e "${CYAN}Protected ports:${NC}"
    for port in "${open_ports[@]}"; do
        echo "  • Port $port"
    done
    echo ""
    
    print_step "Reading approved LAN IPs from tunnel-whitelist.csv..."
    
    # Get all approved IPs
    local approved_ips_str=$(get_approved_lan_ips)
    local approved_ips=($approved_ips_str)
    
    echo -e "${CYAN}Whitelisted IPs (approved for tunnel access):${NC}"
    for ip in "${approved_ips[@]}"; do
        echo "  • $ip"
    done
    echo ""
    
    # Create per-port protection configs
    print_step "Creating per-port protection configurations..."
    for port in "${open_ports[@]}"; do
        create_port_whitelist_config "$port" "$approved_ips_str"
        echo "  ✓ Port $port configured"
    done
    echo ""
    
    # Integrate with LAN Proxy
    integrate_with_lan_proxy "$approved_ips_str"
    echo ""
    
    # Print protection summary
    print_protection_summary
    
    log_action "Network protection setup completed successfully"
    return 0
}

print_protection_summary() {
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}${BOLD}              🎯 PROTECTION STATUS REPORT 🎯${NC}${CYAN}              ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    local open_ports=$(get_open_ports)
    local approved_ips_str=$(get_approved_lan_ips)
    local approved_ips=($approved_ips_str)
    
    echo -e "${GREEN}✅ PROTECTION ENABLED${NC}"
    echo ""
    
    echo "📋 Configuration Files:"
    echo "  • Service Routes CSV: $SERVICE_ROUTES_CSV"
    echo "  • Tunnel Whitelist CSV: $TUNNEL_WHITELIST_CSV"
    echo ""
    
    echo "🔒 Protected Ports:"
    for port in $open_ports; do
        echo "  ✓ Port $port → /tmp/port-${port}-whitelist.json"
    done
    echo ""
    
    echo "✨ Whitelisted IPs:"
    for ip in "${approved_ips[@]}"; do
        echo "  ✓ $ip"
    done
    echo ""
    
    echo "📊 Access Control:"
    echo "  • Authorized IPs: ${#approved_ips[@]} IPs allowed"
    echo "  • Unauthorized IPs: 403 Forbidden response"
    echo "  • Logging: /tmp/blocked-ips.log"
    echo ""
    
    echo "🔄 Integration:"
    echo "  • LAN Proxy: Network config created"
    echo "  • Cloudflare Tunnel: Port configs available"
    echo ""
    
    echo "📝 Logs:"
    echo "  • Operations: $LOG_FILE"
    echo "  • Blocked IPs: $BLOCKED_LOG"
    echo ""
    
    echo -e "${YELLOW}⚠️  Note:${NC} To modify tunnel access:"
    echo "  1. Edit: $TUNNEL_WHITELIST_CSV"
    echo "  2. Change IP status from 'blocked' to 'allowed' (or vice versa)"
    echo "  3. Run this script again to regenerate configs"
    echo ""
}

# ─────────────────────────────────────────────────────────────────────────
# MANUAL OPERATIONS
# ─────────────────────────────────────────────────────────────────────────

list_whitelisted_ips() {
    echo ""
    print_header
    echo -e "${CYAN}Current Whitelisted IPs (from tunnel-whitelist.csv):${NC}"
    echo ""
    
    if [[ ! -f "$TUNNEL_WHITELIST_CSV" ]]; then
        print_error "tunnel-whitelist.csv not found"
        return 1
    fi
    
    # Display as formatted table
    echo "LAN IP          Device Name      Status        Created Date"
    echo "────────────────────────────────────────────────────────────────"
    
    while IFS=',' read -r lan_ip device_name status created_date notes; do
        [[ "$lan_ip" == "lan_ip" ]] && continue
        [[ -z "$lan_ip" ]] && continue
        
        printf "%-15s %-16s %-13s %s\n" "$lan_ip" "$device_name" "$status" "$created_date"
    done < "$TUNNEL_WHITELIST_CSV"
    echo ""
}

add_whitelisted_ip() {
    local new_ip="$1"
    local device_name="${2:-Guest Device}"
    
    if [[ ! -f "$TUNNEL_WHITELIST_CSV" ]]; then
        print_error "tunnel-whitelist.csv not found"
        return 1
    fi
    
    # Append new IP
    echo "$new_ip,$device_name,allowed,$(date +%Y-%m-%d),Added via network-protect.sh" >> "$TUNNEL_WHITELIST_CSV"
    
    print_success "Added $new_ip to whitelist"
    print_step "Regenerating protection configs..."
    setup_network_protection
}

block_whitelisted_ip() {
    local block_ip="$1"
    
    if [[ ! -f "$TUNNEL_WHITELIST_CSV" ]]; then
        print_error "tunnel-whitelist.csv not found"
        return 1
    fi
    
    # Use sed to change status from "allowed" to "blocked"
    sed -i '' "/$block_ip/s/allowed/blocked/" "$TUNNEL_WHITELIST_CSV"
    
    print_success "Blocked $block_ip from tunnel access"
    print_step "Regenerating protection configs..."
    setup_network_protection
}

# ─────────────────────────────────────────────────────────────────────────
# CLI INTERFACE
# ─────────────────────────────────────────────────────────────────────────

show_menu() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}                    📋 OPERATIONS MENU 📋${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "  1) Setup/Update Protection (read CSVs)"
    echo "  2) List Whitelisted IPs"
    echo "  3) Add IP to Whitelist"
    echo "  4) Block IP from Tunnel Access"
    echo "  5) View Protection Log"
    echo "  6) View Blocked Attempts Log"
    echo "  7) Edit tunnel-whitelist.csv"
    echo "  8) Exit"
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

# ─────────────────────────────────────────────────────────────────────────
# MAIN EXECUTION
# ─────────────────────────────────────────────────────────────────────────

main() {
    case "${1:-setup}" in
        setup)
            setup_network_protection
            ;;
        list)
            list_whitelisted_ips
            ;;
        add)
            if [[ -z "${2:-}" ]]; then
                print_error "Usage: $0 add <ip> [device_name]"
                exit 1
            fi
            add_whitelisted_ip "$2" "${3:-}"
            ;;
        block)
            if [[ -z "${2:-}" ]]; then
                print_error "Usage: $0 block <ip>"
                exit 1
            fi
            block_whitelisted_ip "$2"
            ;;
        logs)
            cat "$LOG_FILE"
            ;;
        blocked)
            cat "$BLOCKED_LOG"
            ;;
        edit)
            if command -v nano &> /dev/null; then
                nano "$TUNNEL_WHITELIST_CSV"
            elif command -v vim &> /dev/null; then
                vim "$TUNNEL_WHITELIST_CSV"
            else
                print_error "No text editor found"
                exit 1
            fi
            setup_network_protection  # Regenerate after edits
            ;;
        *)
            setup_network_protection
            show_menu
            read -p "Select option: " choice
            case "$choice" in
                1) setup_network_protection ;;
                2) list_whitelisted_ips ;;
                3) 
                    read -p "Enter IP to whitelist: " ip
                    read -p "Device name: " device
                    add_whitelisted_ip "$ip" "$device"
                    ;;
                4)
                    read -p "Enter IP to block: " ip
                    block_whitelisted_ip "$ip"
                    ;;
                5) cat "$LOG_FILE" ;;
                6) cat "$BLOCKED_LOG" ;;
                7) nano "$TUNNEL_WHITELIST_CSV" && setup_network_protection ;;
                8) exit 0 ;;
                *) print_error "Invalid option" ;;
            esac
            ;;
    esac
}

# Execute
main "$@"
