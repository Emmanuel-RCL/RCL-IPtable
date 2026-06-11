#!/usr/bin/env bash
# ==============================================================================
# RCL-IPtable Pro - Production-Ready Multi-Server TCP/UDP Forwarding Manager
# Compatible: Ubuntu 22/24, Debian 11/12, AlmaLinux 8/9, RockyLinux 8/9
# ==============================================================================

set -o errexit
set -o pipefail
set -o nounset

# ==============================================================================
# GLOBAL VARIABLES & COLORS
# ==============================================================================
VERSION="1.2.3"
BASE_DIR="/etc/rcl-iptable"
DB_FILE="$BASE_DIR/routes.db"
BACKUP_DIR="$BASE_DIR/backups"
LOG_FILE="/var/log/rcl-iptable.log"
SYSCTL_CONF="/etc/sysctl.d/99-rcl-iptable.conf"
CHAIN_NAME="RCL_IPTABLE"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# ==============================================================================
# GLOBAL INSTALLER (Auto-install as 'rcl-iptable' command)
# ==============================================================================
INSTALL_PATH="/usr/local/bin/rcl-iptable"
CURRENT_PATH="$(readlink -f "$0")"

if [[ "$CURRENT_PATH" != "$INSTALL_PATH" ]]; then
    echo -e "${CYAN}Registering RCL-IPtable Pro as a global command...${NC}"
    cp "$CURRENT_PATH" "$INSTALL_PATH"
    chmod +x "$INSTALL_PATH"
    echo -e "${GREEN}Done! You can now use '${BOLD}rcl-iptable${NC}${GREEN}' in the future.${NC}"
    echo -e "${YELLOW}Starting the application now...${NC}\n"
fi

# ==============================================================================
# INITIALIZATION & SAFETY CHECKS
# ==============================================================================

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: This script must be run as root.${NC}"
   exit 1
fi

mkdir -p "$BASE_DIR" "$BACKUP_DIR"
touch "$LOG_FILE" "$DB_FILE"

log() {
    local level="$1"
    local msg="$2"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $msg" >> "$LOG_FILE"
}

detect_os() {
    if [[ -f /etc/debian_version ]]; then
        OS_FAMILY="debian"
    elif [[ -f /etc/redhat-release ]]; then
        OS_FAMILY="rhel"
    else
        OS_FAMILY="unknown"
    fi
}

detect_network() {
    DEFAULT_ROUTE=$(ip route show default | head -n 1)
    IFACE=$(echo "$DEFAULT_ROUTE" | grep -oP 'dev \K\S+')
    if [[ -z "$IFACE" ]]; then
        IFACE="eth0"
    fi
    MTU=$(cat /sys/class/net/"$IFACE"/mtu 2>/dev/null || echo "1500")
}

init_chains() {
    iptables -t nat -N "$CHAIN_NAME" 2>/dev/null || true
    iptables -N "$CHAIN_NAME" 2>/dev/null || true

    iptables -t nat -C PREROUTING -j "$CHAIN_NAME" 2>/dev/null || iptables -t nat -I PREROUTING 1 -j "$CHAIN_NAME"
    iptables -C FORWARD -j "$CHAIN_NAME" 2>/dev/null || iptables -I FORWARD 1 -j "$CHAIN_NAME"

    if ! iptables -t nat -C POSTROUTING -j MASQUERADE 2>/dev/null; then
        iptables -t nat -A POSTROUTING -j MASQUERADE
    fi

    if [[ $(sysctl -n net.ipv4.ip_forward) -ne 1 ]]; then
        sysctl -w net.ipv4.ip_forward=1 > /dev/null
        echo "net.ipv4.ip_forward=1" > "$SYSCTL_CONF"
        sysctl -p "$SYSCTL_CONF" > /dev/null
    elif ! grep -q "net.ipv4.ip_forward=1" "$SYSCTL_CONF" 2>/dev/null; then
        echo "net.ipv4.ip_forward=1" > "$SYSCTL_CONF"
    fi
}

save_iptables() {
    if [[ "$OS_FAMILY" == "debian" ]]; then
        if command -v netfilter-persistent >/dev/null; then
            netfilter-persistent save > /dev/null 2>&1
        elif command -v iptables-save >/dev/null; then
            mkdir -p /etc/iptables
            iptables-save > /etc/iptables/rules.v4 2>/dev/null
        fi
    elif [[ "$OS_FAMILY" == "rhel" ]]; then
        if command -v iptables-save >/dev/null; then
            iptables-save > /etc/sysconfig/iptables 2>/dev/null
        fi
    fi
}

# ==============================================================================
# VALIDATION FUNCTIONS
# ==============================================================================

validate_ip() {
    local ip="$1"
    local regex='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
    if [[ $ip =~ $regex ]]; then
        IFS='.' read -ra octets <<< "$ip"
        for octet in "${octets[@]}"; do
            if [[ $octet -gt 255 ]]; then return 1; fi
        done
        return 0
    else
        return 1
    fi
}

validate_port() {
    local port="$1"
    if [[ "$port" =~ ^[0-9]+$ ]] && [[ "$port" -ge 1 ]] && [[ "$port" -le 65535 ]]; then
        return 0
    fi
    return 1
}

# ==============================================================================
# DATABASE & ROUTING LOGIC
# ==============================================================================

get_next_id() {
    local max_id=0
    if [[ -s "$DB_FILE" ]]; then
        max_id=$(awk -F'|' 'NF==8 {if ($1+0 > max+0) max=$1} END {print max+0}' "$DB_FILE")
    fi
    echo $((max_id + 1))
}

add_iptables_rule() {
    local id="$1" proto="$2" lport="$3" rip="$4" rport="$5"
    
    if [[ "$proto" == "tcp" ]] || [[ "$proto" == "both" ]]; then
        iptables -t nat -A "$CHAIN_NAME" -p tcp --dport "$lport" -j DNAT --to-destination "$rip:$rport" -m comment --comment "RCL_ID_$id"
        iptables -A "$CHAIN_NAME" -p tcp -d "$rip" --dport "$rport" -j ACCEPT -m comment --comment "RCL_ID_$id"
    fi

    if [[ "$proto" == "udp" ]] || [[ "$proto" == "both" ]]; then
        iptables -t nat -A "$CHAIN_NAME" -p udp --dport "$lport" -j DNAT --to-destination "$rip:$rport" -m comment --comment "RCL_ID_$id"
        iptables -A "$CHAIN_NAME" -p udp -d "$rip" --dport "$rport" -j ACCEPT -m comment --comment "RCL_ID_$id"
    fi
}

remove_iptables_rule() {
    local id="$1"
    iptables -t nat -S | grep "RCL_ID_$id" | sed 's/-A/-D/' | while read rule; do iptables -t nat $rule 2>/dev/null || true; done
    iptables -S | grep "RCL_ID_$id" | sed 's/-A/-D/' | while read rule; do iptables $rule 2>/dev/null || true; done
}

rebuild_all_rules() {
    iptables -t nat -F "$CHAIN_NAME"
    iptables -F "$CHAIN_NAME"

    if [[ -s "$DB_FILE" ]]; then
        while IFS='|' read -r id enabled proto lport rip rport created modified; do
            if [[ "$enabled" -eq 1 ]]; then
                add_iptables_rule "$id" "$proto" "$lport" "$rip" "$rport"
            fi
        done < "$DB_FILE"
    fi
    save_iptables
}

# ==============================================================================
# HEADER & UI COMPONENTS
# ==============================================================================

print_header() {
    local active_routes=0 dest_servers=0
    local bbr_st="Disabled" fq_st="Disabled" mss_st="Disabled"

    if [[ -s "$DB_FILE" ]]; then
        active_routes=$(awk -F'|' '$2==1 {count++} END {print count+0}' "$DB_FILE")
        dest_servers=$(awk -F'|' '$2==1 {print $5}' "$DB_FILE" | sort -u | wc -l)
    fi

    [[ $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null) == "bbr" ]] && bbr_st="Enabled"
    [[ $(sysctl -n net.core.default_qdisc 2>/dev/null) == "fq" ]] && fq_st="Enabled"
    iptables -t mangle -C POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null && mss_st="Enabled"

    clear
    echo -e "${CYAN}======================================================${NC}"
    echo -e "${BOLD}       RCL-IPtable Pro v${VERSION}${NC}"
    echo -e "${CYAN}======================================================${NC}"
    echo -e " Interface     : ${BOLD}$IFACE${NC}"
    echo -e " MTU           : ${BOLD}$MTU${NC}"
    echo -e " Active Routes : ${BOLD}$active_routes${NC}"
    echo -e " Dest. Servers : ${BOLD}$dest_servers${NC}"
    echo -e " BBR Status    : ${GREEN}$bbr_st${NC}  |  FQ Status    : ${GREEN}$fq_st${NC}"
    echo -e " MSS Status    : ${GREEN}$mss_st${NC}"
    echo -e "${CYAN}======================================================${NC}"
}

press_enter() {
    echo -e "\n${YELLOW}Press [Enter] to continue...${NC}"
    read -r
}

# ==============================================================================
# 1. ADD ROUTE
# ==============================================================================

add_route() {
    print_header
    echo -e "${BOLD}--- Add New Route ---${NC}"
    
    echo "1. TCP"
    echo "2. UDP"
    echo "3. TCP+UDP"
    echo -n "Select Protocol [1-3]: "
    read -r proto_opt
    case $proto_opt in
        1) proto="tcp" ;;
        2) proto="udp" ;;
        3) proto="both" ;;
        *) echo -e "${RED}Invalid selection.${NC}"; press_enter; return ;;
    esac

    echo -n "Enter Destination Server IP: "
    read -r rip
    if ! validate_ip "$rip"; then
        echo -e "${RED}Invalid IP address.${NC}"; press_enter; return
    fi

    echo -n "Enter Local Port: "
    read -r lport
    if ! validate_port "$lport"; then
        echo -e "${RED}Invalid port (1-65535).${NC}"; press_enter; return
    fi

    echo -n "Enter Remote Port: "
    read -r rport
    if ! validate_port "$rport"; then
        echo -e "${RED}Invalid port (1-65535).${NC}"; press_enter; return
    fi

    # Conflict Detection
    local conflict_id=$(awk -F'|' -v lp="$lport" '$4==lp {print $1}' "$DB_FILE")
    if [[ -n "$conflict_id" ]]; then
        echo -e "\n${YELLOW}Conflict Detected! Port $lport is already routed.${NC}"
        local c_line=$(grep "^${conflict_id}|" "$DB_FILE")
        echo -e "Existing Route: ${RED}$c_line${NC}"
        echo -e "1. Replace Existing Route"
        echo -e "2. View Existing Route"
        echo -e "0. Cancel"
        echo -n "Select option: "
        read -r c_opt
        case $c_opt in
            1) 
                remove_iptables_rule "$conflict_id"
                sed -i "/^${conflict_id}|/d" "$DB_FILE"
                log "INFO" "Replaced route ID $conflict_id due to conflict."
                ;;
            2) 
                grep "^${conflict_id}|" "$DB_FILE"
                press_enter
                return
                ;;
            0|*) return ;;
        esac
    fi

    local id=$(get_next_id)
    local timestamp=$(date +%s)
    
    echo "$id|1|$proto|$lport|$rip|$rport|$timestamp|$timestamp" >> "$DB_FILE"
    add_iptables_rule "$id" "$proto" "$lport" "$rip" "$rport"
    save_iptables
    
    log "INFO" "Added route ID $id: $proto $lport -> $rip:$rport"
    echo -e "${GREEN}Route added successfully (ID: $id).${NC}"
    press_enter
}

# ==============================================================================
# 2. EDIT ROUTE
# ==============================================================================

edit_route_menu() {
    if [[ ! -s "$DB_FILE" ]]; then echo -e "${YELLOW}No routes found.${NC}"; press_enter; return; fi
    
    print_header
    echo -e "${BOLD}--- Select Route to Edit ---${NC}"
    awk -F'|' '{printf "%-5s | %-6s | %-8s | %-15s | %-8s\n", $1, $3, $4, $5, $6}' "$DB_FILE"
    echo -e "-----------------------------------------------"
    echo -n "Enter Route ID (0 to cancel): "
    read -r eid
    
    if [[ "$eid" == "0" ]] || ! awk -F'|' -v id="$eid" '$1==id {found=1} END {exit !found}' "$DB_FILE"; then
        return
    fi

    while true; do
        print_header
        local route_data=$(grep "^${eid}|" "$DB_FILE")
        echo -e "Editing: ${CYAN}$route_data${NC}\n"
        echo "1. Change Destination IP"
        echo "2. Change Local Port"
        echo "3. Change Remote Port"
        echo "4. Change Protocol"
        echo "5. Enable Route"
        echo "6. Disable Route"
        echo "7. Delete Route"
        echo "8. View Statistics"
        echo "9. Health Check"
        echo "0. Back"
        echo -n "Select option: "
        read -r e_opt

        case $e_opt in
            1) 
                echo -n "Enter new Destination IP: "; read -r n_ip
                if validate_ip "$n_ip"; then
                    remove_iptables_rule "$eid"
                    sed -i "s/^\(${eid}|[^|]*|[^|]*|[^|]*|\)[^|]*/\1${n_ip}/" "$DB_FILE"
                    local e_proto=$(awk -F'|' -v id="$eid" '$1==id{print $3}' "$DB_FILE")
                    local e_lp=$(awk -F'|' -v id="$eid" '$1==id{print $4}' "$DB_FILE")
                    local e_rp=$(awk -F'|' -v id="$eid" '$1==id{print $6}' "$DB_FILE")
                    local e_en=$(awk -F'|' -v id="$eid" '$1==id{print $2}' "$DB_FILE")
                    [[ "$e_en" -eq 1 ]] && add_iptables_rule "$eid" "$e_proto" "$e_lp" "$n_ip" "$e_rp"
                    save_iptables; log "INFO" "Edited IP for ID $eid"; 
                else echo -e "${RED}Invalid IP.${NC}"; fi
                ;;
            2)
                echo -n "Enter new Local Port: "; read -r n_lp
                if validate_port "$n_lp"; then
                    remove_iptables_rule "$eid"
                    sed -i "s/^\(${eid}|[^|]*|[^|]*|\)[^|]*/\1${n_lp}/" "$DB_FILE"
                    local e_proto=$(awk -F'|' -v id="$eid" '$1==id{print $3}' "$DB_FILE")
                    local e_rip=$(awk -F'|' -v id="$eid" '$1==id{print $5}' "$DB_FILE")
                    local e_rp=$(awk -F'|' -v id="$eid" '$1==id{print $6}' "$DB_FILE")
                    local e_en=$(awk -F'|' -v id="$eid" '$1==id{print $2}' "$DB_FILE")
                    [[ "$e_en" -eq 1 ]] && add_iptables_rule "$eid" "$e_proto" "$n_lp" "$e_rip" "$e_rp"
                    save_iptables; log "INFO" "Edited Local Port for ID $eid";
                else echo -e "${RED}Invalid Port.${NC}"; fi
                ;;
            3)
                echo -n "Enter new Remote Port: "; read -r n_rp
                if validate_port "$n_rp"; then
                    remove_iptables_rule "$eid"
                    sed -i "s/^\(${eid}|[^|]*|[^|]*|[^|]*|[^|]*|\)[^|]*/\1${n_rp}/" "$DB_FILE"
                    local e_proto=$(awk -F'|' -v id="$eid" '$1==id{print $3}' "$DB_FILE")
                    local e_rip=$(awk -F'|' -v id="$eid" '$1==id{print $5}' "$DB_FILE")
                    local e_lp=$(awk -F'|' -v id="$eid" '$1==id{print $4}' "$DB_FILE")
                    local e_en=$(awk -F'|' -v id="$eid" '$1==id{print $2}' "$DB_FILE")
                    [[ "$e_en" -eq 1 ]] && add_iptables_rule "$eid" "$e_proto" "$e_lp" "$e_rip" "$n_rp"
                    save_iptables; log "INFO" "Edited Remote Port for ID $eid";
                else echo -e "${RED}Invalid Port.${NC}"; fi
                ;;
            4)
                echo "1. TCP"
                echo "2. UDP"
                echo "3. TCP+UDP"
                echo -n "Select new Protocol [1-3]: "
                read -r proto_opt
                case $proto_opt in
                    1) n_pr="tcp" ;;
                    2) n_pr="udp" ;;
                    3) n_pr="both" ;;
                    *) echo -e "${RED}Invalid selection.${NC}"; continue ;;
                esac
                remove_iptables_rule "$eid"
                sed -i "s/^\(${eid}|[^|]*|\)[^|]*/\1${n_pr}/" "$DB_FILE"
                local e_lp=$(awk -F'|' -v id="$eid" '$1==id{print $4}' "$DB_FILE")
                local e_rip=$(awk -F'|' -v id="$eid" '$1==id{print $5}' "$DB_FILE")
                local e_rp=$(awk -F'|' -v id="$eid" '$1==id{print $6}' "$DB_FILE")
                local e_en=$(awk -F'|' -v id="$eid" '$1==id{print $2}' "$DB_FILE")
                [[ "$e_en" -eq 1 ]] && add_iptables_rule "$eid" "$n_pr" "$e_lp" "$e_rip" "$e_rp"
                save_iptables; log "INFO" "Edited Protocol for ID $eid";
                ;;
            5) sed -i "s/^\(${eid}|\)[01]/\11/" "$DB_FILE"; rebuild_all_rules; log "INFO" "Enabled ID $eid" ;;
            6) sed -i "s/^\(${eid}|\)[01]/\10/" "$DB_FILE"; rebuild_all_rules; log "INFO" "Disabled ID $eid" ;;
            7) delete_route_logic "$eid" ; return ;;
            8) view_statistics_single "$eid" ;;
            9) health_check_single "$eid" ;;
            0) return ;;
        esac
        press_enter
    done
}

# ==============================================================================
# 3. ROUTE TABLE
# ==============================================================================

route_table() {
    print_header
    echo -e "${BOLD}--- Route Table (Cisco Style) ---${NC}"
    printf "${BOLD}%-5s | %-8s | %-11s | %-15s | %-11s | %-8s${NC}\n" "ID" "Protocol" "Local Port" "Dest IP" "Remote Port" "Status"
    echo "-----------------------------------------------------------------------"
    if [[ -s "$DB_FILE" ]]; then
        awk -F'|' '{
            status = ($2==1 ? "\033[32mActive\033[0m" : "\033[31mDisabled\033[0m")
            printf "%-5s | %-8s | %-11s | %-15s | %-11s | %s\n", $1, toupper($3), $4, $5, $6, status
        }' "$DB_FILE"
    else
        echo -e "${YELLOW}No routes configured.${NC}"
    fi
    press_enter
}

# ==============================================================================
# 4. TUNNEL STATUS
# ==============================================================================

tunnel_status() {
    print_header
    echo -e "${BOLD}--- Tunnel Status by Server ---${NC}\n"
    if [[ ! -s "$DB_FILE" ]]; then echo -e "${YELLOW}No routes configured.${NC}"; press_enter; return; fi
    
    awk -F'|' '$2==1 {print $5}' "$DB_FILE" | sort -u | while read -r server; do
        echo -e "${CYAN}Server: $server${NC}"
        awk -F'|' -v srv="$server" '$5==srv && $2==1 {printf "  %s/%s\n", $4, toupper($3)}' "$DB_FILE"
        echo ""
    done
    press_enter
}

# ==============================================================================
# 5. LIVE MONITORING
# ==============================================================================

live_monitoring() {
    while true; do
        clear
        echo -e "${BOLD}--- Live Traffic Monitor $(date '+%H:%M:%S') ---${NC}"
        printf "${BOLD}%-5s | %-8s | %-15s | %-15s | %-15s${NC}\n" "ID" "Proto" "Dest IP:Port" "Packets" "Bytes"
        echo "---------------------------------------------------------------"
        
        if [[ -s "$DB_FILE" ]]; then
            awk -F'|' '$2==1 {print $1, $3, $5, $6}' "$DB_FILE" | while read -r id proto rip rport; do
                pkts=0; bytes=0
                if [[ "$proto" == "tcp" ]] || [[ "$proto" == "both" ]]; then
                    stats=$(iptables -t nat -L "$CHAIN_NAME" -nvx | awk -v rp="$rip:$rport" -v p="tcp" '$0 ~ p && $0 ~ rp {print $1, $2; exit}')
                    read -r p b <<< "$stats"
                    pkts=$((pkts + ${p:-0})); bytes=$((bytes + ${b:-0}))
                fi
                if [[ "$proto" == "udp" ]] || [[ "$proto" == "both" ]]; then
                    stats=$(iptables -t nat -L "$CHAIN_NAME" -nvx | awk -v rp="$rip:$rport" -v p="udp" '$0 ~ p && $0 ~ rp {print $1, $2; exit}')
                    read -r p b <<< "$stats"
                    pkts=$((pkts + ${p:-0})); bytes=$((bytes + ${b:-0}))
                fi
                printf "%-5s | %-8s | %-15s | %-15s | %-15s\n" "$id" "${proto^^}" "$rip:$rport" "$pkts" "$bytes"
            done
        fi
        
        echo -e "\n${YELLOW}[ Press (q) or (Enter) to return to menu ]${NC}"
        
        read -t 2 -n 1 -s key || true
        if [[ "$key" == "q" ]] || [[ "$key" == $'\n' ]]; then
            break
        fi
    done
}

# ==============================================================================
# STATISTICS & HEALTH CHECK HELPERS
# ==============================================================================

view_statistics_single() {
    local id="$1"
    local data=$(grep "^${id}|" "$DB_FILE")
    IFS='|' read -r id enabled proto lport rip rport created modified <<< "$data"
    
    pkts=0; bytes=0
    if [[ "$proto" == "tcp" ]] || [[ "$proto" == "both" ]]; then
        stats=$(iptables -t nat -L "$CHAIN_NAME" -nvx | awk -v rp="$rip:$rport" -v p="tcp" '$0 ~ p && $0 ~ rp {print $1, $2; exit}')
        read -r p b <<< "$stats"; pkts=$((pkts + ${p:-0})); bytes=$((bytes + ${b:-0}))
    fi
    if [[ "$proto" == "udp" ]] || [[ "$proto" == "both" ]]; then
        stats=$(iptables -t nat -L "$CHAIN_NAME" -nvx | awk -v rp="$rip:$rport" -v p="udp" '$0 ~ p && $0 ~ rp {print $1, $2; exit}')
        read -r p b <<< "$stats"; pkts=$((pkts + ${p:-0})); bytes=$((bytes + ${b:-0}))
    fi

    echo -e "${BOLD}Statistics for ID $id:${NC}"
    echo "Packets        : $pkts"
    echo "Bytes          : $bytes"
    echo "Creation Date  : $(date -d @"$created" '+%Y-%m-%d %H:%M:%S')"
    echo "Modified Date  : $(date -d @"$modified" '+%Y-%m-%d %H:%M:%S')"
    echo "Status         : $([ "$enabled" -eq 1 ] && echo "Active" || echo "Disabled")"
}

health_check_single() {
    local id="$1"
    local data=$(grep "^${id}|" "$DB_FILE")
    IFS='|' read -r id enabled proto lport rip rport created modified <<< "$data"
    
    echo -e "${BOLD}Health Check for ID $id:${NC}"
    local all_good=1

    if iptables -t nat -C "$CHAIN_NAME" -p tcp --dport "$lport" -j DNAT --to-destination "$rip:$rport" 2>/dev/null || \
       iptables -t nat -C "$CHAIN_NAME" -p udp --dport "$lport" -j DNAT --to-destination "$rip:$rport" 2>/dev/null; then
        echo -e "[${GREEN}OK${NC}] DNAT Rule"
    else
        echo -e "[${RED}FAIL${NC}] DNAT Rule"; all_good=0
    fi

    if iptables -C "$CHAIN_NAME" -p tcp -d "$rip" --dport "$rport" -j ACCEPT 2>/dev/null || \
       iptables -C "$CHAIN_NAME" -p udp -d "$rip" --dport "$rport" -j ACCEPT 2>/dev/null; then
        echo -e "[${GREEN}OK${NC}] FORWARD Rule"
    else
        echo -e "[${RED}FAIL${NC}] FORWARD Rule"; all_good=0
    fi

    if ping -c 1 -W 1 "$rip" > /dev/null 2>&1; then
        echo -e "[${GREEN}OK${NC}] Destination Reachable"
    else
        echo -e "[${YELLOW}WARN${NC}] Destination Unreachable (Ping blocked or down)"
    fi

    if [[ "$enabled" -eq 1 ]]; then
        echo -e "[${GREEN}OK${NC}] Route Active"
    else
        echo -e "[${RED}FAIL${NC}] Route Disabled in DB"; all_good=0
    fi

    if [[ $all_good -eq 1 ]]; then
        log "INFO" "Health check PASSED for ID $id"
    else
        log "WARN" "Health check FAILED for ID $id"
    fi
}

# ==============================================================================
# 6. NETWORK OPTIMIZATION
# ==============================================================================

network_optimization() {
    while true; do
        print_header
        echo -e "${BOLD}--- Network Optimization ---${NC}"
        echo "1. Enable BBR"
        echo "2. Disable BBR"
        echo "3. Enable FQ Queue"
        echo "4. Disable FQ Queue"
        echo "5. Enable MSS Clamping"
        echo "6. Disable MSS Clamping"
        echo "7. View Network Status"
        echo "0. Back"
        echo -n "Select option: "
        read -r net_opt

        case $net_opt in
            1) 
                sysctl -w net.core.default_qdisc=fq > /dev/null
                sysctl -w net.ipv4.tcp_congestion_control=bbr > /dev/null
                sed -i '/net.core.default_qdisc/d' "$SYSCTL_CONF"
                sed -i '/net.ipv4.tcp_congestion_control/d' "$SYSCTL_CONF"
                echo "net.core.default_qdisc=fq" >> "$SYSCTL_CONF"
                echo "net.ipv4.tcp_congestion_control=bbr" >> "$SYSCTL_CONF"
                sysctl -p "$SYSCTL_CONF" > /dev/null
                log "INFO" "BBR Enabled"
                echo -e "${GREEN}BBR Enabled.${NC}"
                ;;
            2)
                sysctl -w net.core.default_qdisc=pfifo_fast > /dev/null
                sysctl -w net.ipv4.tcp_congestion_control=cubic > /dev/null
                sed -i '/net.core.default_qdisc/d' "$SYSCTL_CONF"
                sed -i '/net.ipv4.tcp_congestion_control/d' "$SYSCTL_CONF"
                echo "net.core.default_qdisc=pfifo_fast" >> "$SYSCTL_CONF"
                echo "net.ipv4.tcp_congestion_control=cubic" >> "$SYSCTL_CONF"
                sysctl -p "$SYSCTL_CONF" > /dev/null
                log "INFO" "BBR Disabled"
                echo -e "${YELLOW}BBR Disabled.${NC}"
                ;;
            3)
                sysctl -w net.core.default_qdisc=fq > /dev/null
                sed -i '/net.core.default_qdisc/d' "$SYSCTL_CONF"
                echo "net.core.default_qdisc=fq" >> "$SYSCTL_CONF"
                sysctl -p "$SYSCTL_CONF" > /dev/null
                echo -e "${GREEN}FQ Queue Enabled.${NC}"
                ;;
            4)
                sysctl -w net.core.default_qdisc=pfifo_fast > /dev/null
                sed -i '/net.core.default_qdisc/d' "$SYSCTL_CONF"
                echo "net.core.default_qdisc=pfifo_fast" >> "$SYSCTL_CONF"
                sysctl -p "$SYSCTL_CONF" > /dev/null
                echo -e "${YELLOW}FQ Queue Disabled.${NC}"
                ;;
            5)
                if ! iptables -t mangle -C POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null; then
                    iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
                    save_iptables
                    log "INFO" "MSS Clamping Enabled"
                    echo -e "${GREEN}MSS Clamping Enabled.${NC}"
                else
                    echo -e "${YELLOW}Already enabled.${NC}"
                fi
                ;;
            6)
                if iptables -t mangle -C POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null; then
                    iptables -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
                    save_iptables
                    log "INFO" "MSS Clamping Disabled"
                    echo -e "${YELLOW}MSS Clamping Disabled.${NC}"
                else
                    echo -e "${YELLOW}Already disabled.${NC}"
                fi
                ;;
            7)
                echo -e "\nCurrent TCP Congestion: $(sysctl -n net.ipv4.tcp_congestion_control)"
                echo "Current QDisc: $(sysctl -n net.core.default_qdisc)"
                echo "Current MTU: $MTU"
                press_enter
                ;;
            0) return ;;
        esac
        press_enter
    done
}

# ==============================================================================
# 7. BACKUP & RESTORE
# ==============================================================================

backup_restore() {
    while true; do
        print_header
        echo -e "${BOLD}--- Backup & Restore ---${NC}"
        echo "1. Create Backup"
        echo "2. Restore Backup"
        echo "3. List Backups"
        echo "4. Delete Backup"
        echo "0. Back"
        echo -n "Select option: "
        read -r br_opt

        case $br_opt in
            1)
                local ts=$(date '+%Y%m%d_%H%M%S')
                local bfile="rcl_backup_${ts}.tar.gz"
                tar -czf "$BACKUP_DIR/$bfile" -C /etc rcl-iptable/ 2>/dev/null
                log "INFO" "Backup created: $bfile"
                echo -e "${GREEN}Backup created: $bfile${NC}"
                ;;
            2)
                echo -e "Available Backups:"
                ls -1 "$BACKUP_DIR"/*.tar.gz 2>/dev/null || echo "None"
                echo -n "Enter backup filename to restore: "
                read -r rb_file
                if [[ -f "$BACKUP_DIR/$rb_file" ]]; then
                    read -p "Are you sure? This will overwrite current config. (y/n): " confirm
                    if [[ "$confirm" == "y" ]]; then
                        rebuild_all_rules
                        tar -xzf "$BACKUP_DIR/$rb_file" -C /etc/
                        rebuild_all_rules
                        log "INFO" "Restored from $rb_file"
                        echo -e "${GREEN}Restored successfully.${NC}"
                    fi
                else
                    echo -e "${RED}File not found.${NC}"
                fi
                ;;
            3)
                echo -e "\nAvailable Backups:"
                ls -lht "$BACKUP_DIR"/*.tar.gz 2>/dev/null || echo "None"
                ;;
            4)
                echo -e "Available Backups:"
                ls -1 "$BACKUP_DIR"/*.tar.gz 2>/dev/null || echo "None"
                echo -n "Enter backup filename to delete: "
                read -r db_file
                if [[ -f "$BACKUP_DIR/$db_file" ]]; then
                    rm "$BACKUP_DIR/$db_file"
                    echo -e "${GREEN}Deleted.${NC}"
                else
                    echo -e "${RED}File not found.${NC}"
                fi
                ;;
            0) return ;;
        esac
        press_enter
    done
}

# ==============================================================================
# 8. RESTART TUNNEL
# ==============================================================================

restart_tunnel() {
    print_header
    echo -e "${YELLOW}Rebuilding all tunnels from database...${NC}"
    rebuild_all_rules
    log "INFO" "Tunnels restarted/rebuilt."
    echo -e "${GREEN}Tunnels restarted safely.${NC}"
    press_enter
}

# ==============================================================================
# 9. REMOVE TUNNEL (UNINSTALL)
# ==============================================================================

delete_route_logic() {
    local target="$1"
    print_header
    echo -e "${BOLD}--- Delete Route ---${NC}"
    echo "1. Delete Specific Route (by ID)"
    echo "2. Delete By Port Number"
    echo "3. Delete All Routes For Selected Destination Server"
    echo "0. Cancel"
    echo -n "Select option: "
    read -r del_opt

    case $del_opt in
        1)
            echo -n "Enter Route ID: "; read -r did
            if awk -F'|' -v id="$did" '$1==id {found=1} END {exit !found}' "$DB_FILE"; then
                remove_iptables_rule "$did"
                sed -i "/^${did}|/d" "$DB_FILE"
                save_iptables
                log "INFO" "Deleted route ID $did"
                echo -e "${GREEN}Route deleted.${NC}"
            else
                echo -e "${RED}ID not found.${NC}"
            fi
            ;;
        2)
            echo -n "Enter Local Port: "; read -r dport
            if validate_port "$dport"; then
                awk -F'|' -v lp="$dport" '$4==lp {print $1}' "$DB_FILE" | while read -r did; do
                    remove_iptables_rule "$did"
                    sed -i "/^${did}|/d" "$DB_FILE"
                done
                save_iptables
                log "INFO" "Deleted all routes on port $dport"
                echo -e "${GREEN}Routes on port $dport deleted.${NC}"
            fi
            ;;
        3)
            echo -n "Enter Destination Server IP: "; read -r dip
            if validate_ip "$dip"; then
                awk -F'|' -v ip="$dip" '$5==ip {print $1}' "$DB_FILE" | while read -r did; do
                    remove_iptables_rule "$did"
                    sed -i "/^${did}|/d" "$DB_FILE"
                done
                save_iptables
                log "INFO" "Deleted all routes for $dip"
                echo -e "${GREEN}All routes for $dip deleted.${NC}"
            fi
            ;;
        0) return ;;
    esac
    press_enter
}

remove_tunnel_app() {
    print_header
    echo -e "${RED}${BOLD}!!! DANGER ZONE !!!${NC}"
    echo "This will REMOVE:"
    echo "- All Application Rules"
    echo "- Application Configuration ($BASE_DIR)"
    echo "- Application Databases"
    echo "- All Backups"
    echo "- Custom Chains"
    echo "- Log File"
    echo ""
    read -p "Type 'YES' to confirm complete removal: " confirm
    if [[ "$confirm" == "YES" ]]; then
        iptables -t nat -F "$CHAIN_NAME" 2>/dev/null
        iptables -F "$CHAIN_NAME" 2>/dev/null
        
        iptables -t nat -D PREROUTING -j "$CHAIN_NAME" 2>/dev/null
        iptables -D FORWARD -j "$CHAIN_NAME" 2>/dev/null
        
        iptables -t nat -X "$CHAIN_NAME" 2>/dev/null
        iptables -X "$CHAIN_NAME" 2>/dev/null

        iptables -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null

        save_iptables

        rm -rf "$BASE_DIR"
        rm -f "$LOG_FILE"
        
        if [[ -f "$SYSCTL_CONF" ]]; then
            grep -q "net.ipv4.ip_forward=1" "$SYSCTL_CONF" && sed -i '/net.ipv4.ip_forward=1/d' "$SYSCTL_CONF"
            grep -q "net.core.default_qdisc" "$SYSCTL_CONF" && sed -i '/net.core.default_qdisc/d' "$SYSCTL_CONF"
            grep -q "net.ipv4.tcp_congestion_control" "$SYSCTL_CONF" && sed -i '/net.ipv4.tcp_congestion_control/d' "$SYSCTL_CONF"
            [[ ! -s "$SYSCTL_CONF" ]] && rm -f "$SYSCTL_CONF"
            sysctl --system > /dev/null 2>&1
        fi

        echo -e "${GREEN}RCL-IPtable Pro has been completely removed.${NC}"
        exit 0
    else
        echo -e "${YELLOW}Cancelled.${NC}"
    fi
    press_enter
}

# ==============================================================================
# MAIN MENU
# ==============================================================================

main_menu() {
    while true; do
        print_header
        echo -e "${BOLD}--- Main Menu ---${NC}"
        echo "1.  Add Route"
        echo "2.  Edit Route"
        echo "3.  Route Table"
        echo "4.  Tunnel Status"
        echo "5.  Live Monitoring"
        echo "6.  Network Optimization"
        echo "7.  Backup & Restore"
        echo "8.  Restart Tunnel"
        echo "9.  Remove Tunnel"
        echo "0.  Exit"
        echo -e "${CYAN}------------------------------------------------------${NC}"
        echo -n "Select an option [0-9]: "
        read -r main_opt

        case $main_opt in
            1) add_route ;;
            2) edit_route_menu ;;
            3) route_table ;;
            4) tunnel_status ;;
            5) live_monitoring ;;
            6) network_optimization ;;
            7) backup_restore ;;
            8) restart_tunnel ;;
            9) remove_tunnel_app ;;
            0)
                clear
                echo -e "${CYAN}Exiting RCL-IPtable Pro. Goodbye!${NC}"
                echo -e "${GREEN}You can access the menu anytime by typing: ${BOLD}rcl-iptable${NC}"
                exit 0
                ;;
            *) 
                echo -e "${RED}Invalid option.${NC}"
                press_enter
                ;;
        esac
    done
}

# ==============================================================================
# SCRIPT ENTRY POINT
# ==============================================================================

detect_os
detect_network
init_chains

main_menu
