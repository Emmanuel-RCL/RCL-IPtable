#!/bin/bash

CONFIG_DIR="/etc/rcl-iptable"
CONFIG_FILE="$CONFIG_DIR/config.conf"
CHAIN="RCL_IPTABLE"

TG_CHANNEL="@techno_rey"
TUNNEL_NAME="RCL-IPtable"

mkdir -p "$CONFIG_DIR"

# -------------------------
# Load config
# -------------------------
load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE"
    fi
}

save_config() {
    cat > "$CONFIG_FILE" <<EOF
ROLE=$ROLE
IP_VERSION=$IP_VERSION
PROTOCOL=$PROTOCOL
FOREIGN_IP=$FOREIGN_IP
PORT_MAP_MODE=$PORT_MAP_MODE
PORTS="$PORTS"
EOF
}

# -------------------------
# Header
# -------------------------
show_header() {
    clear
    echo "=================================================="
    echo "              $TUNNEL_NAME"
    echo "              $TG_CHANNEL"
    echo "=================================================="
    echo "Server IP : $(hostname -I | awk '{print $1}')"
    echo "OS        : $(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '\"')"
    echo "Role      : ${ROLE:-Not Configured}"
    echo "IP Version: ${IP_VERSION:-N/A}"
    echo "Protocol  : ${PROTOCOL:-N/A}"
    echo "Foreign IP: ${FOREIGN_IP:-N/A}"
    echo "=================================================="
    echo ""
}

# -------------------------
# Install packages
# -------------------------
install_deps() {
    apt update -y
    apt install iptables iptables-persistent netfilter-persistent -y
}

# -------------------------
# Enable forwarding
# -------------------------
enable_forward() {
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
}

# -------------------------
# Flush rules
# -------------------------
flush_rules() {
    iptables -t nat -D PREROUTING -j $CHAIN 2>/dev/null
    iptables -t nat -F $CHAIN 2>/dev/null
    iptables -t nat -X $CHAIN 2>/dev/null

    iptables -F FORWARD 2>/dev/null
}

# -------------------------
# Apply rules
# -------------------------
apply_rules() {
    flush_rules

    iptables -t nat -N $CHAIN
    iptables -t nat -A PREROUTING -j $CHAIN

    IFS=',' read -ra P <<< "$PORTS"

    for p in "${P[@]}"; do
        if [ "$PORT_MAP_MODE" == "same" ]; then
            dst=$p
        else
            dst=$(echo "$p" | cut -d':' -f2)
            p=$(echo "$p" | cut -d':' -f1)
        fi

        iptables -t nat -A $CHAIN -p $PROTOCOL --dport $p \
            -j DNAT --to-destination $FOREIGN_IP:$dst

        iptables -A FORWARD -p $PROTOCOL -d $FOREIGN_IP --dport $dst -j ACCEPT
    done

    iptables -t nat -A POSTROUTING -j MASQUERADE

    netfilter-persistent save
}

# -------------------------
# Install tunnel
# -------------------------
install_tunnel() {
    show_header
    echo "Install Tunnel (Iran Server)"
    echo "1) IPv4"
    echo "2) IPv6"
    read -p "Select IP version: " ipver

    if [ "$ipver" == "2" ]; then
        IP_VERSION="ipv6"
    else
        IP_VERSION="ipv4"
    fi

    echo "1) TCP"
    echo "2) UDP"
    read -p "Select protocol: " proto

    if [ "$proto" == "2" ]; then
        PROTOCOL="udp"
    else
        PROTOCOL="tcp"
    fi

    read -p "Foreign Server IP: " FOREIGN_IP

    echo "Port Mode:"
    echo "1) Same Port"
    echo "2) Port Mapping"
    read -p "Choose: " pm

    if [ "$pm" == "2" ]; then
        PORT_MAP_MODE="map"
        echo "Enter ports in format local:remote (comma separated)"
        read -p "Ports: " PORTS
    else
        PORT_MAP_MODE="same"
        read -p "Enter ports (comma separated): " PORTS
    fi

    ROLE="iran"

    install_deps
    enable_forward
    apply_rules
    save_config

    echo "Installed successfully"
    read
}

# -------------------------
# Edit tunnel
# -------------------------
edit_tunnel() {
    while true; do
        show_header
        echo "1) Change Foreign IP"
        echo "2) Add Port"
        echo "3) Remove All & Reinstall"
        echo "0) Back"
        read -p "Choose: " c

        case $c in
            1)
                read -p "New Foreign IP: " FOREIGN_IP
                save_config
                apply_rules
                ;;
            2)
                read -p "Add port (format same/map): " np
                PORTS="$PORTS,$np"
                save_config
                apply_rules
                ;;
            3)
                apply_rules
                ;;
            0)
                return
                ;;
        esac
    done
}

# -------------------------
# Restart
# -------------------------
restart_tunnel() {
    apply_rules
    echo "Restarted"
    read
}

# -------------------------
# View config
# -------------------------
view_config() {
    show_header
    echo "Config File:"
    cat "$CONFIG_FILE" 2>/dev/null
    read
}

# -------------------------
# Remove tunnel
# -------------------------
remove_tunnel() {
    flush_rules
    rm -f "$CONFIG_FILE"
    echo "Removed"
    read
}

# -------------------------
# Main menu
# -------------------------
main_menu() {
    load_config

    while true; do
        show_header
        echo "1) Install Tunnel (Iran)"
        echo "2) Edit Tunnel"
        echo "3) Restart Tunnel"
        echo "4) View Config"
        echo "5) Remove Tunnel"
        echo "0) Exit"

        read -p "Select: " opt

        case $opt in
            1) install_tunnel ;;
            2) edit_tunnel ;;
            3) restart_tunnel ;;
            4) view_config ;;
            5) remove_tunnel ;;
            0) exit 0 ;;
        esac
    done
}

# -------------------------
# Install alias
# -------------------------
install_alias() {
    cp $0 /usr/local/bin/rcl-iptable
    chmod +x /usr/local/bin/rcl-iptable
}

install_alias
main_menu
