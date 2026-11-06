#═══════════════════════════════════════════════════════════════════════
# Network Auto-Detection
#═══════════════════════════════════════════════════════════════════════

#═══════════════════════════════════════════════════════════════════════
# Configuration Wizard
#═══════════════════════════════════════════════════════════════════════

run_config_wizard() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  PAQCTL CONFIGURATION WIZARD${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""

    # Backend selection
    echo -e "${BOLD}Select backend:${NC}"
    echo "  1. paqet       (Go/KCP, built-in SOCKS5, single binary)"
    echo "  2. gfw-knocker (Python/QUIC, port forwarding + SOCKS5)"
    echo ""
    local backend_choice
    read -p "  Enter choice [1/2]: " backend_choice < /dev/tty || true
    case "$backend_choice" in
        2) BACKEND="gfw-knocker" ;;
        *) BACKEND="paqet" ;;
    esac
    echo ""
    log_info "Selected backend: $BACKEND"
    echo ""

    # Role selection
    echo -e "${BOLD}Select role:${NC}"
    echo "  1. Server  (accept connections from clients)"
    echo "  2. Client  (connect to a server, provides SOCKS5 proxy)"
    echo ""
    local role_choice
    read -p "  Enter choice [1/2]: " role_choice < /dev/tty || true
    case "$role_choice" in
        1) ROLE="server" ;;
        2) ROLE="client" ;;
        *)
            log_warn "Invalid choice. Defaulting to server."
            ROLE="server"
            ;;
    esac
    echo ""
    log_info "Selected role: $ROLE"

    if [ "$BACKEND" = "paqet" ]; then
        _wizard_paqet
    else
        _wizard_gfk
    fi

    echo ""
    read -p "  Enable OS Kernel Turbo Mode (BBR + 32MB Buffers)? [Y/n]: " t_choice < /dev/tty || true
    if [[ ! "${t_choice:-Y}" =~ ^[nN]$ ]]; then
        TURBO_ENABLED="true"
    else
        TURBO_ENABLED="false"
    fi
    read -p "  Enable Self-Healing Watchdog (Auto-Recovery Service)? [Y/n]: " w_choice < /dev/tty || true
    if [[ ! "${w_choice:-Y}" =~ ^[nN]$ ]]; then
        WATCHDOG_ENABLED="true"
    else
        WATCHDOG_ENABLED="false"
    fi

    # Save settings
    save_settings
}

_wizard_paqet() {
    # Auto-detect network
    detect_network
    echo ""

    # Confirm/override interface
    echo -e "${BOLD}Network interface${NC} [${DETECTED_IFACE:-eth0}]:"
    read -p "  Interface: " input < /dev/tty || true
    IFACE="${input:-$DETECTED_IFACE}"
    IFACE="${IFACE:-eth0}"
    if ! _validate_iface "$IFACE"; then
        log_warn "Invalid interface name. Using eth0."
        IFACE="eth0"
    fi

    # Confirm/override local IP
    echo -e "${BOLD}Local IP${NC} [${DETECTED_IP:-auto}]:"
    read -p "  IP: " input < /dev/tty || true
    LOCAL_IP="${input:-$DETECTED_IP}"
    if [ -n "$LOCAL_IP" ] && ! _validate_ip "$LOCAL_IP"; then
        log_warn "Invalid IP format. Using detected IP."
        LOCAL_IP="$DETECTED_IP"
    fi

    # Confirm/override gateway MAC
    echo -e "${BOLD}Gateway MAC address${NC} [${DETECTED_GW_MAC:-auto}]:"
    read -p "  MAC: " input < /dev/tty || true
    GW_MAC="${input:-$DETECTED_GW_MAC}"

    if [ -z "$GW_MAC" ] || ! _validate_mac "$GW_MAC"; then
        if [ -n "$GW_MAC" ]; then
            log_warn "Invalid MAC format detected."
        else
            log_error "Could not detect gateway MAC address."
        fi
        log_error "Please enter it manually (format: aa:bb:cc:dd:ee:ff)"
        read -p "  Gateway MAC: " GW_MAC < /dev/tty || true
        if [ -z "$GW_MAC" ] || ! _validate_mac "$GW_MAC"; then
            log_error "Valid gateway MAC is required for paqet to function."
            exit 1
        fi
    fi
    # Canonical names used by save_settings / config generation (a reinstall
    # has the previous values loaded, which must not win over the wizard)
    INTERFACE="$IFACE"
    GATEWAY_MAC="$GW_MAC"

    if [ "$ROLE" = "server" ]; then
        echo ""
        echo -e "${BOLD}Listen port${NC} [8443]:"
        read -p "  Port: " input < /dev/tty || true
        LISTEN_PORT="${input:-8443}"
        if ! [[ "$LISTEN_PORT" =~ ^[0-9]+$ ]] || [ "$LISTEN_PORT" -lt 1 ] || [ "$LISTEN_PORT" -gt 65535 ]; then
            log_warn "Invalid port. Using default 8443."
            LISTEN_PORT=8443
        fi

        echo ""
        log_info "Generating encryption key..."
        ENCRYPTION_KEY=$("$INSTALL_DIR/bin/paqet" secret 2>/dev/null || true)
        if [ -z "$ENCRYPTION_KEY" ]; then
            log_warn "Could not auto-generate key. Using openssl fallback..."
            ENCRYPTION_KEY=$(openssl rand -base64 32 2>/dev/null | tr -d '=+/' | head -c 32 || true)
        fi
        if [ -z "$ENCRYPTION_KEY" ] || [ "${#ENCRYPTION_KEY}" -lt 16 ]; then
            log_error "Failed to generate a valid encryption key"
            return 1
        fi
        echo ""
        echo -e "${GREEN}${BOLD}  Encryption Key: ${ENCRYPTION_KEY}${NC}"
        echo ""
        echo -e "${YELLOW}  IMPORTANT: Save this key! Clients need it to connect.${NC}"
        echo ""
        SOCKS_PORT=""
    else
        echo ""
        echo -e "${BOLD}Remote server address${NC} (IP:PORT):"
        read -p "  Server: " REMOTE_SERVER < /dev/tty || true
        if [ -z "$REMOTE_SERVER" ]; then
            log_error "Remote server address is required."
            exit 1
        fi

        echo ""
        echo -e "${BOLD}Encryption key${NC} (from server setup):"
        read -p "  Key: " ENCRYPTION_KEY < /dev/tty || true
        if [ -z "$ENCRYPTION_KEY" ]; then
            log_error "Encryption key is required."
            exit 1
        fi

        echo ""
        echo "===================================================================="
        echo "  ROUTING MODE SELECTION"
        echo "===================================================================="
        echo "  Note: Choose how traffic is handled across your proxy tunnel."
        echo ""
        echo "  1) SOCKS5 Proxy Mode [DEFAULT - Recommended for most users]"
        echo "     • Creates a standard all-in-one SOCKS5 proxy on port 1080."
        echo "     • Best for direct browser browsing, Telegram, and general apps."
        echo ""
        echo "  2) Direct Port Forwarding Mode [For advanced server-to-server setups]"
        echo "     • Forwards raw TCP/UDP traffic directly without SOCKS5 overhead."
        echo "     • Best for connecting backend Xray/sing-box panels or CDN tunnels."
        echo "===================================================================="
        echo ""
        read -p "  Select Routing Mode [1-2, default: 1]: " r_choice < /dev/tty || true
        r_choice="${r_choice:-1}"
        if [ "$r_choice" = "2" ]; then
            ROUTING_MODE="forward"
            echo -e "${BOLD}Local Forward Listen Port${NC} [14000]:"
            read -p "  Port: " input < /dev/tty || true; FORWARD_PORT="${input:-14000}"
            echo -e "${BOLD}Target Address (IP:PORT)${NC} [127.0.0.1:80]:"
            read -p "  Target: " input < /dev/tty || true; FORWARD_TARGET="${input:-127.0.0.1:80}"; _egress_forward_hint "$FORWARD_TARGET"
            SOCKS_PORT=1080
        else
            ROUTING_MODE="socks5"
            echo -e "${BOLD}SOCKS5 listen port${NC} [1080]:"
            read -p "  SOCKS port: " input < /dev/tty || true
            SOCKS_PORT="${input:-1080}"
            if ! [[ "$SOCKS_PORT" =~ ^[0-9]+$ ]] || [ "$SOCKS_PORT" -lt 1 ] || [ "$SOCKS_PORT" -gt 65535 ]; then
                log_warn "Invalid port. Using default 1080."
                SOCKS_PORT=1080
            fi
        fi
        LISTEN_PORT=""
    fi

    echo ""
    echo "===================================================================="
    echo "  PERFORMANCE PROFILE SELECTION"
    echo "===================================================================="
    echo "  Note: Select a profile that matches your network link quality."
    echo ""
    echo "  1) Standard / Balanced [DEFAULT - conn: 2, mtu: 1350]"
    echo "     • Smart default for general internet uplinks and everyday usage."
    echo ""
    echo "  2) High-Loss / Restricted Uplink [conn: 4, wnd: 1024, mtu: 1300]"
    echo "     • Optimized for restricted networks, severe packet loss, or heavy DPI."
    echo ""
    echo "  3) High-Throughput / CDN Tunnel [conn: 8, wnd: 2048, sockbuf: 8MB]"
    echo "     • Maximized concurrency for multi-layer CDN routing or Gigabit fiber."
    echo ""
    echo "  4) Low-Latency / Gaming & VOIP [conn: 2, mtu: 1200, nodelay: 1]"
    echo "     • Ultra-fast response times for real-time applications."
    echo "===================================================================="
    echo ""
    read -p "  Select Profile [1-4, default: 1]: " p_choice < /dev/tty || true
    p_choice="${p_choice:-1}"
    case "$p_choice" in
        2)
            KCP_PROFILE="highloss"; KCP_CONN=4; KCP_MTU=1300; KCP_SNDWND=1024; KCP_RCVWND=1024
            KCP_NODELAY=0; KCP_INTERVAL=20; KCP_RESEND=2; KCP_NOCONGESTION=0; KCP_SOCKBUF=4194304; KCP_SMUXBUF=4194304 ;;
        3)
            KCP_PROFILE="cdntunnel"; KCP_CONN=8; KCP_MTU=1400; KCP_SNDWND=2048; KCP_RCVWND=2048
            KCP_NODELAY=0; KCP_INTERVAL=20; KCP_RESEND=2; KCP_NOCONGESTION=0; KCP_SOCKBUF=8388608; KCP_SMUXBUF=8388608 ;;
        4)
            KCP_PROFILE="gaming"; KCP_CONN=2; KCP_MTU=1200; KCP_SNDWND=512; KCP_RCVWND=512
            KCP_NODELAY=1; KCP_INTERVAL=10; KCP_RESEND=2; KCP_NOCONGESTION=1; KCP_SOCKBUF=4194304; KCP_SMUXBUF=4194304 ;;
        *)
            KCP_PROFILE="standard"; KCP_CONN=2; KCP_MTU=1350; KCP_SNDWND=1024; KCP_RCVWND=1024
            KCP_NODELAY=0; KCP_INTERVAL=20; KCP_RESEND=2; KCP_NOCONGESTION=0; KCP_SOCKBUF=4194304; KCP_SMUXBUF=4194304 ;;
    esac

    # Generate YAML config
    generate_config
}

_wizard_gfk() {
    if [ "$ROLE" = "server" ]; then
        # Server IP (this machine's public IP)
        detect_network
        echo ""
        echo -e "${BOLD}This server's public IP${NC} [${DETECTED_IP:-}]:"
        read -p "  IP: " input < /dev/tty || true
        GFK_SERVER_IP="${input:-$DETECTED_IP}"
        if [ -z "$GFK_SERVER_IP" ] || ! _validate_ip "$GFK_SERVER_IP"; then
            log_error "Valid server IP is required."
            exit 1
        fi

        # VIO TCP port (must be closed to OS, raw socket handles it)
        echo ""
        echo -e "${BOLD}VIO TCP port${NC} [45000] (raw socket port, must be blocked by firewall):"
        read -p "  Port: " input < /dev/tty || true
        GFK_VIO_PORT="${input:-45000}"
        if ! _validate_port "$GFK_VIO_PORT"; then
            log_warn "Invalid port. Using default 45000."
            GFK_VIO_PORT=45000
        fi

        # QUIC port
        echo ""
        echo -e "${BOLD}QUIC tunnel port${NC} [25000]:"
        read -p "  Port: " input < /dev/tty || true
        GFK_QUIC_PORT="${input:-25000}"
        if ! _validate_port "$GFK_QUIC_PORT"; then
            log_warn "Invalid port. Using default 25000."
            GFK_QUIC_PORT=25000
        fi

        # Auth code
        echo ""
        local auto_auth
        auto_auth=$(openssl rand -base64 16 2>/dev/null | tr -d '=+/' | head -c 16)
        echo -e "${BOLD}QUIC auth code${NC} [auto-generated]:"
        read -p "  Auth code: " input < /dev/tty || true
        GFK_AUTH_CODE="${input:-$auto_auth}"
        echo ""
        echo -e "${GREEN}${BOLD}  Auth Code: ${GFK_AUTH_CODE}${NC}"
        echo ""
        echo -e "${YELLOW}  IMPORTANT: Save this auth code! Clients need it to connect.${NC}"
        echo ""

        # Port mappings
        echo -e "${BOLD}TCP port mappings${NC} (local:remote, comma-separated) [14000:443]:"
        echo -e "  ${DIM}Example: 14000:443,15000:2096,16000:10809${NC}"
        read -p "  Mappings: " input < /dev/tty || true
        GFK_PORT_MAPPINGS="${input:-14000:443}"
        MICROSOCKS_PORT=""

    else
        # Client: server IP
        echo ""
        echo -e "${BOLD}Remote server IP${NC} (server's public IP):"
        read -p "  Server IP: " GFK_SERVER_IP < /dev/tty || true
        if [ -z "$GFK_SERVER_IP" ] || ! _validate_ip "$GFK_SERVER_IP"; then
            log_error "Valid server IP is required."
            exit 1
        fi

        # Server's VIO TCP port (what port the server is listening on)
        echo ""
        echo -e "${BOLD}Server's VIO TCP port${NC} [45000] (must match server config):"
        read -p "  Port: " input < /dev/tty || true
        GFK_VIO_PORT="${input:-45000}"
        if ! _validate_port "$GFK_VIO_PORT"; then
            log_warn "Invalid port. Using default 45000."
            GFK_VIO_PORT=45000
        fi

        # Local VIO client port (client's local binding)
        echo ""
        echo -e "${BOLD}Local VIO client port${NC} [40000]:"
        read -p "  Port: " input < /dev/tty || true
        GFK_VIO_CLIENT_PORT="${input:-40000}"
        if ! _validate_port "$GFK_VIO_CLIENT_PORT"; then
            log_warn "Invalid port. Using default 40000."
            GFK_VIO_CLIENT_PORT=40000
        fi

        # Server's QUIC port
        echo ""
        echo -e "${BOLD}Server's QUIC port${NC} [25000] (must match server config):"
        read -p "  Port: " input < /dev/tty || true
        GFK_QUIC_PORT="${input:-25000}"
        if ! _validate_port "$GFK_QUIC_PORT"; then
            log_warn "Invalid port. Using default 25000."
            GFK_QUIC_PORT=25000
        fi

        # Local QUIC client port
        echo ""
        echo -e "${BOLD}Local QUIC client port${NC} [20000]:"
        read -p "  Port: " input < /dev/tty || true
        GFK_QUIC_CLIENT_PORT="${input:-20000}"
        if ! _validate_port "$GFK_QUIC_CLIENT_PORT"; then
            log_warn "Invalid port. Using default 20000."
            GFK_QUIC_CLIENT_PORT=20000
        fi

        # Auth code (from server)
        echo ""
        echo -e "${BOLD}QUIC auth code${NC} (from server setup):"
        read -p "  Auth code: " GFK_AUTH_CODE < /dev/tty || true
        if [ -z "$GFK_AUTH_CODE" ]; then
            log_error "Auth code is required."
            exit 1
        fi

        # Port mappings (must match server)
        echo ""
        echo -e "${BOLD}TCP port mappings${NC} (must match server) [14000:443]:"
        read -p "  Mappings: " input < /dev/tty || true
        GFK_PORT_MAPPINGS="${input:-14000:443}"
    fi

    # Generate GFK config
    generate_gfk_config
}

generate_config() {
    log_info "Generating paqet configuration..."

    # Validate required fields
    if [ -z "$IFACE" ] || [ -z "$LOCAL_IP" ] || [ -z "$GW_MAC" ] || [ -z "$ENCRYPTION_KEY" ]; then
        log_error "Missing required configuration fields (interface, ip, gateway_mac, or secret)"
        return 1
    fi
    if [ "$ROLE" = "server" ]; then
        if [ -z "$LISTEN_PORT" ]; then log_error "Missing listen port"; return 1; fi
    else
        if [ -z "$REMOTE_SERVER" ] || [ -z "$SOCKS_PORT" ]; then
            log_error "Missing server address or SOCKS port"
            return 1
        fi
        local _rs_ip="${REMOTE_SERVER%:*}" _rs_port="${REMOTE_SERVER##*:}"
        if ! _validate_ip "$_rs_ip" || ! _validate_port "$_rs_port"; then
            log_error "Server address must be valid IP:PORT (e.g. 1.2.3.4:8443)"
            return 1
        fi
    fi

    # Ensure install directory exists
    mkdir -p "$INSTALL_DIR" || { log_error "Failed to create $INSTALL_DIR"; return 1; }

    local tmp_conf
    tmp_conf=$(mktemp "$INSTALL_DIR/config.yaml.XXXXXXXX") || { log_error "Failed to create temp file"; return 1; }
    # Set permissions on temp file before writing (fixes race condition)
    chmod 600 "$tmp_conf" 2>/dev/null

    (
    umask 077
    generate_paqet_yaml "$tmp_conf"
    )
    if ! mv "$tmp_conf" "$INSTALL_DIR/config.yaml"; then
        log_error "Failed to save configuration file"
        rm -f "$tmp_conf"
        return 1
    fi
    # Ensure final permissions (mv preserves source permissions on most systems)
    chmod 600 "$INSTALL_DIR/config.yaml" 2>/dev/null
    log_success "Configuration saved to $INSTALL_DIR/config.yaml"
}
