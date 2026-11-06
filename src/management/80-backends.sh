#═══════════════════════════════════════════════════════════════════════
# Switch Backend
#═══════════════════════════════════════════════════════════════════════

switch_backend() {
    local current_backend="${BACKEND:-paqet}"
    local new_backend
    if [ "$current_backend" = "paqet" ]; then
        new_backend="gfw-knocker"
    else
        new_backend="paqet"
    fi

    # Check if the other backend is installed
    local other_installed=false
    if [ "$new_backend" = "gfw-knocker" ]; then
        if [ "$ROLE" = "server" ]; then
            [ -d "$GFK_DIR" ] && [ -f "$GFK_DIR/quic_server.py" ] && other_installed=true
        else
            [ -d "$GFK_DIR" ] && [ -f "$GFK_DIR/quic_client.py" ] && other_installed=true
        fi
    else
        [ -f "$INSTALL_DIR/bin/paqet" ] && other_installed=true
    fi

    if [ "$other_installed" = false ]; then
        echo ""
        echo -e "${YELLOW}${new_backend} is not installed.${NC}"
        echo ""
        echo "  Use 'Install additional backend' option to install it first."
        echo ""
        read -n 1 -s -r -p "  Press any key..." < /dev/tty || true
        return 0
    fi

    echo ""
    echo -e "${BOLD}Switch active backend from ${current_backend} to ${new_backend}?${NC}"
    echo ""
    echo "  This will:"
    echo "  - Stop ${current_backend}"
    echo "  - Start ${new_backend}"
    echo ""
    read -p "  Proceed? [y/N]: " confirm < /dev/tty || true
    [[ "$confirm" =~ ^[Yy]$ ]] || { log_info "Cancelled"; return 0; }

    # Stop current
    stop_paqet
    _remove_firewall

    # Switch to new backend
    BACKEND="$new_backend"
    save_settings

    # Setup firewall and start new backend
    _apply_firewall
    start_paqet

    log_success "Switched to ${new_backend}"
    read -n 1 -s -r -p "  Press any key..." < /dev/tty || true
}

install_additional_backend() {
    local current_backend="${BACKEND:-paqet}"
    local new_backend
    if [ "$current_backend" = "paqet" ]; then
        new_backend="gfw-knocker"
    else
        new_backend="paqet"
    fi

    # Check if already installed
    local already_installed=false
    if [ "$new_backend" = "gfw-knocker" ]; then
        if [ "$ROLE" = "server" ]; then
            [ -d "$GFK_DIR" ] && [ -f "$GFK_DIR/quic_server.py" ] && already_installed=true
        else
            [ -d "$GFK_DIR" ] && [ -f "$GFK_DIR/quic_client.py" ] && already_installed=true
        fi
    else
        [ -f "$INSTALL_DIR/bin/paqet" ] && already_installed=true
    fi

    if [ "$already_installed" = true ]; then
        echo ""
        echo -e "${GREEN}${new_backend} is already installed.${NC}"
        echo ""
        echo "  Use 'Switch backend' to change the active backend."
        echo ""
        read -n 1 -s -r -p "  Press any key..." < /dev/tty || true
        return 0
    fi

    echo ""
    echo -e "${BOLD}Install ${new_backend} alongside ${current_backend}?${NC}"
    echo ""
    echo "  This will:"
    echo "  - Keep ${current_backend} running"
    echo "  - Install ${new_backend} as an additional option"
    echo "  - You can switch between them anytime"
    echo ""
    read -p "  Proceed? [y/N]: " confirm < /dev/tty || true
    [[ "$confirm" =~ ^[Yy]$ ]] || { log_info "Cancelled"; return 0; }

    echo ""
    log_info "Installing ${new_backend}..."

    if [ "$new_backend" = "gfw-knocker" ]; then
        # Collect GFK configuration for client role
        if [ "$ROLE" = "client" ]; then
            echo ""
            echo -e "${BOLD}GFK Client Configuration${NC}"
            echo -e "${DIM}(these must match your server settings)${NC}"
            echo ""

            echo -e "${BOLD}Server IP${NC} (server's public IP):"
            read -p "  IP: " input < /dev/tty || true
            if [ -z "$input" ] || ! _validate_ip "$input"; then
                log_error "Valid server IP is required."
                read -n 1 -s -r -p "  Press any key..." < /dev/tty || true
                return 1
            fi
            GFK_SERVER_IP="$input"

            echo -e "${BOLD}Server's VIO TCP port${NC} [45000] (must match server):"
            read -p "  Port: " input < /dev/tty || true
            GFK_VIO_PORT="${input:-45000}"
            if ! _validate_port "$GFK_VIO_PORT"; then
                log_warn "Invalid port. Using default 45000."
                GFK_VIO_PORT=45000
            fi

            echo -e "${BOLD}Local VIO client port${NC} [40000]:"
            read -p "  Port: " input < /dev/tty || true
            GFK_VIO_CLIENT_PORT="${input:-40000}"
            if ! _validate_port "$GFK_VIO_CLIENT_PORT"; then
                log_warn "Invalid port. Using default 40000."
                GFK_VIO_CLIENT_PORT=40000
            fi

            echo -e "${BOLD}Server's QUIC port${NC} [25000] (must match server):"
            read -p "  Port: " input < /dev/tty || true
            GFK_QUIC_PORT="${input:-25000}"
            if ! _validate_port "$GFK_QUIC_PORT"; then
                log_warn "Invalid port. Using default 25000."
                GFK_QUIC_PORT=25000
            fi

            echo -e "${BOLD}Local QUIC client port${NC} [20000]:"
            read -p "  Port: " input < /dev/tty || true
            GFK_QUIC_CLIENT_PORT="${input:-20000}"
            if ! _validate_port "$GFK_QUIC_CLIENT_PORT"; then
                log_warn "Invalid port. Using default 20000."
                GFK_QUIC_CLIENT_PORT=20000
            fi

            echo -e "${BOLD}QUIC auth code${NC} (from server setup):"
            read -p "  Auth code: " input < /dev/tty || true
            if [ -z "$input" ]; then
                log_error "Auth code is required."
                read -n 1 -s -r -p "  Press any key..." < /dev/tty || true
                return 1
            fi
            GFK_AUTH_CODE="$input"

            echo -e "${BOLD}TCP port mappings${NC} (must match server) [14000:443]:"
            read -p "  Mappings: " input < /dev/tty || true
            GFK_PORT_MAPPINGS="${input:-14000:443}"
            echo ""
        fi

        # Install GFK without changing current backend
        if ! _install_gfk_components; then
            log_error "Failed to install ${new_backend}"
            read -n 1 -s -r -p "  Press any key..." < /dev/tty || true
            return 1
        fi
    else
        # Install paqet without changing current backend
        if ! _install_paqet_components; then
            log_error "Failed to install ${new_backend}"
            read -n 1 -s -r -p "  Press any key..." < /dev/tty || true
            return 1
        fi
    fi

    echo ""
    log_success "${new_backend} installed successfully!"
    echo ""
    echo "  Use 'Switch backend' to activate it."
    echo ""
    read -n 1 -s -r -p "  Press any key..." < /dev/tty || true
}

_install_paqet_components() {
    log_info "Downloading paqet binary..."
    local _paqet_ver
    _paqet_ver=$(curl -s --max-time 10 "$PAQET_API_URL" 2>/dev/null | grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | grep -o '"[^"]*"$' | tr -d '"')
    if [ -z "$_paqet_ver" ] || ! _validate_version_tag "$_paqet_ver"; then
        _paqet_ver="$PAQET_VERSION_PINNED"
    fi
    log_info "Using paqet ${_paqet_ver}"
    if ! download_paqet "$_paqet_ver"; then
        log_error "Failed to download paqet"
        return 1
    fi
    log_success "paqet binary installed"

    # Generate config.yaml if it doesn't exist
    if [ ! -f "$INSTALL_DIR/config.yaml" ]; then
        echo ""
        echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
        echo -e "${BOLD}  PAQET CONFIGURATION${NC}"
        echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
        echo ""

        # Detect network settings
        detect_network
        local _det_iface="$DETECTED_IFACE"
        local _det_ip="$DETECTED_IP"
        local _det_mac="$DETECTED_GW_MAC"

        # Prompt for interface
        echo -e "${BOLD}Network Interface${NC} [${_det_iface:-eth0}]:"
        read -p "  Interface: " input < /dev/tty || true
        local _iface="${input:-${_det_iface:-eth0}}"

        # Prompt for local IP
        echo -e "${BOLD}Local IP${NC} [${_det_ip:-}]:"
        read -p "  IP: " input < /dev/tty || true
        local _local_ip="${input:-$_det_ip}"

        # Prompt for gateway MAC
        echo -e "${BOLD}Gateway MAC${NC} [${_det_mac:-}]:"
        read -p "  MAC: " input < /dev/tty || true
        local _gw_mac="${input:-$_det_mac}"

        # Validate MAC if provided
        if [ -n "$_gw_mac" ] && ! [[ "$_gw_mac" =~ ^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$ ]]; then
            log_warn "Invalid MAC format. Expected: aa:bb:cc:dd:ee:ff"
            read -p "  Enter valid MAC: " input < /dev/tty || true
            [ -n "$input" ] && _gw_mac="$input"
        fi

        # Generate encryption key
        local _key
        _key=$("$INSTALL_DIR/bin/paqet" secret 2>/dev/null || true)
        if [ -z "$_key" ]; then
            _key=$(openssl rand -base64 32 2>/dev/null | tr -d '=+/' | head -c 32 || true)
        fi

        if [ "$ROLE" = "server" ]; then
            # Prompt for port
            echo -e "${BOLD}Listen Port${NC} [8443]:"
            read -p "  Port: " input < /dev/tty || true
            local _port="${input:-8443}"

            # Show generated key
            echo ""
            echo -e "${GREEN}${BOLD}  Generated Encryption Key: ${_key}${NC}"
            echo -e "${YELLOW}  IMPORTANT: Save this key! Clients need it to connect.${NC}"
            echo ""
            echo -e "${BOLD}Encryption Key${NC} (press Enter to use generated key):"
            read -p "  Key: " input < /dev/tty || true
            [ -n "$input" ] && _key="$input"

            LISTEN_PORT="$_port"
            ENCRYPTION_KEY="$_key"
        else
            # Client prompts
            echo -e "${BOLD}Remote Server${NC} (IP:PORT):"
            read -p "  Server: " input < /dev/tty || true
            local _server="${input:-${REMOTE_SERVER:-}}"
            if [ -z "$_server" ]; then
                log_warn "No server specified. You must edit config.yaml later."
                _server="SERVER_IP:8443"
            fi

            echo -e "${BOLD}Encryption Key${NC} (from server):"
            read -p "  Key: " input < /dev/tty || true
            [ -n "$input" ] && _key="$input"

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
                echo -e "${BOLD}SOCKS5 Port${NC} [1080]:"
                read -p "  Port: " input < /dev/tty || true
                SOCKS_PORT="${input:-1080}"
            fi

            REMOTE_SERVER="$_server"
            ENCRYPTION_KEY="$_key"
        fi

        select_performance_profile

        # Validate required fields
        if [ -z "$_iface" ] || [ -z "$_local_ip" ] || [ -z "$_gw_mac" ]; then
            log_error "Missing required fields (interface, IP, or MAC)"
            return 1
        fi
        if [ -z "$_key" ] || [ "${#_key}" -lt 16 ]; then
            log_error "Invalid encryption key"
            return 1
        fi

        local tmp_conf
        tmp_conf=$(mktemp "$INSTALL_DIR/config.yaml.XXXXXXXX") || { log_error "Failed to create temp file"; return 1; }
        chmod 600 "$tmp_conf" 2>/dev/null

        INTERFACE="$_iface" LOCAL_IP="$_local_ip" GATEWAY_MAC="$_gw_mac" ENCRYPTION_KEY="$_key" generate_paqet_yaml "$tmp_conf"

        if ! mv "$tmp_conf" "$INSTALL_DIR/config.yaml"; then
            log_error "Failed to save config.yaml"
            rm -f "$tmp_conf"
            return 1
        fi
        chmod 600 "$INSTALL_DIR/config.yaml" 2>/dev/null

        # Update global vars for settings
        INTERFACE="$_iface"
        LOCAL_IP="$_local_ip"
        GATEWAY_MAC="$_gw_mac"

        log_success "Configuration saved to $INSTALL_DIR/config.yaml"

        # Save to settings.conf for persistence
        save_settings 2>/dev/null || true
    fi
}










_install_gfk_components() {
    log_info "Installing GFK components..."

    # Auto-detect server IP if not set (critical for server-side sniffer filter)
    if [ -z "${GFK_SERVER_IP:-}" ] && [ "$ROLE" = "server" ]; then
        GFK_SERVER_IP="${LOCAL_IP:-}"
        [ -z "$GFK_SERVER_IP" ] && GFK_SERVER_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')
        [ -z "$GFK_SERVER_IP" ] && GFK_SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
        if [ -n "$GFK_SERVER_IP" ]; then
            log_info "Auto-detected server IP: ${GFK_SERVER_IP}"
        else
            log_error "Could not detect server IP. Set GFK_SERVER_IP manually."
            return 1
        fi
    fi

    # Auto-generate auth code if not set
    if [ -z "${GFK_AUTH_CODE:-}" ] || [ "$GFK_AUTH_CODE" = "not set" ]; then
        GFK_AUTH_CODE=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 16 2>/dev/null || openssl rand -hex 8)
        log_info "Generated GFK auth code: ${GFK_AUTH_CODE}"
    fi

    # Save settings with server IP and auth code
    save_settings

    # Install Python dependencies (venv + scapy + aioquic)
    install_python_deps || return 1

    # Download GFK scripts (server and client)
    download_gfk || return 1

    # Generate TLS certificates for QUIC
    generate_gfk_certs || return 1

    # Setup Xray (server only — adds SOCKS5 alongside panel if detected)
    if [ "$ROLE" = "server" ]; then
        setup_xray_for_gfk || return 1
    elif [ "$ROLE" = "client" ]; then
        create_gfk_client_wrapper
    fi

    # Generate parameters.py config
    generate_gfk_config || return 1

    save_settings

    log_success "GFK components installed"
}
