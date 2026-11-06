#═══════════════════════════════════════════════════════════════════════
# Configuration
#═══════════════════════════════════════════════════════════════════════

_change_config_gfk() {
    local was_running="$1"
    echo ""
    echo -e "${BOLD}Select role:${NC}"
    echo "  1. Server"
    echo "  2. Client"
    echo ""
    local role_choice
    read -p "  Enter choice [1/2]: " role_choice < /dev/tty || true
    case "$role_choice" in
        1) ROLE="server" ;;
        2) ROLE="client" ;;
        *) log_warn "Invalid. Keeping current role: $ROLE" ;;
    esac

    if [ "$ROLE" = "server" ]; then
        echo -e "${BOLD}Server public IP${NC} [${GFK_SERVER_IP}]:"
        read -p "  IP: " input < /dev/tty || true
        if [ -n "$input" ] && ! _validate_ip "$input"; then
            log_error "Invalid IP address"; return 1
        fi
        [ -n "$input" ] && GFK_SERVER_IP="$input"

        echo -e "${BOLD}VIO TCP port${NC} [${GFK_VIO_PORT:-45000}]:"
        read -p "  Port: " input < /dev/tty || true
        if [ -n "$input" ] && ! _validate_port "$input"; then
            log_error "Invalid port number"; return 1
        fi
        [ -n "$input" ] && GFK_VIO_PORT="$input"

        echo -e "${BOLD}QUIC port${NC} [${GFK_QUIC_PORT:-25000}]:"
        read -p "  Port: " input < /dev/tty || true
        if [ -n "$input" ] && ! _validate_port "$input"; then
            log_error "Invalid port number"; return 1
        fi
        [ -n "$input" ] && GFK_QUIC_PORT="$input"

        echo -e "${BOLD}Auth code${NC} [keep current]:"
        read -p "  Code: " input < /dev/tty || true
        [ -n "$input" ] && GFK_AUTH_CODE="$input"

        echo -e "${BOLD}Port mappings${NC} [${GFK_PORT_MAPPINGS:-14000:443}]:"
        read -p "  Mappings: " input < /dev/tty || true
        [ -n "$input" ] && GFK_PORT_MAPPINGS="$input"

        echo -e "${BOLD}Outgoing TCP flags${NC} [${GFK_TCP_FLAGS:-AP}]:"
        echo -e "  ${DIM}Controls TCP flags on outgoing violated packets (default: AP)${NC}"
        echo -e "  ${DIM}Valid flags: S(SYN) A(ACK) P(PSH) R(RST) F(FIN) U(URG)${NC}"
        read -p "  Flags: " input < /dev/tty || true
        if [ -n "$input" ] && ! [[ "$input" =~ ^[FSRPAUEC]+$ ]]; then
            log_error "Invalid flags. Use uppercase letters only: F, S, R, P, A, U, E, C"; return 1
        fi
        [ -n "$input" ] && GFK_TCP_FLAGS="$input"
    else
        echo -e "${BOLD}Server IP${NC} [${GFK_SERVER_IP}]:"
        read -p "  IP: " input < /dev/tty || true
        if [ -n "$input" ] && ! _validate_ip "$input"; then
            log_error "Invalid IP address"; return 1
        fi
        [ -n "$input" ] && GFK_SERVER_IP="$input"

        echo -e "${BOLD}Server's VIO TCP port${NC} [${GFK_VIO_PORT:-45000}] (must match server):"
        read -p "  Port: " input < /dev/tty || true
        if [ -n "$input" ] && ! _validate_port "$input"; then
            log_error "Invalid port number"; return 1
        fi
        [ -n "$input" ] && GFK_VIO_PORT="$input"

        echo -e "${BOLD}Local VIO client port${NC} [${GFK_VIO_CLIENT_PORT:-40000}]:"
        read -p "  Port: " input < /dev/tty || true
        if [ -n "$input" ] && ! _validate_port "$input"; then
            log_error "Invalid port number"; return 1
        fi
        [ -n "$input" ] && GFK_VIO_CLIENT_PORT="$input"

        echo -e "${BOLD}Server's QUIC port${NC} [${GFK_QUIC_PORT:-25000}] (must match server):"
        read -p "  Port: " input < /dev/tty || true
        if [ -n "$input" ] && ! _validate_port "$input"; then
            log_error "Invalid port number"; return 1
        fi
        [ -n "$input" ] && GFK_QUIC_PORT="$input"

        echo -e "${BOLD}Local QUIC client port${NC} [${GFK_QUIC_CLIENT_PORT:-20000}]:"
        read -p "  Port: " input < /dev/tty || true
        if [ -n "$input" ] && ! _validate_port "$input"; then
            log_error "Invalid port number"; return 1
        fi
        [ -n "$input" ] && GFK_QUIC_CLIENT_PORT="$input"

        echo -e "${BOLD}Auth code${NC}:"
        read -p "  Code: " input < /dev/tty || true
        [ -n "$input" ] && GFK_AUTH_CODE="$input"

        echo -e "${BOLD}Port mappings${NC} [${GFK_PORT_MAPPINGS:-14000:443}]:"
        read -p "  Mappings: " input < /dev/tty || true
        [ -n "$input" ] && GFK_PORT_MAPPINGS="$input"

        echo -e "${BOLD}Outgoing TCP flags${NC} [${GFK_TCP_FLAGS:-AP}]:"
        echo -e "  ${DIM}Controls TCP flags on outgoing violated packets (default: AP)${NC}"
        echo -e "  ${DIM}Valid flags: S(SYN) A(ACK) P(PSH) R(RST) F(FIN) U(URG)${NC}"
        read -p "  Flags: " input < /dev/tty || true
        if [ -n "$input" ] && ! [[ "$input" =~ ^[FSRPAUEC]+$ ]]; then
            log_error "Invalid flags. Use uppercase letters only: F, S, R, P, A, U, E, C"; return 1
        fi
        [ -n "$input" ] && GFK_TCP_FLAGS="$input"
    fi

    # Regenerate parameters.py
    generate_gfk_config || { [ "$was_running" = true ] && start_paqet; return 1; }

    # Regenerate wrapper if client
    if [ "$ROLE" = "client" ]; then
        create_gfk_client_wrapper
    fi

    # Save settings
    local IFACE="" GW_MAC=""
    save_settings

    # Re-apply firewall
    _apply_firewall

    # Restart
    [ "$was_running" = true ] && start_paqet
    log_success "GFW-knocker configuration updated"
}

change_config() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  CHANGE CONFIGURATION${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    local _warn_text="config"
    [ "$BACKEND" = "gfw-knocker" ] && _warn_text="parameters.py"
    echo -e "  ${YELLOW}Warning: This will regenerate ${_warn_text} and restart ${BACKEND}.${NC}"
    echo -e "  ${DIM}Non-interactive alternative: sudo paqctl config set KEY=VALUE (see: paqctl help config)${NC}"
    echo ""
    if ! _has_tty; then
        log_error "Interactive configuration needs a terminal. Use: paqctl config set KEY=VALUE"
        return 1
    fi
    _confirm "Continue?" || return 0

    local was_running=false
    is_running && was_running=true
    [ "$was_running" = true ] && stop_paqet

    if [ "$BACKEND" = "gfw-knocker" ]; then
        _remove_firewall
        _change_config_gfk "$was_running"
        return
    fi

    # Remove old firewall rules (save old port before user changes it)
    local _saved_port="$LISTEN_PORT"
    if [ "$ROLE" = "server" ] && [ -n "$_saved_port" ]; then
        _remove_firewall
    fi

    # Re-run wizard (inline version)
    echo ""
    echo -e "${BOLD}Select role:${NC}"
    echo "  1. Server"
    echo "  2. Client"
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

    # Detect network
    local _iface=$(ip route show default 2>/dev/null | awk '{print $5; exit}')
    # Note: grep returns exit 1 if no matches, so we add || true for pipefail
    local _ip=$(ip -4 addr show "$_iface" 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | { grep -o '[0-9.]*' || true; } | head -1)
    local _gw=$(ip route show default 2>/dev/null | awk '{print $3; exit}')
    local _gw_mac=""
    [ -n "$_gw" ] && _gw_mac=$(ip neigh show "$_gw" 2>/dev/null | awk '/lladdr/{print $5; exit}')

    echo ""
    echo -e "${BOLD}Interface${NC} [${_iface:-$INTERFACE}]:"
    read -p "  Interface: " input < /dev/tty || true
    INTERFACE="${input:-${_iface:-$INTERFACE}}"

    echo -e "${BOLD}Local IP${NC} [${_ip:-$LOCAL_IP}]:"
    read -p "  IP: " input < /dev/tty || true
    LOCAL_IP="${input:-${_ip:-$LOCAL_IP}}"

    echo -e "${BOLD}Gateway MAC${NC} [${_gw_mac:-$GATEWAY_MAC}]:"
    read -p "  MAC: " input < /dev/tty || true
    GATEWAY_MAC="${input:-${_gw_mac:-$GATEWAY_MAC}}"
    if [ -n "$GATEWAY_MAC" ] && ! _validate_mac "$GATEWAY_MAC"; then
        log_warn "Invalid MAC address format (expected: aa:bb:cc:dd:ee:ff)"
        read -p "  Enter valid MAC address: " input < /dev/tty || true
        if [ -n "$input" ] && ! _validate_mac "$input"; then
            log_warn "Invalid MAC format, keeping current value"
            input=""
        fi
        [ -n "$input" ] && GATEWAY_MAC="$input"
    fi

    if [ "$ROLE" = "server" ]; then
        echo -e "${BOLD}Port${NC} [${LISTEN_PORT:-8443}]:"
        read -p "  Port: " input < /dev/tty || true
        LISTEN_PORT="${input:-${LISTEN_PORT:-8443}}"
        if ! _validate_port "$LISTEN_PORT"; then
            log_warn "Invalid port. Using default 8443."
            LISTEN_PORT=8443
        fi

        echo -e "${BOLD}Encryption key${NC} [keep current]:"
        read -p "  Key (enter to keep): " input < /dev/tty || true
        [ -n "$input" ] && ENCRYPTION_KEY="$input"
        REMOTE_SERVER=""
        SOCKS_PORT=""
    else
        echo -e "${BOLD}Remote server${NC} (IP:PORT):"
        read -p "  Server: " input < /dev/tty || true
        REMOTE_SERVER="${input:-$REMOTE_SERVER}"

        echo -e "${BOLD}Encryption key${NC}:"
        read -p "  Key: " input < /dev/tty || true
        [ -n "$input" ] && ENCRYPTION_KEY="$input"

        echo -e "${BOLD}SOCKS5 port${NC} [${SOCKS_PORT:-1080}]:"
        read -p "  Port: " input < /dev/tty || true
        SOCKS_PORT="${input:-${SOCKS_PORT:-1080}}"
        LISTEN_PORT=""
    fi

    # TCP flags (for both server and client)
    echo -e "${BOLD}TCP local flag${NC} [${PAQET_TCP_LOCAL_FLAG:-PA}]:"
    echo -e "  ${DIM}Controls TCP flags on outgoing packets (default: PA = PSH+ACK)${NC}"
    echo -e "  ${DIM}Valid flags: S(SYN) A(ACK) P(PSH) R(RST) F(FIN) U(URG) E(ECE) C(CWR)${NC}"
    echo -e "  ${DIM}Multiple values: PA,A (tries PA first, then A)${NC}"
    read -p "  Flag: " input < /dev/tty || true
    if [ -n "$input" ] && ! [[ "$input" =~ ^[FSRPAUEC]+(,[FSRPAUEC]+)*$ ]]; then
        log_warn "Invalid flags. Use: FSRPAUEC (e.g., PA or PA,A). Keeping current value."
        input=""
    fi
    [ -n "$input" ] && PAQET_TCP_LOCAL_FLAG="$input"

    echo -e "${BOLD}TCP remote flag${NC} [${PAQET_TCP_REMOTE_FLAG:-PA}]:"
    echo -e "  ${DIM}Controls expected TCP flags on incoming packets (default: PA)${NC}"
    echo -e "  ${DIM}Should match the server/client counterpart's local flag${NC}"
    read -p "  Flag: " input < /dev/tty || true
    if [ -n "$input" ] && ! [[ "$input" =~ ^[FSRPAUEC]+(,[FSRPAUEC]+)*$ ]]; then
        log_warn "Invalid flags. Use: FSRPAUEC (e.g., PA or PA,A). Keeping current value."
        input=""
    fi
    [ -n "$input" ] && PAQET_TCP_REMOTE_FLAG="$input"

    # Validate required fields
    if [ -z "$INTERFACE" ] || [ -z "$LOCAL_IP" ] || [ -z "$GATEWAY_MAC" ] || [ -z "$ENCRYPTION_KEY" ]; then
        log_error "Missing required configuration fields"
        [ "$was_running" = true ] && start_paqet
        return 1
    fi

    # Regenerate config.yaml and settings.conf from the shared writers so
    # tuning (KCP_*), routing, turbo and watchdog settings are preserved.
    if ! _write_paqet_config "$INSTALL_DIR/config.yaml"; then
        log_error "Failed to save configuration"
        [ "$was_running" = true ] && start_paqet
        return 1
    fi
    save_settings || log_error "Failed to save settings"

    log_success "Configuration updated"

    if [ "$was_running" = true ]; then
        start_paqet
    fi
}
