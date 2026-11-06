#═══════════════════════════════════════════════════════════════════════
# Main Installation Flow
#═══════════════════════════════════════════════════════════════════════

# Handle --update-components flag (called during self-update)
if [ "${1:-}" = "--update-components" ]; then
    INSTALL_DIR="${INSTALL_DIR:-/opt/paqctl}"
    _load_settings
    create_management_script
    exit 0
fi

main() {
    check_root
    print_header

    # Check if already installed
    if [ -f "$INSTALL_DIR/settings.conf" ] && { [ -x "$INSTALL_DIR/bin/paqet" ] || [ -f "$GFK_DIR/mainserver.py" ]; }; then
        _load_settings
        log_info "paqctl is already installed (backend: ${BACKEND:-paqet})."
        echo ""
        echo "  1. Reinstall / Reconfigure"
        echo "  2. Open menu  (same as: sudo paqctl menu)"
        echo "  3. Exit"
        echo ""
        read -p "  Choice [1-3]: " choice < /dev/tty || true
        case "$choice" in
            1) log_info "Reinstalling..." ;;
            2) exec /usr/local/bin/paqctl menu ;;
            *) exit 0 ;;
        esac
    fi

    # Step 1: Detect OS
    log_info "Step 1/7: Detecting operating system..."
    detect_os
    echo ""

    # Step 2: Install dependencies
    log_info "Step 2/7: Installing dependencies..."
    check_dependencies
    echo ""

    # Carry Telegram settings and fine-grained KCP tuning over a reinstall.
    # Everything the wizard asks about (backend, role, network, routing,
    # profile, turbo, watchdog) comes from the wizard, not the old file.
    if [ -f "$INSTALL_DIR/settings.conf" ]; then
        _load_settings TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID TELEGRAM_INTERVAL TELEGRAM_ENABLED \
            TELEGRAM_ALERTS_ENABLED TELEGRAM_DAILY_SUMMARY TELEGRAM_WEEKLY_SUMMARY \
            TELEGRAM_SERVER_LABEL TELEGRAM_START_HOUR \
            KCP_NODELAY KCP_INTERVAL KCP_RESEND KCP_NOCONGESTION KCP_SOCKBUF KCP_SMUXBUF
    fi

    # Step 3: Configuration wizard (determines backend + role + config)
    log_info "Step 3/7: Configuration..."
    run_config_wizard
    echo ""

    # Step 4: Backend-specific dependencies and download
    log_info "Step 4/7: Setting up ${BACKEND} backend..."
    if [ "$BACKEND" = "gfw-knocker" ]; then
        install_python_deps || { log_error "Failed to install Python dependencies"; exit 1; }
        download_gfk || { log_error "Failed to download GFK"; exit 1; }
        generate_gfk_certs || { log_error "Failed to generate certificates"; exit 1; }
        if [ "$ROLE" = "server" ]; then
            # Install Xray SOCKS5 proxy (adds alongside panel if detected)
            setup_xray_for_gfk || { log_error "Failed to setup Xray"; exit 1; }
            # Regenerate config if mappings changed (panel detected → SOCKS5 added)
            if [ "${XRAY_PANEL_DETECTED:-false}" = "true" ]; then
                generate_gfk_config || { log_error "Failed to regenerate GFK config"; exit 1; }
            fi
        elif [ "$ROLE" = "client" ]; then
            create_gfk_client_wrapper || { log_error "Failed to create client wrapper"; exit 1; }
        fi
        PAQET_VERSION="$GFK_VERSION_PINNED"
        log_info "Using GFK ${PAQET_VERSION} (pinned for stability)"
    else
        # Fetch latest version from GitHub, fall back to pinned if API unreachable
        PAQET_VERSION=$(curl -s --max-time 10 "$PAQET_API_URL" 2>/dev/null | grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | grep -o '"[^"]*"$' | tr -d '"')
        if [ -z "$PAQET_VERSION" ] || ! _validate_version_tag "$PAQET_VERSION"; then
            PAQET_VERSION="$PAQET_VERSION_PINNED"
        fi
        log_info "Installing paqet ${PAQET_VERSION}"
        download_paqet "$PAQET_VERSION"
    fi
    echo ""

    # Step 5: Apply firewall rules
    log_info "Step 5/7: Firewall setup..."
    if [ "$BACKEND" = "gfw-knocker" ]; then
        if [ "$ROLE" = "server" ]; then
            local _vio_port="${GFK_VIO_PORT:-45000}"
            log_info "Blocking VIO TCP port $_vio_port (raw socket handles it)..."
            if _is_firewalld_active; then
                firewall-cmd --direct --query-rule ipv4 raw PREROUTING 0 -p tcp --dport "$_vio_port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || \
                    firewall-cmd --direct --add-rule ipv4 raw PREROUTING 0 -p tcp --dport "$_vio_port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || true
                firewall-cmd --direct --query-rule ipv4 raw OUTPUT 0 -p tcp --sport "$_vio_port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || \
                    firewall-cmd --direct --add-rule ipv4 raw OUTPUT 0 -p tcp --sport "$_vio_port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || true
                firewall-cmd --direct --query-rule ipv4 filter INPUT 0 -p tcp --dport "$_vio_port" -m comment --comment "paqctl" -j DROP 2>/dev/null || \
                    firewall-cmd --direct --add-rule ipv4 filter INPUT 0 -p tcp --dport "$_vio_port" -m comment --comment "paqctl" -j DROP 2>/dev/null || \
                    log_warn "Failed to add VIO INPUT DROP rule via firewalld"
                firewall-cmd --direct --query-rule ipv4 filter OUTPUT 0 -p tcp --sport "$_vio_port" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP 2>/dev/null || \
                    firewall-cmd --direct --add-rule ipv4 filter OUTPUT 0 -p tcp --sport "$_vio_port" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP 2>/dev/null || \
                    log_warn "Failed to add VIO RST DROP rule via firewalld"
                firewall-cmd --direct --query-rule ipv6 filter INPUT 0 -p tcp --dport "$_vio_port" -m comment --comment "paqctl" -j DROP 2>/dev/null || \
                    firewall-cmd --direct --add-rule ipv6 filter INPUT 0 -p tcp --dport "$_vio_port" -m comment --comment "paqctl" -j DROP 2>/dev/null || true
                firewall-cmd --direct --query-rule ipv6 filter OUTPUT 0 -p tcp --sport "$_vio_port" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP 2>/dev/null || \
                    firewall-cmd --direct --add-rule ipv6 filter OUTPUT 0 -p tcp --sport "$_vio_port" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP 2>/dev/null || true
                persist_iptables_rules
            elif command -v iptables &>/dev/null; then
                modprobe iptable_raw 2>/dev/null || true
                iptables -t raw -C PREROUTING -p tcp --dport "$_vio_port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || \
                    iptables -t raw -I PREROUTING 1 -p tcp --dport "$_vio_port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || true
                iptables -t raw -C OUTPUT -p tcp --sport "$_vio_port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || \
                    iptables -t raw -I OUTPUT 1 -p tcp --sport "$_vio_port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || true
                iptables -C INPUT -p tcp --dport "$_vio_port" -m comment --comment "paqctl" -j DROP 2>/dev/null || \
                    iptables -I INPUT 1 -p tcp --dport "$_vio_port" -m comment --comment "paqctl" -j DROP 2>/dev/null || \
                    log_warn "Failed to add VIO INPUT DROP rule"
                iptables -C OUTPUT -p tcp --sport "$_vio_port" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP 2>/dev/null || \
                    iptables -I OUTPUT 1 -p tcp --sport "$_vio_port" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP 2>/dev/null || \
                    log_warn "Failed to add VIO RST DROP rule"
                if command -v ip6tables &>/dev/null; then
                    ip6tables -C INPUT -p tcp --dport "$_vio_port" -m comment --comment "paqctl" -j DROP 2>/dev/null || \
                        ip6tables -I INPUT 1 -p tcp --dport "$_vio_port" -m comment --comment "paqctl" -j DROP 2>/dev/null || true
                    ip6tables -C OUTPUT -p tcp --sport "$_vio_port" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP 2>/dev/null || \
                        ip6tables -I OUTPUT 1 -p tcp --sport "$_vio_port" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP 2>/dev/null || true
                fi
            else
                log_warn "iptables not found - firewall rules cannot be applied"
            fi
        else
            local _vio_client_port="${GFK_VIO_CLIENT_PORT:-40000}"
            log_info "Applying NOTRACK + DROP rules for VIO client port $_vio_client_port..."
            if _is_firewalld_active; then
                firewall-cmd --direct --query-rule ipv4 raw PREROUTING 0 -p tcp --dport "$_vio_client_port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || \
                    firewall-cmd --direct --add-rule ipv4 raw PREROUTING 0 -p tcp --dport "$_vio_client_port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || true
                firewall-cmd --direct --query-rule ipv4 raw OUTPUT 0 -p tcp --sport "$_vio_client_port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || \
                    firewall-cmd --direct --add-rule ipv4 raw OUTPUT 0 -p tcp --sport "$_vio_client_port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || true
                firewall-cmd --direct --query-rule ipv4 filter INPUT 0 -p tcp --dport "$_vio_client_port" -m comment --comment "paqctl" -j DROP 2>/dev/null || \
                    firewall-cmd --direct --add-rule ipv4 filter INPUT 0 -p tcp --dport "$_vio_client_port" -m comment --comment "paqctl" -j DROP 2>/dev/null || \
                    log_warn "Failed to add VIO client INPUT DROP rule via firewalld"
                firewall-cmd --direct --query-rule ipv4 filter OUTPUT 0 -p tcp --sport "$_vio_client_port" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP 2>/dev/null || \
                    firewall-cmd --direct --add-rule ipv4 filter OUTPUT 0 -p tcp --sport "$_vio_client_port" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP 2>/dev/null || \
                    log_warn "Failed to add VIO client RST DROP rule via firewalld"
                firewall-cmd --direct --query-rule ipv6 filter INPUT 0 -p tcp --dport "$_vio_client_port" -m comment --comment "paqctl" -j DROP 2>/dev/null || \
                    firewall-cmd --direct --add-rule ipv6 filter INPUT 0 -p tcp --dport "$_vio_client_port" -m comment --comment "paqctl" -j DROP 2>/dev/null || true
                firewall-cmd --direct --query-rule ipv6 filter OUTPUT 0 -p tcp --sport "$_vio_client_port" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP 2>/dev/null || \
                    firewall-cmd --direct --add-rule ipv6 filter OUTPUT 0 -p tcp --sport "$_vio_client_port" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP 2>/dev/null || true
                persist_iptables_rules
            elif command -v iptables &>/dev/null; then
                modprobe iptable_raw 2>/dev/null || true
                iptables -t raw -C PREROUTING -p tcp --dport "$_vio_client_port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || \
                    iptables -t raw -I PREROUTING 1 -p tcp --dport "$_vio_client_port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || true
                iptables -t raw -C OUTPUT -p tcp --sport "$_vio_client_port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || \
                    iptables -t raw -I OUTPUT 1 -p tcp --sport "$_vio_client_port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || true
                iptables -C INPUT -p tcp --dport "$_vio_client_port" -m comment --comment "paqctl" -j DROP 2>/dev/null || \
                    iptables -I INPUT 1 -p tcp --dport "$_vio_client_port" -m comment --comment "paqctl" -j DROP 2>/dev/null || \
                    log_warn "Failed to add VIO client INPUT DROP rule"
                iptables -C OUTPUT -p tcp --sport "$_vio_client_port" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP 2>/dev/null || \
                    iptables -I OUTPUT 1 -p tcp --sport "$_vio_client_port" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP 2>/dev/null || \
                    log_warn "Failed to add VIO client RST DROP rule"
                if command -v ip6tables &>/dev/null; then
                    ip6tables -C INPUT -p tcp --dport "$_vio_client_port" -m comment --comment "paqctl" -j DROP 2>/dev/null || \
                        ip6tables -I INPUT 1 -p tcp --dport "$_vio_client_port" -m comment --comment "paqctl" -j DROP 2>/dev/null || true
                    ip6tables -C OUTPUT -p tcp --sport "$_vio_client_port" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP 2>/dev/null || \
                        ip6tables -I OUTPUT 1 -p tcp --sport "$_vio_client_port" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP 2>/dev/null || true
                fi
            else
                log_warn "iptables not found - firewall rules cannot be applied"
            fi
        fi
    elif [ "$ROLE" = "server" ]; then
        apply_iptables_rules "$LISTEN_PORT"
    else
        log_info "Client mode - no firewall rules needed"
    fi
    echo ""

    # Step 6: Create service + management script
    log_info "Step 6/7: Setting up service..."
    if ! mkdir -p "$INSTALL_DIR/bin" "$BACKUP_DIR"; then
        log_error "Failed to create installation directories"
        exit 1
    fi
    create_management_script
    setup_service
    setup_logrotate
    # Save settings to persist version and config
    save_settings
    if [ "$TURBO_ENABLED" = "true" ]; then
        /usr/local/bin/paqctl turbo 2>/dev/null || true
    fi
    if [ "$WATCHDOG_ENABLED" = "true" ]; then
        /usr/local/bin/paqctl watchdog enable 2>/dev/null || true
    fi
    echo ""

    # Step 7: Start the service
    log_info "Step 7/7: Starting ${BACKEND}..."
    if command -v systemctl &>/dev/null && [ -d /run/systemd/system ]; then
        systemctl start paqctl.service 2>/dev/null
    fi

    sleep 2

    # Final summary
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}${BOLD}  INSTALLATION COMPLETE!${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  Backend:    ${BOLD}${BACKEND}${NC}"
    echo -e "  Role:       ${BOLD}${ROLE}${NC}"
    echo -e "  Version:    ${BOLD}${PAQET_VERSION}${NC}"

    if [ "$BACKEND" = "gfw-knocker" ]; then
        if [ "$ROLE" = "server" ]; then
            local _xray_port
            _xray_port=$(echo "${GFK_PORT_MAPPINGS:-14000:443}" | cut -d: -f2 | cut -d, -f1)
            echo -e "  VIO port:   ${BOLD}${GFK_VIO_PORT}${NC}"
            echo -e "  QUIC port:  ${BOLD}${GFK_QUIC_PORT}${NC}"
            if [ "${XRAY_PANEL_DETECTED:-false}" = "true" ]; then
                echo -e "  Xray:       ${BOLD}Existing panel detected (forwarding to port ${_xray_port})${NC}"
                if [ -n "${GFK_SOCKS_VIO_PORT:-}" ]; then
                    echo -e "  SOCKS5:     ${BOLD}127.0.0.1:${GFK_SOCKS_PORT} (auto-added, VIO port ${GFK_SOCKS_VIO_PORT})${NC}"
                    echo ""
                    echo -e "  ${GREEN}✓ GFK forwards to panel + SOCKS5 proxy added${NC}"
                else
                    echo ""
                    echo -e "  ${GREEN}✓ GFK forwards to panel${NC}"
                fi
                local _first_vio
                _first_vio=$(echo "${GFK_PORT_MAPPINGS:-14000:443}" | cut -d: -f1 | cut -d, -f1)
                echo -e "  ${YELLOW}! Panel users: configure Iran outbound → 127.0.0.1:${_first_vio}${NC}"
                if [ -n "${GFK_SOCKS_VIO_PORT:-}" ]; then
                    echo -e "  ${YELLOW}! Direct SOCKS5: use 127.0.0.1:${GFK_SOCKS_VIO_PORT} on client${NC}"
                fi
            else
                echo -e "  Xray:       ${BOLD}127.0.0.1:${_xray_port} (SOCKS5)${NC}"
                echo ""
                echo -e "  ${GREEN}✓ Xray SOCKS5 proxy installed and running${NC}"
            fi
            echo ""
            echo -e "${YELLOW}╔═══════════════════════════════════════════════════════════════╗${NC}"
            echo -e "${YELLOW}║  ${BOLD}CLIENT CONNECTION INFO - SAVE THIS!${NC}${YELLOW}                          ║${NC}"
            echo -e "${YELLOW}╠═══════════════════════════════════════════════════════════════╣${NC}"
            echo -e "${YELLOW}║${NC}  Server IP:  ${BOLD}${GFK_SERVER_IP}${NC}"
            echo -e "${YELLOW}║${NC}  Auth Code:  ${BOLD}${GFK_AUTH_CODE}${NC}"
            echo -e "${YELLOW}║${NC}  Mappings:   ${BOLD}${GFK_PORT_MAPPINGS}${NC}"
            if [ "${XRAY_PANEL_DETECTED:-false}" = "true" ] && [ -n "${GFK_SOCKS_VIO_PORT:-}" ]; then
                echo -e "${YELLOW}║${NC}"
                echo -e "${YELLOW}║${NC}  ${GREEN}Proxy port:  127.0.0.1:${GFK_SOCKS_VIO_PORT} (SOCKS5 — use this on client)${NC}"
                local _panel_vio
                _panel_vio=$(echo "${GFK_PORT_MAPPINGS:-14000:443}" | cut -d, -f1 | cut -d: -f1)
                echo -e "${YELLOW}║${NC}  Panel port: 127.0.0.1:${_panel_vio} (vmess/vless — for panel-to-panel)"
            elif [ "${XRAY_PANEL_DETECTED:-false}" = "true" ]; then
                local _panel_vio
                _panel_vio=$(echo "${GFK_PORT_MAPPINGS:-14000:443}" | cut -d, -f1 | cut -d: -f1)
                echo -e "${YELLOW}║${NC}"
                echo -e "${YELLOW}║${NC}  Panel port: 127.0.0.1:${_panel_vio} (vmess/vless — for panel-to-panel)"
            else
                local _proxy_vio
                _proxy_vio=$(echo "${GFK_PORT_MAPPINGS:-14000:443}" | cut -d, -f1 | cut -d: -f1)
                echo -e "${YELLOW}║${NC}"
                echo -e "${YELLOW}║${NC}  ${GREEN}Proxy port:  127.0.0.1:${_proxy_vio} (SOCKS5 — use this on client)${NC}"
            fi
            echo -e "${YELLOW}╚═══════════════════════════════════════════════════════════════╝${NC}"
        else
            local _socks_vio
            if [ -n "${GFK_SOCKS_VIO_PORT:-}" ]; then
                _socks_vio="$GFK_SOCKS_VIO_PORT"
            else
                _socks_vio=$(echo "${GFK_PORT_MAPPINGS:-14000:443}" | cut -d, -f1 | cut -d: -f1)
            fi
            echo -e "  Server:     ${BOLD}${GFK_SERVER_IP}${NC}"
            echo -e "  SOCKS5:     ${BOLD}127.0.0.1:${_socks_vio}${NC}"
            echo ""
            echo -e "  ${YELLOW}Test your proxy:${NC}"
            echo -e "  ${BOLD}  curl --proxy socks5h://127.0.0.1:${_socks_vio} https://httpbin.org/ip${NC}"
        fi
    elif [ "$ROLE" = "server" ]; then
        echo -e "  Port:       ${BOLD}${LISTEN_PORT}${NC}"
        echo ""
        echo -e "${YELLOW}╔═══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}║  ${BOLD}CLIENT CONNECTION INFO - SAVE THIS!${NC}${YELLOW}                          ║${NC}"
        echo -e "${YELLOW}╠═══════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${YELLOW}║${NC}  Server:  ${BOLD}${LOCAL_IP}:${LISTEN_PORT}${NC}"
        echo -e "${YELLOW}║${NC}  Key:     ${BOLD}${ENCRYPTION_KEY}${NC}"
        echo -e "${YELLOW}╚═══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  ${CYAN}Key also saved in: ${INSTALL_DIR}/config.yaml${NC}"
    else
        echo -e "  Server:     ${BOLD}${REMOTE_SERVER}${NC}"
        echo -e "  SOCKS5:     ${BOLD}127.0.0.1:${SOCKS_PORT}${NC}"
        echo ""
        echo -e "  ${YELLOW}Test your proxy:${NC}"
        echo -e "  ${BOLD}  curl --proxy socks5h://127.0.0.1:${SOCKS_PORT} https://httpbin.org/ip${NC}"
    fi

    echo ""
    echo -e "  ${CYAN}Management commands:${NC}"
    echo "    sudo paqctl menu       Interactive menu"
    echo "    sudo paqctl status     Check status"
    echo "    sudo paqctl health     Health check"
    echo "    sudo paqctl logs       View logs"
    echo "    sudo paqctl update     Update paqet"
    echo "    sudo paqctl help       All commands"
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${BOLD}${YELLOW}⚠ IMPORTANT: Save the connection info above before continuing!${NC}"
    echo ""
    echo -e "  ${CYAN}Press Y to open the management menu, or any other key to exit...${NC}"
    read -n 1 -r choice < /dev/tty || true
    echo ""
    if [[ "$choice" =~ ^[Yy]$ ]]; then
        exec /usr/local/bin/paqctl menu
    else
        echo -e "  ${GREEN}Run 'sudo paqctl menu' when ready.${NC}"
        echo ""
    fi
}

# Handle command line arguments
case "${1:-}" in
    menu)
        check_root
        if [ -f "$INSTALL_DIR/settings.conf" ] && [ -x /usr/local/bin/paqctl ]; then
            exec /usr/local/bin/paqctl menu
        else
            echo -e "${RED}paqctl is not installed. Run the installer first.${NC}"
            exit 1
        fi
        ;;
    *)
        main "$@"
        ;;
esac
