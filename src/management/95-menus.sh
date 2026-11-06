#═══════════════════════════════════════════════════════════════════════
# Paqet Diagnostic Tools (ping / dump)
#═══════════════════════════════════════════════════════════════════════

run_ping() {
    echo ""
    if [ "$BACKEND" = "gfw-knocker" ]; then
        log_warn "ping diagnostic is only available for paqet backend"
        return 0
    fi
    if [ ! -x "$INSTALL_DIR/bin/paqet" ]; then
        log_error "paqet binary not found"
        return 1
    fi
    if [ ! -f "$INSTALL_DIR/config.yaml" ]; then
        log_error "config.yaml not found. Run: sudo paqctl config"
        return 1
    fi
    if [ "$ROLE" = "server" ]; then
        log_warn "paqet ping tests the connection from a client to its server; run it on a client."
        log_info "On this server, use: sudo paqctl health (or doctor)"
        return 0
    fi
    log_info "Running paqet ping (Ctrl+C to stop)..."
    echo ""
    "$INSTALL_DIR/bin/paqet" ping -c "$INSTALL_DIR/config.yaml" 2>&1 || true
    echo ""
}

run_dump() {
    echo ""
    if [ "$BACKEND" = "gfw-knocker" ]; then
        log_warn "dump diagnostic is only available for paqet backend"
        return 0
    fi
    if [ ! -x "$INSTALL_DIR/bin/paqet" ]; then
        log_error "paqet binary not found"
        return 1
    fi
    if [ ! -f "$INSTALL_DIR/config.yaml" ]; then
        log_error "config.yaml not found. Run: sudo paqctl config"
        return 1
    fi
    log_info "Running paqet dump — packet capture diagnostic (Ctrl+C to stop)..."
    echo -e "${DIM}  This shows raw packets being sent and received by paqet.${NC}"
    echo ""
    "$INSTALL_DIR/bin/paqet" dump -c "$INSTALL_DIR/config.yaml" 2>&1 || true
    echo ""
}

#═══════════════════════════════════════════════════════════════════════
# Settings Menu
#═══════════════════════════════════════════════════════════════════════

show_settings_menu() {
    local redraw=true
    while true; do
        if [ "$redraw" = true ]; then
            clear
            echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
            echo -e "${BOLD}  SETTINGS & TOOLS${NC}"
            echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
            echo ""
            echo "  1. Change configuration"
            echo "  2. Manage firewall rules"
            echo "  3. Generate encryption key"
            echo "  4. Backup configuration"
            echo "  5. Restore from backup"
            echo "  6. Health check"
            echo "  7. Telegram notifications"
            echo "  8. Version info"
            echo "  9. Rollback to previous version"
            echo "  p. Ping test (connectivity)"
            echo "  d. Packet dump (diagnostics)"
            echo "  c. Active Client Monitor (top)"
            echo "  t. Speed & Bandwidth Test"
            echo "  r. DNS Leak & Routing Check"
            echo "  f. IP Ban & Allowlist Manager"
            echo "  k. Rotate Encryption Key / Auth Code"
            echo "  l. System Cleanup & Cache Flush"
            echo "  e. Export Config String"
            echo "  m. Import Config String"
            echo "  a. Install additional backend"
            echo "  s. Switch backend (current: ${BACKEND})"
            echo "  0. Performance Tuning & Supercharging (Turbo, Watchdog, MTU)"
            echo "  u. Uninstall"
            echo ""
            echo "  b. Back to main menu"
            echo ""
            redraw=false
        fi

        read -p "  Choice: " s_choice < /dev/tty || break
        case "$s_choice" in
            1) change_config; redraw=true ;;
            2) show_firewall; redraw=true ;;
            3) generate_secret; read -n 1 -s -r -p "  Press any key..." < /dev/tty || true; redraw=true ;;
            4) backup_config; read -n 1 -s -r -p "  Press any key..." < /dev/tty || true; redraw=true ;;
            5) restore_config; read -n 1 -s -r -p "  Press any key..." < /dev/tty || true; redraw=true ;;
            6) health_check; read -n 1 -s -r -p "  Press any key..." < /dev/tty || true; redraw=true ;;
            7) show_telegram_menu; redraw=true ;;
            8) show_version; read -n 1 -s -r -p "  Press any key..." < /dev/tty || true; redraw=true ;;
            9) rollback_paqet; read -n 1 -s -r -p "  Press any key..." < /dev/tty || true; redraw=true ;;
            p|P) run_ping; read -n 1 -s -r -p "  Press any key..." < /dev/tty || true; redraw=true ;;
            d|D) run_dump; read -n 1 -s -r -p "  Press any key..." < /dev/tty || true; redraw=true ;;
            c|C) show_active_clients; read -n 1 -s -r -p "  Press any key..." < /dev/tty || true; redraw=true ;;
            t|T) run_speedtest; read -n 1 -s -r -p "  Press any key..." < /dev/tty || true; redraw=true ;;
            r|R) check_proxy_routing; read -n 1 -s -r -p "  Press any key..." < /dev/tty || true; redraw=true ;;
            f|F) manage_ip_ban; redraw=true ;;
            k|K) rotate_key; read -n 1 -s -r -p "  Press any key..." < /dev/tty || true; redraw=true ;;
            l|L) system_cleanup; read -n 1 -s -r -p "  Press any key..." < /dev/tty || true; redraw=true ;;
            e|E) export_config_string; read -n 1 -s -r -p "  Press any key..." < /dev/tty || true; redraw=true ;;
            m|M) import_config_string; read -n 1 -s -r -p "  Press any key..." < /dev/tty || true; redraw=true ;;
            a|A) install_additional_backend; redraw=true ;;
            s|S) switch_backend; redraw=true ;;
            0) tune_menu; redraw=true ;;
            u|U) uninstall_paqctl; [ -d "$INSTALL_DIR" ] || exit 0; redraw=true ;;
            b|B) return ;;
            "") ;;
            *) echo -e "  ${RED}Invalid choice${NC}" ;;
        esac
    done
}

#═══════════════════════════════════════════════════════════════════════
# Info Menu
#═══════════════════════════════════════════════════════════════════════

show_info_menu() {
    local redraw=true
    while true; do
        if [ "$redraw" = true ]; then
            clear
            echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
            echo -e "${BOLD}  INFO & HELP${NC}"
            echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
            echo ""
            echo "  1. How Paqet Works"
            echo "  2. Server vs Client Mode"
            echo "  3. Firewall Rules Explained"
            echo "  4. Troubleshooting"
            echo "  5. About"
            echo ""
            echo "  b. Back"
            echo ""
            redraw=false
        fi

        read -p "  Choice: " i_choice < /dev/tty || break
        case "$i_choice" in
            1)
                clear
                echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
                echo -e "${BOLD}  HOW PAQET WORKS${NC}"
                echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
                echo ""
                echo -e "  ${BOLD}Overview:${NC}"
                echo "  Paqet is a bidirectional packet-level proxy written in Go."
                echo "  Unlike traditional proxies (Shadowsocks, V2Ray, etc.) that"
                echo "  operate at the application or transport layer, paqet works"
                echo "  at the raw socket level — below the OS network stack."
                echo ""
                echo -e "  ${BOLD}How it works step by step:${NC}"
                echo ""
                echo "  1. PACKET CRAFTING"
                echo "     Paqet uses gopacket + libpcap to craft TCP packets"
                echo "     directly, bypassing the kernel's TCP/IP stack entirely."
                echo "     This means the OS doesn't even know there's a connection."
                echo ""
                echo "  2. KCP ENCRYPTED TRANSPORT"
                echo "     All traffic between client and server is encrypted using"
                echo "     the KCP protocol with AES symmetric key encryption."
                echo "     KCP provides reliable, ordered delivery over raw packets"
                echo "     with built-in error correction and retransmission."
                echo ""
                echo "  3. CONNECTION MULTIPLEXING"
                echo "     Multiple connections are multiplexed over a single KCP"
                echo "     session using smux, reducing overhead and improving"
                echo "     performance for concurrent requests."
                echo ""
                echo "  4. FIREWALL BYPASS"
                echo "     Because it operates below the OS network stack, paqet"
                echo "     bypasses traditional firewalls (ufw, firewalld) and"
                echo "     kernel-level connection tracking (conntrack). The OS"
                echo "     firewall never sees the traffic as a 'connection'."
                echo ""
                echo "  5. SOCKS5 PROXY (Client)"
                echo "     On the client side, paqet exposes a standard SOCKS5"
                echo "     proxy that any application can use. Traffic enters"
                echo "     the SOCKS5 port, gets encrypted and sent via raw"
                echo "     packets to the server, which forwards it to the"
                echo "     destination on the open internet."
                echo ""
                echo -e "  ${DIM}Technical stack: Go, gopacket, libpcap, KCP, smux, AES${NC}"
                echo -e "  ${DIM}Project: https://github.com/SamNet-dev/paqctl${NC}"
                echo ""
                read -n 1 -s -r -p "  Press any key..." < /dev/tty || true
                redraw=true
                ;;
            2)
                clear
                echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
                echo -e "${BOLD}  SERVER VS CLIENT MODE${NC}"
                echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
                echo ""
                echo -e "  ${GREEN}${BOLD}SERVER MODE${NC}"
                echo -e "  ${DIM}─────────────────────────────────────────────${NC}"
                echo "  The server is the exit node. It receives encrypted raw"
                echo "  packets from clients, decrypts them, and forwards the"
                echo "  traffic to the open internet. Responses are encrypted"
                echo "  and sent back to the client."
                echo ""
                echo "  Requirements:"
                echo "  - A server with a public IP address"
                echo "  - Root access (raw sockets need it)"
                echo "  - libpcap installed"
                echo "  - iptables NOTRACK + RST DROP rules (auto-managed)"
                echo "  - An open port (paqctl manages firewall rules, but you"
                echo "    may need to allow the port in your cloud provider's"
                echo "    security group / network firewall)"
                echo ""
                echo "  After setup, share with your clients:"
                echo "    - Server IP and port (e.g. 1.2.3.4:8443)"
                echo "    - Encryption key (generated during setup)"
                echo ""
                echo -e "  ${CYAN}${BOLD}CLIENT MODE${NC}"
                echo -e "  ${DIM}─────────────────────────────────────────────${NC}"
                echo "  The client connects to a paqet server and provides a"
                echo "  local SOCKS5 proxy. Applications on your machine connect"
                echo "  to the SOCKS5 port, and traffic is tunneled through"
                echo "  paqet's encrypted raw-socket connection to the server."
                echo ""
                echo "  Requirements:"
                echo "  - Server IP:PORT and encryption key from the server admin"
                echo "  - Root access (raw sockets need it)"
                echo "  - libpcap installed"
                echo ""
                echo "  Usage after setup:"
                echo "    Browser:  Set SOCKS5 proxy to 127.0.0.1:1080"
                echo "    curl:     curl --proxy socks5h://127.0.0.1:1080 URL"
                echo "    System:   Configure system proxy to SOCKS5 127.0.0.1:1080"
                echo ""
                echo -e "  ${BOLD}Data flow:${NC}"
                echo "    App -> SOCKS5(:1080) -> paqet client -> raw packets"
                echo "    -> internet -> paqet server -> destination website"
                echo ""
                read -n 1 -s -r -p "  Press any key..." < /dev/tty || true
                redraw=true
                ;;
            3)
                clear
                echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
                echo -e "${BOLD}  FIREWALL RULES EXPLAINED${NC}"
                echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
                echo ""
                echo "  Paqet requires specific iptables rules on the SERVER."
                echo "  These rules are needed because paqet crafts raw TCP"
                echo "  packets, and without them the kernel interferes."
                echo ""
                echo -e "  ${BOLD}Rule 1: PREROUTING NOTRACK${NC}"
                echo "  iptables -t raw -A PREROUTING -p tcp --dport PORT -j NOTRACK"
                echo ""
                echo "  WHY: Tells the kernel's connection tracker (conntrack) to"
                echo "  ignore incoming packets on the paqet port. Without this,"
                echo "  conntrack tries to match packets to connections it doesn't"
                echo "  know about and may drop them."
                echo ""
                echo -e "  ${BOLD}Rule 2: OUTPUT NOTRACK${NC}"
                echo "  iptables -t raw -A OUTPUT -p tcp --sport PORT -j NOTRACK"
                echo ""
                echo "  WHY: Same as above but for outgoing packets. Prevents"
                echo "  conntrack from tracking paqet's outbound raw packets."
                echo ""
                echo -e "  ${BOLD}Rule 3: RST DROP${NC}"
                echo "  iptables -t mangle -A OUTPUT -p tcp --sport PORT"
                echo "           --tcp-flags RST RST -j DROP"
                echo ""
                echo "  WHY: When the kernel sees incoming TCP SYN packets on a"
                echo "  port with no listening socket, it sends TCP RST (reset)"
                echo "  back. This would kill paqet connections. This rule drops"
                echo "  those RST packets so paqet can handle them instead."
                echo ""
                echo -e "  ${DIM}These rules are auto-managed by paqctl:${NC}"
                echo -e "  ${DIM}  - Applied on service start (ExecStartPre)${NC}"
                echo -e "  ${DIM}  - Removed on service stop (ExecStopPost)${NC}"
                echo -e "  ${DIM}  - Persisted across reboots when possible${NC}"
                echo ""
                read -n 1 -s -r -p "  Press any key..." < /dev/tty || true
                redraw=true
                ;;
            4)
                clear
                echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
                echo -e "${BOLD}  TROUBLESHOOTING${NC}"
                echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
                echo ""
                echo -e "  ${BOLD}Service won't start:${NC}"
                echo "  1. Check logs:        sudo paqctl logs"
                echo "  2. Run health check:  sudo paqctl health"
                echo "  3. Verify libpcap:    ldconfig -p | grep libpcap"
                echo "  4. Check config:      cat /opt/paqctl/config.yaml"
                echo "  5. Test binary:       sudo /opt/paqctl/bin/paqet version"
                echo ""
                echo -e "  ${BOLD}Client can't connect to server:${NC}"
                echo "  1. Verify server IP and port are correct"
                echo "  2. Check encryption key matches exactly"
                echo "  3. Ensure server iptables rules are active:"
                echo "       sudo paqctl firewall  (on server)"
                echo "  4. Check cloud security group allows the port"
                echo "  5. Test raw connectivity:"
                echo "       sudo /opt/paqctl/bin/paqet ping -c /opt/paqctl/config.yaml"
                echo "  6. Run packet dump to see what's happening:"
                echo "       sudo /opt/paqctl/bin/paqet dump -c /opt/paqctl/config.yaml"
                echo ""
                echo -e "  ${BOLD}SOCKS5 not working (client side):${NC}"
                echo "  1. Verify client is running:  sudo paqctl status"
                echo "  2. Test the proxy directly:"
                echo "       curl -v --proxy socks5h://127.0.0.1:1080 https://httpbin.org/ip"
                echo "  3. Check SOCKS port is listening:"
                echo "       ss -tlnp | grep 1080"
                echo "  4. Check if paqet output shows errors:"
                echo "       sudo paqctl logs"
                echo ""
                echo -e "  ${BOLD}High CPU / Memory:${NC}"
                echo "  1. Check process stats:  sudo paqctl status"
                echo "  2. Restart the service:  sudo paqctl restart"
                echo "  3. Check for latest version: sudo paqctl update"
                echo ""
                echo -e "  ${BOLD}After system reboot:${NC}"
                echo "  1. paqctl auto-starts via systemd (check: systemctl status paqctl)"
                echo "  2. iptables rules are re-applied by ExecStartPre"
                echo "  3. If rules are missing: sudo paqctl firewall -> Apply"
                echo ""
                read -n 1 -s -r -p "  Press any key..." < /dev/tty || true
                redraw=true
                ;;
            5)
                clear
                echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
                echo -e "${BOLD}  ABOUT${NC}"
                echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
                echo ""
                echo -e "  ${BOLD}paqctl v${VERSION}${NC} - Paqet Management Tool"
                echo ""
                echo -e "  ${CYAN}── Paqet ──${NC}"
                echo ""
                echo -e "  ${BOLD}Creator:${NC}    hanselime"
                echo -e "  ${BOLD}Repository:${NC} https://github.com/SamNet-dev/paqctl"
                echo -e "  ${BOLD}License:${NC}    AGPL-3.0 - Copyright (C) 2026 SamNet Technologies, LLC"
                echo -e "  ${BOLD}Language:${NC}   Go"
                echo -e "  ${BOLD}Contact:${NC}    Signal @hanselime.11"
                echo ""
                echo "  Paqet is a bidirectional packet-level proxy that uses"
                echo "  KCP over raw TCP packets with custom TCP flags."
                echo "  It operates below the OS TCP/IP stack to bypass"
                echo "  firewalls and deep packet inspection."
                echo ""
                echo "  Features:"
                echo "  - Raw TCP packet crafting via gopacket"
                echo "  - KCP + AES symmetric encryption"
                echo "  - SOCKS5 proxy for dynamic connections"
                echo "  - Connection multiplexing via smux"
                echo "  - Cross-platform (Linux, macOS, Windows)"
                echo "  - Android client: github.com/AliRezaBeigy/paqetNG"
                echo ""
                echo -e "  ${CYAN}── paqctl Management Tool ──${NC}"
                echo ""
                echo -e "  ${BOLD}Built by:${NC}   SamNet-dev"
                echo -e "  ${BOLD}Repository:${NC} https://github.com/SamNet-dev/paqctl"
                echo -e "  ${BOLD}License:${NC}    AGPL-3.0 - Copyright (C) 2026 SamNet Technologies, LLC"
                echo ""
                echo "  paqctl provides one-click installation, configuration,"
                echo "  service management, auto-updates, health monitoring,"
                echo "  and Telegram notifications for paqet."
                echo ""
                echo -e "  ${DIM}Original paqet by hanselime, improved by SamNet.${NC}"
                echo ""
                read -n 1 -s -r -p "  Press any key..." < /dev/tty || true
                redraw=true
                ;;
            b|B) return ;;
            "") ;;
            *) echo -e "  ${RED}Invalid choice${NC}" ;;
        esac
    done
}

#═══════════════════════════════════════════════════════════════════════
# Connection Info Display
#═══════════════════════════════════════════════════════════════════════

# show_connection_info [--ip ADDR] [--qr]   (supports --json)
show_connection_info() {
    local -a export_args=("$@")
    _load_settings

    local local_ip
    local_ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="src"){print $(i+1); exit}}')
    [ -n "$local_ip" ] || local_ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    [ -n "$local_ip" ] || local_ip="unknown"

    local paqet_installed=false gfk_installed=false
    _paqet_installed && paqet_installed=true
    _gfk_installed && gfk_installed=true

    local paqet_port="${LISTEN_PORT:-8443}"
    local paqet_key="${ENCRYPTION_KEY:-}"
    if [ -z "$paqet_key" ] && [ -f "$INSTALL_DIR/config.yaml" ]; then
        paqet_key=$(grep -E '^[[:space:]]*key:' "$INSTALL_DIR/config.yaml" 2>/dev/null | head -1 | awk '{print $2}' | tr -d '"' || true)
    fi
    local gfk_ip="${GFK_SERVER_IP:-$local_ip}"
    local gfk_auth="${GFK_AUTH_CODE:-}"
    local gfk_mappings="${GFK_PORT_MAPPINGS:-14000:443}"

    if [ "$JSON_OUTPUT" = true ]; then
        local uri="" host=""
        if [ "$paqet_installed" = true ] || [ "$gfk_installed" = true ]; then
            local _a override=""
            for ((_a = 0; _a < ${#export_args[@]}; _a++)); do
                case "${export_args[$_a]}" in
                    --ip) override="${export_args[$((_a + 1))]:-}" ;;
                    --ip=*) override="${export_args[$_a]#--ip=}" ;;
                esac
            done
            host=$(_export_host "$override" 2>/dev/null) && uri=$(_build_export_uri "$host" 2>/dev/null)
        fi
        printf '{"role":%s,"backend":%s,' "$(_json_str "$ROLE")" "$(_json_str "$BACKEND")"
        if [ "$paqet_installed" = true ]; then
            printf '"paqet":{"server":%s,"port":%s,"key":%s,"client_socks":%s},' \
                "$(_json_str "$local_ip")" "$(_json_num "$paqet_port")" "$(_json_str "$paqet_key")" "$(_json_str "127.0.0.1:${SOCKS_PORT:-1080}")"
        else
            printf '"paqet":null,'
        fi
        if [ "$gfk_installed" = true ]; then
            printf '"gfk":{"server_ip":%s,"auth_code":%s,"port_mappings":%s,"vio_port":%s,"quic_port":%s,"client_socks":%s},' \
                "$(_json_str "$gfk_ip")" "$(_json_str "$gfk_auth")" "$(_json_str "$gfk_mappings")" \
                "$(_json_num "${GFK_VIO_PORT:-45000}")" "$(_json_num "${GFK_QUIC_PORT:-25000}")" "$(_json_str "127.0.0.1:$(_gfk_client_socks_port)")"
        else
            printf '"gfk":null,'
        fi
        printf '"uri":%s}\n' "$(if [ -n "$uri" ]; then _json_str "$uri"; else printf 'null'; fi)"
        return 0
    fi

    [ "$MENU_MODE" = true ] && clear
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  CLIENT CONNECTION INFO${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""

    if [ "$paqet_installed" = true ]; then
        echo -e "  ${GREEN}${BOLD}━━━ PAQET ━━━${NC}"
        echo ""
        echo -e "  ${YELLOW}╔═══════════════════════════════════════════════════════════╗${NC}"
        echo -e "  ${YELLOW}║${NC}  Server:  ${BOLD}${local_ip}:${paqet_port}${NC}"
        echo -e "  ${YELLOW}║${NC}  Key:     ${BOLD}${paqet_key:-not set}${NC}"
        echo -e "  ${YELLOW}╚═══════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  ${DIM}Client proxy: 127.0.0.1:${SOCKS_PORT:-1080} (SOCKS5)${NC}"
        echo ""
    fi

    if [ "$gfk_installed" = true ]; then
        echo -e "  ${MAGENTA}${BOLD}━━━ GFW-KNOCKER ━━━${NC}"
        echo ""
        echo -e "  ${YELLOW}╔═══════════════════════════════════════════════════════════╗${NC}"
        echo -e "  ${YELLOW}║${NC}  Server IP:  ${BOLD}${gfk_ip}${NC}"
        echo -e "  ${YELLOW}║${NC}  Auth Code:  ${BOLD}${gfk_auth:-not set}${NC}"
        echo -e "  ${YELLOW}║${NC}  Mappings:   ${BOLD}${gfk_mappings}${NC}"
        echo -e "  ${YELLOW}╚═══════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  ${DIM}VIO port: ${GFK_VIO_PORT:-45000} | QUIC port: ${GFK_QUIC_PORT:-25000}${NC}"
        echo -e "  ${DIM}Client proxy: 127.0.0.1:$(_gfk_client_socks_port) (SOCKS5)${NC}"
        echo ""
    fi

    local rc=0
    if [ "$paqet_installed" = false ] && [ "$gfk_installed" = false ]; then
        echo -e "  ${YELLOW}No backends installed yet.${NC}"
        echo ""
        echo "  Run 'sudo paqctl menu' and select 'Settings & Tools'"
        echo "  to install a backend."
        echo ""
        echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
        echo ""
        rc=1
    else
        export_config_string "${export_args[@]}" || rc=$?
    fi

    if [ "$MENU_MODE" = true ]; then
        read -n 1 -s -r -p "  Press any key to return..." < /dev/tty || true
    fi
    return $rc
}

#═══════════════════════════════════════════════════════════════════════
# Interactive Menu
#═══════════════════════════════════════════════════════════════════════

show_menu() {
    MENU_MODE=true
    if ! _has_tty; then
        log_error "The interactive menu needs a terminal. Run 'paqctl help' for scriptable commands."
        return 1
    fi
    # Auto-fix systemd service if in failed state
    if command -v systemctl &>/dev/null && [ -d /run/systemd/system ]; then
        local svc_state=$(systemctl is-active paqctl.service 2>/dev/null)
        if [ "$svc_state" = "failed" ]; then
            systemctl reset-failed paqctl.service 2>/dev/null || true
        fi
    fi

    # Reload settings
    _load_settings

    local paqet_installed=false
    local gfk_installed=false
    local redraw=true

    while true; do
        if [ "$redraw" = true ]; then
            # Re-check what's installed each redraw
            paqet_installed=false
            gfk_installed=false
            [ -f "$INSTALL_DIR/bin/paqet" ] && paqet_installed=true
            if [ "$ROLE" = "server" ]; then
                [ -d "$GFK_DIR" ] && [ -f "$GFK_DIR/quic_server.py" ] && gfk_installed=true
            else
                [ -d "$GFK_DIR" ] && [ -f "$GFK_DIR/quic_client.py" ] && gfk_installed=true
            fi

            clear
            print_header

            # Status line showing both backends
            local boot_badge=""
            if _init_system >/dev/null; then
                if _boot_enabled; then
                    boot_badge="  |  Boot: ${GREEN}enabled${NC}"
                else
                    boot_badge="  |  Boot: ${YELLOW}disabled${NC}"
                fi
            fi
            echo -e "${CYAN}─────────────────────────────────────────────────────────────────${NC}"
            echo -e "  ${BOLD}BACKEND STATUS${NC}  (Role: ${ROLE})${boot_badge}"
            echo -e "${CYAN}─────────────────────────────────────────────────────────────────${NC}"

            # Paqet status
            if [ "$paqet_installed" = true ]; then
                local _paqet_info=""
                if [ "$ROLE" = "server" ]; then
                    _paqet_info="Port: ${LISTEN_PORT:-8443}"
                else
                    _paqet_info="Server: ${REMOTE_SERVER:-N/A}"
                fi
                if is_paqet_running; then
                    echo -e "  Paqet:       ${GREEN}● Running${NC}  |  ${_paqet_info}  |  SOCKS5: 127.0.0.1:${SOCKS_PORT:-1080}"
                else
                    echo -e "  Paqet:       ${RED}○ Stopped${NC}  |  ${_paqet_info}"
                fi
            else
                echo -e "  Paqet:       ${DIM}not installed${NC}"
            fi

            # GFK status
            if [ "$gfk_installed" = true ]; then
                if is_gfk_running; then
                    local _gfk_sv
                    if [ -n "${GFK_SOCKS_VIO_PORT:-}" ]; then
                        _gfk_sv="$GFK_SOCKS_VIO_PORT"
                    else
                        _gfk_sv=$(echo "${GFK_PORT_MAPPINGS:-14000:443}" | cut -d, -f1 | cut -d: -f1)
                    fi
                    echo -e "  GFK:         ${GREEN}● Running${NC}  |  VIO: ${GFK_VIO_PORT:-45000}  |  SOCKS5: 127.0.0.1:${_gfk_sv}"
                else
                    echo -e "  GFK:         ${RED}○ Stopped${NC}  |  VIO: ${GFK_VIO_PORT:-45000}"
                fi
            else
                echo -e "  GFK:         ${DIM}not installed${NC}"
            fi

            echo -e "${CYAN}─────────────────────────────────────────────────────────────────${NC}"

            echo ""
            echo -e "  ${CYAN}MAIN MENU${NC}"
            echo ""
            echo "  1. View status"
            echo "  2. View logs"
            echo "  3. Health check"
            echo "  4. Update"
            echo ""

            # Paqet controls
            if [ "$paqet_installed" = true ]; then
                if is_paqet_running; then
                    echo -e "  p. ${RED}Stop${NC} Paqet"
                else
                    echo -e "  p. ${GREEN}Start${NC} Paqet"
                fi
            fi

            # GFK controls
            if [ "$gfk_installed" = true ]; then
                if is_gfk_running; then
                    echo -e "  g. ${RED}Stop${NC} GFK"
                else
                    echo -e "  g. ${GREEN}Start${NC} GFK"
                fi
            fi

            # Start/Stop all
            if [ "$paqet_installed" = true ] && [ "$gfk_installed" = true ]; then
                echo ""
                if is_paqet_running && is_gfk_running; then
                    echo -e "  a. ${RED}Stop ALL${NC} backends"
                elif ! is_paqet_running && ! is_gfk_running; then
                    echo -e "  a. ${GREEN}Start ALL${NC} backends"
                else
                    echo "  a. Toggle ALL backends"
                fi
            fi

            echo ""
            echo "  r. Quick Restart Service"
            echo "  b. Toggle Auto-start on Boot"
            echo "  8. Settings & Tools"
            echo -e "  ${GREEN}t. Performance Tuning & Supercharging (v1.1.0)${NC}"
            echo -e "  ${YELLOW}c. Connection Info${NC}"
            echo "  i. Info & Help"
            echo -e "  ${RED}u. Uninstall${NC}"
            echo "  0. Exit"
            echo -e "${CYAN}─────────────────────────────────────────────────────────────────${NC}"
            echo ""
            redraw=false
        fi

        echo -n "  Select option: "
        if ! read choice < /dev/tty 2>/dev/null; then
            log_error "Cannot read input. If piped, run: sudo paqctl menu"
            exit 1
        fi

        case "$choice" in
            1) show_status; read -n 1 -s -r -p "  Press any key to return..." < /dev/tty || true; redraw=true ;;
            2) show_logs; redraw=true ;;
            3) health_check; read -n 1 -s -r -p "  Press any key to return..." < /dev/tty || true; redraw=true ;;
            4) update_paqet; read -n 1 -s -r -p "  Press any key to return..." < /dev/tty || true; redraw=true ;;
            p|P)
                if [ "$paqet_installed" = true ]; then
                    if is_paqet_running; then
                        stop_paqet_backend
                    else
                        start_paqet_backend
                    fi
                    read -n 1 -s -r -p "  Press any key to return..." < /dev/tty || true
                else
                    echo -e "  ${YELLOW}Paqet not installed${NC}"
                fi
                redraw=true
                ;;
            g|G)
                if [ "$gfk_installed" = true ]; then
                    if is_gfk_running; then
                        stop_gfk_backend
                    else
                        start_gfk_backend
                    fi
                    read -n 1 -s -r -p "  Press any key to return..." < /dev/tty || true
                else
                    echo -e "  ${YELLOW}GFK not installed${NC}"
                fi
                redraw=true
                ;;
            a|A)
                if [ "$paqet_installed" = true ] && [ "$gfk_installed" = true ]; then
                    if is_paqet_running && is_gfk_running; then
                        # Stop all
                        stop_paqet_backend
                        stop_gfk_backend
                    elif ! is_paqet_running && ! is_gfk_running; then
                        # Start all
                        start_paqet_backend
                        start_gfk_backend
                    else
                        # Mixed state - ask user
                        echo ""
                        echo "  1. Start all backends"
                        echo "  2. Stop all backends"
                        echo -n "  Choice: "
                        read subchoice < /dev/tty || true
                        case "$subchoice" in
                            1)
                                [ "$paqet_installed" = true ] && ! is_paqet_running && start_paqet_backend
                                [ "$gfk_installed" = true ] && ! is_gfk_running && start_gfk_backend
                                ;;
                            2)
                                is_paqet_running && stop_paqet_backend
                                is_gfk_running && stop_gfk_backend
                                ;;
                        esac
                    fi
                    read -n 1 -s -r -p "  Press any key to return..." < /dev/tty || true
                fi
                redraw=true
                ;;
            r|R) restart_paqet; read -n 1 -s -r -p "  Press any key to return..." < /dev/tty || true; redraw=true ;;
            b|B)
                if _boot_enabled; then
                    _set_boot disable || true
                else
                    _set_boot enable || true
                fi
                read -n 1 -s -r -p "  Press any key to return..." < /dev/tty || true; redraw=true ;;
            8) show_settings_menu; redraw=true ;;
            t|T) tune_menu; redraw=true ;;
            c|C) show_connection_info; redraw=true ;;
            i|I) show_info_menu; redraw=true ;;
            u|U) uninstall_paqctl; [ -d "$INSTALL_DIR" ] || exit 0; redraw=true ;;
            0) echo "  Exiting."; exit 0 ;;
            "") ;;
            *) echo -e "  ${RED}Invalid choice: ${NC}${YELLOW}$choice${NC}" ;;
        esac
    done
}
