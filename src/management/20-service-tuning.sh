#═══════════════════════════════════════════════════════════════════════
# Service Control
#═══════════════════════════════════════════════════════════════════════

is_running() {
    # Check which backends are installed
    local paqet_installed=false gfk_installed=false
    [ -f "$INSTALL_DIR/bin/paqet" ] && paqet_installed=true
    if [ "$ROLE" = "server" ]; then
        [ -d "$GFK_DIR" ] && [ -f "$GFK_DIR/quic_server.py" ] && gfk_installed=true
    else
        [ -d "$GFK_DIR" ] && [ -f "$GFK_DIR/quic_client.py" ] && gfk_installed=true
    fi

    # If both backends installed, return true if EITHER is running
    if [ "$paqet_installed" = true ] && [ "$gfk_installed" = true ]; then
        is_paqet_running && return 0
        is_gfk_running && return 0
        return 1
    fi

    # Single backend mode - original logic
    if command -v systemctl &>/dev/null && [ -d /run/systemd/system ]; then
        systemctl is-active paqctl.service &>/dev/null && return 0
    elif [ -f /run/paqctl.pid ]; then
        local _pid
        _pid=$(cat /run/paqctl.pid 2>/dev/null)
        # Validate PID is numeric and process exists
        [[ "$_pid" =~ ^[0-9]+$ ]] && kill -0 "$_pid" 2>/dev/null && return 0
    fi
    # Also check for the process directly with more specific patterns
    if [ "$BACKEND" = "gfw-knocker" ]; then
        # Use full path matching to avoid false positives
        pgrep -f "${GFK_DIR}/mainserver.py" &>/dev/null && return 0
        pgrep -f "${GFK_DIR}/mainclient.py" &>/dev/null && return 0
        pgrep -f "${INSTALL_DIR}/bin/gfk-client.sh" &>/dev/null && return 0
    else
        # Match specific config file path
        pgrep -f "${INSTALL_DIR}/bin/paqet run -c ${INSTALL_DIR}/config.yaml" &>/dev/null && return 0
    fi
    return 1
}

# Check if paqet backend specifically is running
is_paqet_running() {
    pgrep -f "${INSTALL_DIR}/bin/paqet run -c ${INSTALL_DIR}/config.yaml" &>/dev/null && return 0
    return 1
}

# Check if GFK backend specifically is running
is_gfk_running() {
    if [ "$ROLE" = "server" ]; then
        pgrep -f "${GFK_DIR}/mainserver.py" &>/dev/null && return 0
    else
        pgrep -f "${GFK_DIR}/mainclient.py" &>/dev/null && return 0
        pgrep -f "${INSTALL_DIR}/bin/gfk-client.sh" &>/dev/null && return 0
    fi
    return 1
}

#═══════════════════════════════════════════════════════════════════════
# Paqet v1.1.0 Performance Tuning & Supercharging
#═══════════════════════════════════════════════════════════════════════

apply_turbo_mode() {
    log_info "Applying OS Kernel Turbo Mode (BBR + 32MB Buffers)..."
    local sysctl_conf="/etc/sysctl.d/99-paqctl-turbo.conf"
    if [ ! -f "$sysctl_conf" ] && [ -f "/etc/sysctl.conf" ]; then
        sysctl_conf="/etc/sysctl.conf"
    fi
    cat > /tmp/99-paqctl-turbo.conf << 'EOF'
# Paqctl v1.1.0 Turbo Mode - High Performance Network Stack
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.core.optmem_max = 65536
net.ipv4.tcp_rmem = 4096 1048576 33554432
net.ipv4.tcp_wmem = 4096 65536 33554432
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192
net.core.netdev_max_backlog = 16384
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
fs.file-max = 2097152
EOF
    if [ -d "/etc/sysctl.d" ]; then
        mv /tmp/99-paqctl-turbo.conf /etc/sysctl.d/99-paqctl-turbo.conf 2>/dev/null || true
    else
        cat /tmp/99-paqctl-turbo.conf >> /etc/sysctl.conf 2>/dev/null || true
        rm -f /tmp/99-paqctl-turbo.conf
    fi
    sysctl --system &>/dev/null || sysctl -p &>/dev/null || true

    local max_nofile="1048576"
    if [ -f "/proc/sys/fs/nr_open" ]; then
        local sys_nr_open=$(cat /proc/sys/fs/nr_open 2>/dev/null || echo "1048576")
        if [ "$sys_nr_open" -lt 1048576 ] 2>/dev/null; then
            max_nofile="$sys_nr_open"
        fi
    fi

    if [ -f "/etc/systemd/system/paqctl.service" ] && command -v systemctl &>/dev/null && [ -d /run/systemd/system ]; then
        mkdir -p /etc/systemd/system/paqctl.service.d 2>/dev/null || true
        cat > /etc/systemd/system/paqctl.service.d/limits.conf << EOF
[Service]
LimitNOFILE=${max_nofile}
LimitNPROC=51200
EOF
        systemctl daemon-reload 2>/dev/null || true
        systemctl restart paqctl.service 2>/dev/null || true
    else
        mkdir -p /etc/security/limits.d 2>/dev/null || true
        cat > /etc/security/limits.d/99-paqctl.conf << EOF
* soft nofile ${max_nofile}
* hard nofile ${max_nofile}
root soft nofile ${max_nofile}
root hard nofile ${max_nofile}
EOF
        ulimit -n "${max_nofile}" 2>/dev/null || true
        restart_paqet 2>/dev/null || true
    fi

    TURBO_ENABLED="true"
    save_settings 2>/dev/null || true
    log_success "Kernel Turbo Mode enabled! BBR congestion control and 32MB buffers active."
}

remove_turbo_mode() {
    log_info "Removing OS Kernel Turbo Mode..."
    rm -f /etc/sysctl.d/99-paqctl-turbo.conf /etc/security/limits.d/99-paqctl.conf 2>/dev/null || true
    rm -rf /etc/systemd/system/paqctl.service.d 2>/dev/null || true
    if command -v systemctl &>/dev/null && [ -d /run/systemd/system ]; then
        systemctl daemon-reload 2>/dev/null || true
        systemctl restart paqctl.service 2>/dev/null || true
    else
        restart_paqet 2>/dev/null || true
    fi
    TURBO_ENABLED="false"
    save_settings 2>/dev/null || true
    log_success "Kernel Turbo Mode disabled."
}

manage_watchdog() {
    local action="${1:-status}"
    local timer_file="/etc/systemd/system/paqctl-watchdog.timer"
    local service_file="/etc/systemd/system/paqctl-watchdog.service"
    local cron_file="/etc/cron.d/paqctl-watchdog"

    if ! command -v systemctl &>/dev/null || [ ! -d /run/systemd/system ]; then
        case "$action" in
            enable)
                log_info "Enabling Self-Healing Watchdog via cron (non-systemd environment)..."
                mkdir -p /etc/cron.d 2>/dev/null || true
                echo "* * * * * root /usr/local/bin/paqctl watchdog check >/dev/null 2>&1" > "$cron_file"
                chmod 644 "$cron_file" 2>/dev/null || true
                WATCHDOG_ENABLED="true"
                save_settings 2>/dev/null || true
                log_success "Watchdog enabled via cron (* * * * *)! System will self-heal within 60s if service fails."
                ;;
            disable)
                log_info "Disabling Self-Healing Watchdog..."
                rm -f "$cron_file" 2>/dev/null || true
                WATCHDOG_ENABLED="false"
                save_settings 2>/dev/null || true
                log_success "Watchdog disabled."
                ;;
            check)
                if [ -f "$INSTALL_DIR/.stopped" ] || [ -f "/run/paqctl.stopped" ]; then
                    return 0
                fi
                if ! is_running; then
                    start_paqet &>/dev/null || true
                    if [ "$TELEGRAM_ALERTS_ENABLED" = "true" ]; then
                        send_telegram_alert "⚠️ *Paqctl Watchdog Alert*
Service was down on \`${TELEGRAM_SERVER_LABEL:-$(hostname)}\`. Auto-recovery triggered!" &>/dev/null || true
                    fi
                fi
                ;;
            *)
                if [ -f "$cron_file" ] || [ "${WATCHDOG_ENABLED}" = "true" ]; then
                    echo -e "  Watchdog Status: ${GREEN}${BOLD}ACTIVE (Checking every 1m via cron)${NC}"
                else
                    echo -e "  Watchdog Status: ${RED}${BOLD}INACTIVE${NC}"
                fi
                ;;
        esac
        return 0
    fi

    case "$action" in
        enable)
            log_info "Enabling Self-Healing Watchdog (Auto-Recovery)..."
            cat > "$service_file" << EOF
[Unit]
Description=Paqctl Watchdog Health Check
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/paqctl watchdog check
EOF
            cat > "$timer_file" << EOF
[Unit]
Description=Run Paqctl Watchdog every minute

[Timer]
OnBootSec=2min
OnUnitActiveSec=1min
Unit=paqctl-watchdog.service

[Install]
WantedBy=timers.target
EOF
            systemctl daemon-reload 2>/dev/null || true
            systemctl enable paqctl-watchdog.timer &>/dev/null || true
            systemctl start paqctl-watchdog.timer &>/dev/null || true
            WATCHDOG_ENABLED="true"
            save_settings 2>/dev/null || true
            log_success "Watchdog enabled! System will self-heal within 60s if service fails."
            ;;
        disable)
            log_info "Disabling Self-Healing Watchdog..."
            systemctl stop paqctl-watchdog.timer &>/dev/null || true
            systemctl disable paqctl-watchdog.timer &>/dev/null || true
            rm -f "$timer_file" "$service_file" 2>/dev/null || true
            systemctl daemon-reload 2>/dev/null || true
            WATCHDOG_ENABLED="false"
            save_settings 2>/dev/null || true
            log_success "Watchdog disabled."
            ;;
        check)
            if [ -f "$INSTALL_DIR/.stopped" ] || [ -f "/run/paqctl.stopped" ]; then
                return 0
            fi
            if ! is_running; then
                start_paqet &>/dev/null || true
                if [ "$TELEGRAM_ALERTS_ENABLED" = "true" ]; then
                    send_telegram_alert "⚠️ *Paqctl Watchdog Alert*
Service was down on \`${TELEGRAM_SERVER_LABEL:-$(hostname)}\`. Auto-recovery triggered!" &>/dev/null || true
                fi
            fi
            ;;
        *)
            if [ -f "$timer_file" ] && systemctl is-active paqctl-watchdog.timer &>/dev/null; then
                echo -e "  Watchdog Status: ${GREEN}${BOLD}ACTIVE (Checking every 1m)${NC}"
            else
                echo -e "  Watchdog Status: ${RED}${BOLD}INACTIVE${NC}"
            fi
            ;;
    esac
}

detect_optimal_mtu() {
    echo ""
    log_info "Running Smart MTU Auto-Discovery..."
    local target="8.8.8.8"
    if [ "$ROLE" = "client" ] && [ -n "$REMOTE_SERVER" ]; then
        local _srv="${REMOTE_SERVER%:*}"
        if [ -n "$_srv" ] && [ "$_srv" != "0.0.0.0" ] && [ "$_srv" != "127.0.0.1" ] && [ "$_srv" != "localhost" ]; then
            target="$_srv"
        fi
    fi
    echo -e "  ${DIM}Testing path MTU to ${target}...${NC}"

    local ping_flag=""
    if ping -c 1 -W 1 -M do -s 64 127.0.0.1 &>/dev/null; then
        ping_flag="-M do"
    elif ping -c 1 -W 1 -D -s 64 127.0.0.1 &>/dev/null; then
        ping_flag="-D"
    fi

    local mtu=1500
    local found=0
    if ping -c 1 -W 1 -s 64 "$target" &>/dev/null || ping -c 1 -W 1 127.0.0.1 &>/dev/null; then
        while [ $mtu -ge 1200 ]; do
            if ping -c 1 -W 1 ${ping_flag} -s $((mtu - 28)) "$target" &>/dev/null; then
                found=$mtu
                break
            fi
            mtu=$((mtu - 20))
        done
    fi

    echo ""
    if [ "$found" -eq 0 ]; then
        log_warn "ICMP ping probes restricted or blocked by network/container firewall. Defaulting to safe MTU: 1350"
        found=1350
    else
        log_success "Physical path MTU detected: ${found}"
        if [ "$found" -gt 150 ]; then
            found=$((found - 150))
        else
            found=1350
        fi
        log_info "Applying Safe KCP/Tunnel MTU: ${found} (reserved 150 bytes for KCP header & AEAD crypto overhead)"
    fi
    echo -e "  ${DIM}(Prevents 'Message too large' / EMSGSIZE socket errors under high throughput)${NC}"
    KCP_MTU="$found"
    save_settings 2>/dev/null || true
    return 0
}

select_performance_profile() {
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
    local _profile_mtu=1350
    case "$p_choice" in
        2)
            KCP_PROFILE="highloss"; KCP_CONN=4; _profile_mtu=1300; KCP_SNDWND=1024; KCP_RCVWND=1024
            KCP_NODELAY=0; KCP_INTERVAL=20; KCP_RESEND=2; KCP_NOCONGESTION=0; KCP_SOCKBUF=4194304; KCP_SMUXBUF=4194304 ;;
        3)
            KCP_PROFILE="cdntunnel"; KCP_CONN=8; _profile_mtu=1400; KCP_SNDWND=2048; KCP_RCVWND=2048
            KCP_NODELAY=0; KCP_INTERVAL=20; KCP_RESEND=2; KCP_NOCONGESTION=0; KCP_SOCKBUF=8388608; KCP_SMUXBUF=8388608 ;;
        4)
            KCP_PROFILE="gaming"; KCP_CONN=2; _profile_mtu=1200; KCP_SNDWND=512; KCP_RCVWND=512
            KCP_NODELAY=1; KCP_INTERVAL=10; KCP_RESEND=2; KCP_NOCONGESTION=1; KCP_SOCKBUF=4194304; KCP_SMUXBUF=4194304 ;;
        *)
            KCP_PROFILE="standard"; KCP_CONN=2; _profile_mtu=1350; KCP_SNDWND=1024; KCP_RCVWND=1024
            KCP_NODELAY=0; KCP_INTERVAL=20; KCP_RESEND=2; KCP_NOCONGESTION=0; KCP_SOCKBUF=4194304; KCP_SMUXBUF=4194304 ;;
    esac
    local _curr_mtu=$(grep -E "^KCP_MTU=" "$INSTALL_DIR/settings.conf" 2>/dev/null | cut -d'=' -f2 | tr -d '"' || echo "")
    if [ -n "$_curr_mtu" ] && [ "$_curr_mtu" -gt 0 ] 2>/dev/null; then
        if [ "$_profile_mtu" -lt "$_curr_mtu" ] 2>/dev/null; then
            KCP_MTU="$_profile_mtu"
        else
            KCP_MTU="$_curr_mtu"
        fi
    else
        KCP_MTU="$_profile_mtu"
    fi
    save_settings 2>/dev/null || true
}

tune_menu() {
    while true; do
        echo ""
        echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
        echo -e "${BOLD}  PERFORMANCE & SUPERCHARGING MENU (v1.1.0)${NC}"
        echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
        echo ""
        echo -e "  Current Profile : ${GREEN}${BOLD}${KCP_PROFILE:-standard}${NC} (conn: ${KCP_CONN:-2}, mtu: ${KCP_MTU:-1350})"
        echo -e "  Kernel Turbo Mode: $( [ "${TURBO_ENABLED}" = "true" ] && echo -e "${GREEN}${BOLD}ENABLED (BBR + 32MB)${NC}" || echo -e "${RED}DISABLED${NC}" )"
        echo -e "  Watchdog Service : $( [ "${WATCHDOG_ENABLED}" = "true" ] && echo -e "${GREEN}${BOLD}ENABLED (1m Auto-Heal)${NC}" || echo -e "${RED}DISABLED${NC}" )"
        echo ""
        echo "  1. Select Performance Profile (Standard/High-Loss/CDN/Gaming)"
        echo "  2. Run Smart MTU Auto-Discovery"
        echo "  3. Toggle OS Kernel Turbo Mode (BBR + 32MB Buffers)"
        echo "  4. Toggle Self-Healing Watchdog Service"
        echo "  5. Apply & Restart Service with Current Tuning"
        echo "  b. Back to Main Menu"
        echo ""
        read -p "  Choice [1-5/b]: " t_choice < /dev/tty || true
        case "$t_choice" in
            1)
                select_performance_profile
                if [ -d "$INSTALL_DIR" ]; then generate_paqet_yaml "$INSTALL_DIR/config.yaml" 2>/dev/null || true; fi
                if [ -d "$GFK_DIR" ] && [ "$BACKEND" = "gfw-knocker" ]; then generate_gfk_config 2>/dev/null || true; fi
                if systemctl is-active --quiet paqet 2>/dev/null; then systemctl restart paqet 2>/dev/null || true; fi
                if systemctl is-active --quiet paqet-gfk 2>/dev/null; then systemctl restart paqet-gfk 2>/dev/null || true; fi
                log_success "Profile & MTU applied and service restarted!"
                ;;
            2)
                detect_optimal_mtu
                if [ -d "$INSTALL_DIR" ]; then generate_paqet_yaml "$INSTALL_DIR/config.yaml" 2>/dev/null || true; fi
                if [ -d "$GFK_DIR" ] && [ "$BACKEND" = "gfw-knocker" ]; then generate_gfk_config 2>/dev/null || true; fi
                if systemctl is-active --quiet paqet 2>/dev/null; then systemctl restart paqet 2>/dev/null || true; fi
                if systemctl is-active --quiet paqet-gfk 2>/dev/null; then systemctl restart paqet-gfk 2>/dev/null || true; fi
                log_success "Optimal MTU applied and service restarted!"
                ;;
            3)
                if [ "${TURBO_ENABLED}" = "true" ]; then
                    remove_turbo_mode
                else
                    apply_turbo_mode
                fi
                ;;
            4)
                if [ "${WATCHDOG_ENABLED}" = "true" ]; then
                    manage_watchdog disable
                else
                    manage_watchdog enable
                fi
                ;;
            5)
                generate_paqet_yaml "$INSTALL_DIR/config.yaml"
                restart_paqet
                log_success "Service restarted with updated tuning!"
                ;;
            b|B) break ;;
            *) echo -e "  ${RED}Invalid choice${NC}" ;;
        esac
    done
}

# Start paqet backend only
start_paqet_backend() {
    rm -f "$INSTALL_DIR/.stopped" /run/paqctl.stopped 2>/dev/null || true
    if is_paqet_running; then
        log_warn "paqet is already running"
        return 0
    fi

    if [ ! -f "$INSTALL_DIR/bin/paqet" ]; then
        log_error "paqet binary not installed. Use 'Install additional backend' first."
        return 1
    fi

    # Generate config.yaml if missing - prompt for values
    if [ ! -f "$INSTALL_DIR/config.yaml" ]; then
        echo ""
        echo -e "${YELLOW}config.yaml not found. Let's configure paqet:${NC}"
        echo ""

        detect_network
        local _det_iface="$DETECTED_IFACE"
        local _det_ip="$DETECTED_IP"
        local _det_mac="$DETECTED_GW_MAC"

        echo -e "${BOLD}Network Interface${NC} [${_det_iface:-eth0}]:"
        read -p "  Interface: " input < /dev/tty || true
        local _iface="${input:-${_det_iface:-eth0}}"

        echo -e "${BOLD}Local IP${NC} [${_det_ip:-}]:"
        read -p "  IP: " input < /dev/tty || true
        local _local_ip="${input:-$_det_ip}"

        echo -e "${BOLD}Gateway MAC${NC} [${_det_mac:-}]:"
        read -p "  MAC: " input < /dev/tty || true
        local _gw_mac="${input:-$_det_mac}"

        local _key
        _key=$("$INSTALL_DIR/bin/paqet" secret 2>/dev/null || true)
        if [ -z "$_key" ]; then
            _key=$(openssl rand -base64 32 2>/dev/null | tr -d '=+/' | head -c 32 || true)
        fi

        if [ "$ROLE" = "server" ]; then
            echo -e "${BOLD}Listen Port${NC} [8443]:"
            read -p "  Port: " input < /dev/tty || true
            local _port="${input:-8443}"

            echo ""
            echo -e "${GREEN}${BOLD}  Generated Key: ${_key}${NC}"
            echo -e "${BOLD}Encryption Key${NC} (Enter to use generated):"
            read -p "  Key: " input < /dev/tty || true
            [ -n "$input" ] && _key="$input"

            LISTEN_PORT="$_port"
            ENCRYPTION_KEY="$_key"

            cat > "$INSTALL_DIR/config.yaml" << EOFCFG
role: "server"
log:
  level: "info"
listen:
  addr: ":${_port}"
network:
  interface: "${_iface}"
  ipv4:
    addr: "${_local_ip}:${_port}"
    router_mac: "${_gw_mac}"
transport:
  protocol: "kcp"
  kcp:
    mode: "fast"
    key: "${_key}"
EOFCFG
        else
            echo -e "${BOLD}Remote Server${NC} (IP:PORT):"
            read -p "  Server: " input < /dev/tty || true
            local _server="${input:-${REMOTE_SERVER:-}}"

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

        INTERFACE="$_iface" LOCAL_IP="$_local_ip" GATEWAY_MAC="$_gw_mac" generate_paqet_yaml "$INSTALL_DIR/config.yaml"

        if [ ! -f "$INSTALL_DIR/config.yaml" ]; then
            log_error "Failed to write config.yaml"
            return 1
        fi
        chmod 600 "$INSTALL_DIR/config.yaml" 2>/dev/null
        INTERFACE="$_iface"
        LOCAL_IP="$_local_ip"
        GATEWAY_MAC="$_gw_mac"
        save_settings 2>/dev/null || true
        log_success "Configuration saved"
        echo ""
    fi

    log_info "Starting paqet backend..."

    # Apply paqet firewall rules
    local _saved_backend="$BACKEND"
    BACKEND="paqet"
    _apply_firewall
    BACKEND="$_saved_backend"

    (umask 077; touch /var/log/paqet-backend.log)
    nohup "$INSTALL_DIR/bin/paqet" run -c "$INSTALL_DIR/config.yaml" > /var/log/paqet-backend.log 2>&1 &
    echo $! > /run/paqet-backend.pid

    sleep 2
    if is_paqet_running; then
        log_success "paqet backend started"
    else
        log_error "paqet failed to start. Check: tail /var/log/paqet-backend.log"
        return 1
    fi
}

# Stop paqet backend only
stop_paqet_backend() {
    touch "$INSTALL_DIR/.stopped" /run/paqctl.stopped 2>/dev/null || true
    if ! is_paqet_running; then
        log_warn "paqet is not running"
        return 0
    fi

    log_info "Stopping paqet backend..."

    if [ -f /run/paqet-backend.pid ]; then
        local _pid
        _pid=$(cat /run/paqet-backend.pid 2>/dev/null)
        if [ -n "$_pid" ] && [[ "$_pid" =~ ^[0-9]+$ ]]; then
            kill "$_pid" 2>/dev/null
            sleep 1
            kill -0 "$_pid" 2>/dev/null && kill -9 "$_pid" 2>/dev/null
        fi
        rm -f /run/paqet-backend.pid
    fi

    pkill -f "${INSTALL_DIR}/bin/paqet run -c" 2>/dev/null || true

    # Remove paqet firewall rules
    local _saved_backend="$BACKEND"
    BACKEND="paqet"
    _remove_firewall
    BACKEND="$_saved_backend"

    sleep 1
    if ! is_paqet_running; then
        log_success "paqet backend stopped"
    else
        pkill -9 -f "${INSTALL_DIR}/bin/paqet run -c" 2>/dev/null || true
        log_success "paqet backend stopped (forced)"
    fi
}

# Start GFK backend only
start_gfk_backend() {
    rm -f "$INSTALL_DIR/.stopped" /run/paqctl.stopped 2>/dev/null || true
    if is_gfk_running; then
        log_warn "gfw-knocker is already running"
        return 0
    fi

    if [ ! -d "$GFK_DIR" ] || [ ! -f "$GFK_DIR/quic_server.py" ]; then
        log_error "gfw-knocker not installed. Use 'Install additional backend' first."
        return 1
    fi

    if [ ! -f "$GFK_DIR/parameters.py" ]; then
        generate_gfk_config 2>/dev/null || true
    fi

    log_info "Starting gfw-knocker backend..."

    # Apply GFK firewall rules
    local _saved_backend="$BACKEND"
    BACKEND="gfw-knocker"
    _apply_firewall
    BACKEND="$_saved_backend"

    (umask 077; touch /var/log/gfk-backend.log)

    if [ "$ROLE" = "server" ]; then
        # Start Xray if not running
        if command -v xray &>/dev/null || [ -x /usr/local/bin/xray ] || [ -x /usr/local/x-ui/bin/xray-linux-amd64 ]; then
            if ! pgrep -f "xray run" &>/dev/null; then
                systemctl start xray 2>/dev/null || xray run -c /usr/local/etc/xray/config.json &>/dev/null &
                sleep 2
            fi
        fi
        # Run from GFK_DIR so relative script paths work
        pushd "$GFK_DIR" >/dev/null
        nohup "$INSTALL_DIR/venv/bin/python" "$GFK_DIR/mainserver.py" > /var/log/gfk-backend.log 2>&1 &
        popd >/dev/null
    else
        if [ -x "$INSTALL_DIR/bin/gfk-client.sh" ]; then
            nohup "$INSTALL_DIR/bin/gfk-client.sh" > /var/log/gfk-backend.log 2>&1 &
        else
            # Run from GFK_DIR so relative script paths work
            pushd "$GFK_DIR" >/dev/null
            nohup "$INSTALL_DIR/venv/bin/python" "$GFK_DIR/mainclient.py" > /var/log/gfk-backend.log 2>&1 &
            popd >/dev/null
        fi
    fi
    echo $! > /run/gfk-backend.pid

    sleep 2
    if is_gfk_running; then
        log_success "gfw-knocker backend started"
    else
        log_error "gfw-knocker failed to start. Check: tail /var/log/gfk-backend.log"
        return 1
    fi
}

# Stop GFK backend only
stop_gfk_backend() {
    touch "$INSTALL_DIR/.stopped" /run/paqctl.stopped 2>/dev/null || true
    if ! is_gfk_running; then
        log_warn "gfw-knocker is not running"
        return 0
    fi

    log_info "Stopping gfw-knocker backend..."

    if [ -f /run/gfk-backend.pid ]; then
        local _pid
        _pid=$(cat /run/gfk-backend.pid 2>/dev/null)
        if [ -n "$_pid" ] && [[ "$_pid" =~ ^[0-9]+$ ]]; then
            kill "$_pid" 2>/dev/null
            sleep 1
            kill -0 "$_pid" 2>/dev/null && kill -9 "$_pid" 2>/dev/null
        fi
        rm -f /run/gfk-backend.pid
    fi

    pkill -f "${GFK_DIR}/mainserver.py" 2>/dev/null || true
    pkill -f "${GFK_DIR}/mainclient.py" 2>/dev/null || true
    pkill -f "${INSTALL_DIR}/bin/gfk-client.sh" 2>/dev/null || true
    pkill -f "${INSTALL_DIR}/bin/microsocks" 2>/dev/null || true

    # Remove GFK firewall rules
    local _saved_backend="$BACKEND"
    BACKEND="gfw-knocker"
    _remove_firewall
    BACKEND="$_saved_backend"

    sleep 1
    if ! is_gfk_running; then
        log_success "gfw-knocker backend stopped"
    else
        pkill -9 -f "${GFK_DIR}/mainserver.py" 2>/dev/null || true
        pkill -9 -f "${GFK_DIR}/mainclient.py" 2>/dev/null || true
        pkill -9 -f "${INSTALL_DIR}/bin/gfk-client.sh" 2>/dev/null || true
        log_success "gfw-knocker backend stopped (forced)"
    fi
}

start_paqet() {
    rm -f "$INSTALL_DIR/.stopped" /run/paqctl.stopped 2>/dev/null || true
    # Check which backends are installed
    local paqet_installed=false gfk_installed=false
    [ -f "$INSTALL_DIR/bin/paqet" ] && paqet_installed=true
    if [ "$ROLE" = "server" ]; then
        [ -d "$GFK_DIR" ] && [ -f "$GFK_DIR/quic_server.py" ] && gfk_installed=true
    else
        [ -d "$GFK_DIR" ] && [ -f "$GFK_DIR/quic_client.py" ] && gfk_installed=true
    fi

    # If both backends installed, start both
    if [ "$paqet_installed" = true ] && [ "$gfk_installed" = true ]; then
        local started_something=false
        if ! is_paqet_running; then
            start_paqet_backend && started_something=true
        else
            log_warn "paqet is already running"
        fi
        if ! is_gfk_running; then
            start_gfk_backend && started_something=true
        else
            log_warn "gfw-knocker is already running"
        fi
        [ "$started_something" = true ] && return 0
        return 0
    fi

    # Single backend mode - original logic
    if is_running; then
        log_warn "${BACKEND} is already running"
        return 0
    fi

    log_info "Starting paqet..."
    local _direct_start=false

    if command -v systemctl &>/dev/null && [ -d /run/systemd/system ]; then
        systemctl start paqctl.service 2>/dev/null
    elif command -v rc-service &>/dev/null; then
        rc-service paqctl start 2>/dev/null
    elif [ -x /etc/init.d/paqctl ]; then
        /etc/init.d/paqctl start 2>/dev/null
    else
        # Direct start - track for cleanup on failure
        _direct_start=true
        _apply_firewall
        (umask 077; touch /var/log/paqctl.log)
        if [ "$BACKEND" = "gfw-knocker" ]; then
            if [ "$ROLE" = "client" ] && [ -x "$INSTALL_DIR/bin/gfk-client.sh" ]; then
                nohup "$INSTALL_DIR/bin/gfk-client.sh" > /var/log/paqctl.log 2>&1 &
            else
                nohup "$INSTALL_DIR/venv/bin/python" "$GFK_DIR/mainserver.py" > /var/log/paqctl.log 2>&1 &
            fi
        else
            nohup "$INSTALL_DIR/bin/paqet" run -c "$INSTALL_DIR/config.yaml" > /var/log/paqctl.log 2>&1 &
        fi
        echo $! > /run/paqctl.pid
    fi

    sleep 2
    if is_running; then
        log_success "${BACKEND} started successfully"
    else
        log_error "${BACKEND} failed to start. Check logs: sudo paqctl logs"
        # Clean up firewall rules on failure (only for direct start)
        if [ "$_direct_start" = true ]; then
            _remove_firewall
        fi
        return 1
    fi
}

stop_paqet() {
    touch "$INSTALL_DIR/.stopped" /run/paqctl.stopped 2>/dev/null || true
    # Check which backends are installed
    local paqet_installed=false gfk_installed=false
    [ -f "$INSTALL_DIR/bin/paqet" ] && paqet_installed=true
    if [ "$ROLE" = "server" ]; then
        [ -d "$GFK_DIR" ] && [ -f "$GFK_DIR/quic_server.py" ] && gfk_installed=true
    else
        [ -d "$GFK_DIR" ] && [ -f "$GFK_DIR/quic_client.py" ] && gfk_installed=true
    fi

    # If both backends installed, stop both
    if [ "$paqet_installed" = true ] && [ "$gfk_installed" = true ]; then
        local stopped_something=false
        if is_paqet_running; then
            stop_paqet_backend && stopped_something=true
        fi
        if is_gfk_running; then
            stop_gfk_backend && stopped_something=true
        fi
        if [ "$stopped_something" = false ]; then
            log_warn "No backends are running"
        fi
        return 0
    fi

    # Single backend mode - original logic
    if ! is_running; then
        log_warn "paqet is not running"
        return 0
    fi

    log_info "Stopping paqet..."

    if command -v systemctl &>/dev/null && [ -d /run/systemd/system ]; then
        systemctl stop paqctl.service 2>/dev/null
    elif command -v rc-service &>/dev/null; then
        rc-service paqctl stop 2>/dev/null
    elif [ -x /etc/init.d/paqctl ]; then
        /etc/init.d/paqctl stop 2>/dev/null
    else
        if [ -f /run/paqctl.pid ]; then
            local _pid
            _pid=$(cat /run/paqctl.pid 2>/dev/null)
            if [ -n "$_pid" ]; then
                kill "$_pid" 2>/dev/null
                local _count=0
                while kill -0 "$_pid" 2>/dev/null && [ $_count -lt 10 ]; do
                    sleep 1
                    _count=$((_count + 1))
                done
                kill -0 "$_pid" 2>/dev/null && kill -9 "$_pid" 2>/dev/null
            fi
            rm -f /run/paqctl.pid
        fi
        # Use specific paths to avoid killing unrelated processes
        if [ "$BACKEND" = "gfw-knocker" ]; then
            pkill -f "${GFK_DIR}/mainserver.py" 2>/dev/null || true
            pkill -f "${GFK_DIR}/mainclient.py" 2>/dev/null || true
            pkill -f "${INSTALL_DIR}/bin/gfk-client.sh" 2>/dev/null || true
            pkill -f "${INSTALL_DIR}/bin/microsocks" 2>/dev/null || true
        else
            pkill -f "${INSTALL_DIR}/bin/paqet run -c" 2>/dev/null || true
        fi
        _remove_firewall
    fi

    sleep 1
    if ! is_running; then
        log_success "${BACKEND} stopped"
    else
        log_warn "${BACKEND} may still be running, force killing..."
        if [ "$BACKEND" = "gfw-knocker" ]; then
            pkill -9 -f "${GFK_DIR}/mainserver.py" 2>/dev/null || true
            pkill -9 -f "${GFK_DIR}/mainclient.py" 2>/dev/null || true
            pkill -9 -f "${INSTALL_DIR}/bin/gfk-client.sh" 2>/dev/null || true
            pkill -9 -f "${INSTALL_DIR}/bin/microsocks" 2>/dev/null || true
        else
            pkill -9 -f "${INSTALL_DIR}/bin/paqet run -c" 2>/dev/null || true
        fi
        sleep 1
        log_success "${BACKEND} stopped"
    fi
}

restart_paqet() {
    stop_paqet
    sleep 1
    start_paqet
}
