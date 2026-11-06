#═══════════════════════════════════════════════════════════════════════
# Status & Info
#═══════════════════════════════════════════════════════════════════════

# Seconds since paqctl.service became active (systemd only)
_service_uptime_seconds() {
    command -v systemctl &>/dev/null && [ -d /run/systemd/system ] || return 1
    local started ts
    started=$(systemctl show paqctl.service --property=ActiveEnterTimestamp 2>/dev/null | cut -d= -f2)
    [ -n "$started" ] || return 1
    ts=$(date -d "$started" +%s 2>/dev/null) || return 1
    [ "$ts" -gt 0 ] 2>/dev/null || return 1
    echo $(( $(date +%s) - ts ))
}

# Are the server-side firewall rules for the active backend in place?
_firewall_rules_ok() {
    command -v iptables &>/dev/null || return 1
    if [ "$BACKEND" = "gfw-knocker" ]; then
        local _vp="${GFK_VIO_PORT:-45000}"
        { iptables -C INPUT -p tcp --dport "$_vp" -m comment --comment "paqctl" -j DROP 2>/dev/null || \
          iptables -C INPUT -p tcp --dport "$_vp" -j DROP 2>/dev/null; } && \
        { iptables -C OUTPUT -p tcp --sport "$_vp" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP 2>/dev/null || \
          iptables -C OUTPUT -p tcp --sport "$_vp" --tcp-flags RST RST -j DROP 2>/dev/null; }
    else
        iptables -t raw -C PREROUTING -p tcp --dport "${LISTEN_PORT:-8443}" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null && \
        iptables -t mangle -C OUTPUT -p tcp --sport "${LISTEN_PORT:-8443}" -m comment --comment "paqctl" --tcp-flags RST RST -j DROP 2>/dev/null
    fi
}

_status_json() {
    local running=false p_inst=false g_inst=false p_run=false g_run=false
    is_running && running=true
    _paqet_installed && p_inst=true
    _gfk_installed && g_inst=true
    is_paqet_running && p_run=true
    is_gfk_running && g_run=true
    local pid="" uptime="" fw="null" boot="null"
    if [ "$BACKEND" = "gfw-knocker" ]; then
        pid=$(pgrep -f "mainserver.py|mainclient.py" 2>/dev/null | head -1)
    else
        pid=$(pgrep -f "paqet run -c" 2>/dev/null | head -1)
    fi
    uptime=$(_service_uptime_seconds 2>/dev/null || true)
    if [ "$ROLE" = "server" ]; then
        if _firewall_rules_ok; then fw=true; else fw=false; fi
    fi
    if _boot_enabled; then boot=true; else boot=false; fi
    printf '{'
    printf '"paqctl_version":%s,' "$(_json_str "$VERSION")"
    printf '"backend":%s,"role":%s,' "$(_json_str "$BACKEND")" "$(_json_str "$ROLE")"
    printf '"running":%s,"pid":%s,"uptime_seconds":%s,' "$(_json_bool "$running")" "$(_json_num "$pid")" "$(_json_num "$uptime")"
    printf '"boot_enabled":%s,"firewall_ok":%s,' "$boot" "$fw"
    printf '"paqet":{"installed":%s,"running":%s,"version":%s},' "$(_json_bool "$p_inst")" "$(_json_bool "$p_run")" "$(_json_str "${PAQET_VERSION:-unknown}")"
    printf '"gfk":{"installed":%s,"running":%s},' "$(_json_bool "$g_inst")" "$(_json_bool "$g_run")"
    if [ "$BACKEND" = "gfw-knocker" ]; then
        printf '"server_ip":%s,"vio_port":%s,"quic_port":%s,"port_mappings":%s,' \
            "$(_json_str "${GFK_SERVER_IP:-}")" "$(_json_num "${GFK_VIO_PORT:-}")" "$(_json_num "${GFK_QUIC_PORT:-}")" "$(_json_str "${GFK_PORT_MAPPINGS:-}")"
        [ "$ROLE" = "client" ] && printf '"socks_port":%s,' "$(_json_num "$(_gfk_client_socks_port)")"
    else
        printf '"interface":%s,"local_ip":%s,' "$(_json_str "${INTERFACE:-}")" "$(_json_str "${LOCAL_IP:-}")"
        if [ "$ROLE" = "server" ]; then
            printf '"listen_port":%s,' "$(_json_num "${LISTEN_PORT:-}")"
        else
            printf '"remote_server":%s,"socks_port":%s,"routing_mode":%s,' "$(_json_str "${REMOTE_SERVER:-}")" "$(_json_num "${SOCKS_PORT:-}")" "$(_json_str "${ROUTING_MODE:-socks5}")"
        fi
        printf '"kcp_profile":%s,"kcp_mtu":%s,' "$(_json_str "${KCP_PROFILE:-standard}")" "$(_json_num "${KCP_MTU:-1350}")"
    fi
    printf '"watchdog_enabled":%s,"turbo_enabled":%s,"telegram_enabled":%s' \
        "$(_json_bool "${WATCHDOG_ENABLED:-false}")" "$(_json_bool "${TURBO_ENABLED:-false}")" "$(_json_bool "${TELEGRAM_ENABLED:-false}")"
    printf '}\n'
}

show_status() {
    if [ "$JSON_OUTPUT" = true ]; then
        _status_json
        return 0
    fi
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  PAQCTL STATUS (${BACKEND})${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""

    # Running status
    if is_running; then
        echo -e "  Status:     ${GREEN}● Running${NC}"
        # Uptime
        if command -v systemctl &>/dev/null && [ -d /run/systemd/system ]; then
            local started
            started=$(systemctl show paqctl.service --property=ActiveEnterTimestamp 2>/dev/null | cut -d= -f2)
            if [ -n "$started" ]; then
                local started_ts
                started_ts=$(date -d "$started" +%s 2>/dev/null || echo 0)
                if [ "$started_ts" -gt 0 ] 2>/dev/null; then
                    local now=$(date +%s)
                    local up=$((now - started_ts))
                    local days=$((up / 86400))
                    local hours=$(( (up % 86400) / 3600 ))
                    local mins=$(( (up % 3600) / 60 ))
                    if [ "$days" -gt 0 ]; then
                        echo -e "  Uptime:     ${days}d ${hours}h ${mins}m"
                    else
                        echo -e "  Uptime:     ${hours}h ${mins}m"
                    fi
                fi
            fi
        fi
        # PID
        local pid
        if [ "$BACKEND" = "gfw-knocker" ]; then
            pid=$(pgrep -f "mainserver.py|mainclient.py" 2>/dev/null | head -1)
        else
            pid=$(pgrep -f "paqet run -c" 2>/dev/null | head -1)
        fi
        [ -n "$pid" ] && echo -e "  PID:        $pid"

        # CPU/RAM of process
        if [ -n "$pid" ]; then
            local cpu_mem
            cpu_mem=$(ps -p "$pid" -o %cpu=,%mem= 2>/dev/null | head -1)
            if [ -n "$cpu_mem" ]; then
                local cpu=$(echo "$cpu_mem" | awk '{print $1}')
                local mem=$(echo "$cpu_mem" | awk '{print $2}')
                echo -e "  CPU:        ${cpu}%"
                echo -e "  Memory:     ${mem}%"
            fi
        fi
    else
        echo -e "  Status:     ${RED}● Stopped${NC}"
    fi

    echo ""
    echo -e "  ${DIM}── Configuration ──${NC}"
    echo -e "  Backend:    ${BOLD}${BACKEND}${NC}"
    echo -e "  Role:       ${BOLD}${ROLE}${NC}"
    echo -e "  Version:    ${PAQET_VERSION}"

    if [ "$BACKEND" = "gfw-knocker" ]; then
        echo -e "  Server IP:  ${GFK_SERVER_IP}"
        echo -e "  VIO port:   ${GFK_VIO_PORT}"
        echo -e "  QUIC port:  ${GFK_QUIC_PORT}"
        if [ "$ROLE" = "server" ]; then
            if [ "${XRAY_PANEL_DETECTED:-false}" = "true" ] && [ -n "${GFK_SOCKS_VIO_PORT:-}" ]; then
                local _md=""
                IFS=',' read -ra _pairs <<< "${GFK_PORT_MAPPINGS}"
                for _p in "${_pairs[@]}"; do
                    if [ "${_p%%:*}" = "${GFK_SOCKS_VIO_PORT}" ]; then
                        _md="${_md:+${_md}, }${_p} (SOCKS5)"
                    else
                        _md="${_md:+${_md}, }${_p} (panel)"
                    fi
                done
                echo -e "  Mappings:   ${_md}"
                echo -e "  SOCKS5:     ${GREEN}127.0.0.1:${GFK_SOCKS_PORT}${NC} (server-side)"
                echo -e "  Client use: ${GREEN}127.0.0.1:${GFK_SOCKS_VIO_PORT}${NC} (set as proxy on client)"
            elif [ "${XRAY_PANEL_DETECTED:-false}" = "true" ]; then
                echo -e "  Mappings:   ${GFK_PORT_MAPPINGS}"
                echo -e "  SOCKS5:     ${YELLOW}not configured${NC}"
            else
                echo -e "  Mappings:   ${GFK_PORT_MAPPINGS}"
                local _srv_port _cli_port
                _srv_port=$(echo "${GFK_PORT_MAPPINGS:-14000:443}" | cut -d, -f1 | cut -d: -f2)
                _cli_port=$(echo "${GFK_PORT_MAPPINGS:-14000:443}" | cut -d, -f1 | cut -d: -f1)
                echo -e "  SOCKS5:     ${GREEN}127.0.0.1:${_srv_port}${NC} (server-side)"
                echo -e "  Client use: ${GREEN}127.0.0.1:${_cli_port}${NC} (set as proxy on client)"
            fi
            echo -e "  Auth code:  ${GFK_AUTH_CODE:0:8}..."
            local _vio_port="${GFK_VIO_PORT:-45000}"
            local _input_ok=false _rst_ok=false
            if iptables -C INPUT -p tcp --dport "$_vio_port" -m comment --comment "paqctl" -j DROP 2>/dev/null || \
               iptables -C INPUT -p tcp --dport "$_vio_port" -j DROP 2>/dev/null; then
                _input_ok=true
            fi
            if iptables -C OUTPUT -p tcp --sport "$_vio_port" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP 2>/dev/null || \
               iptables -C OUTPUT -p tcp --sport "$_vio_port" --tcp-flags RST RST -j DROP 2>/dev/null; then
                _rst_ok=true
            fi
            if [ "$_input_ok" = true ] && [ "$_rst_ok" = true ]; then
                echo -e "  Firewall:   ${GREEN}VIO port blocked${NC}"
            elif [ "$_input_ok" = true ]; then
                echo -e "  Firewall:   ${YELLOW}Partial (RST DROP missing)${NC}"
            else
                echo -e "  Firewall:   ${RED}VIO port NOT blocked${NC}"
            fi
        else
            echo -e "  Mappings:   ${GFK_PORT_MAPPINGS}"
            local _fv
            if [ -n "${GFK_SOCKS_VIO_PORT:-}" ]; then
                _fv="$GFK_SOCKS_VIO_PORT"
            else
                _fv=$(echo "${GFK_PORT_MAPPINGS:-14000:443}" | cut -d, -f1 | cut -d: -f1)
            fi
            echo -e "  Proxy:      ${GREEN}SOCKS5 127.0.0.1:${_fv}${NC} (set as browser proxy)"
        fi
    else
        echo -e "  Interface:  ${INTERFACE}"
        echo -e "  Local IP:   ${LOCAL_IP}"
        if [ "$ROLE" = "server" ]; then
            echo -e "  Port:       ${LISTEN_PORT}"
            echo -e "  Key:        ${ENCRYPTION_KEY:0:8}..."
            if iptables -t raw -C PREROUTING -p tcp --dport "$LISTEN_PORT" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null; then
                echo -e "  Firewall:   ${GREEN}Rules active${NC}"
            else
                echo -e "  Firewall:   ${RED}Rules missing${NC}"
            fi
        else
            echo -e "  Server:     ${REMOTE_SERVER}"
            echo -e "  SOCKS port: ${SOCKS_PORT}"
            echo -e "  Key:        ${ENCRYPTION_KEY:0:8}..."
        fi
    fi

    # Telegram
    if [ "$TELEGRAM_ENABLED" = "true" ]; then
        echo -e "  Telegram:   ${GREEN}Enabled${NC}"
    else
        echo -e "  Telegram:   ${DIM}Disabled${NC}"
    fi

    echo ""
}

#═══════════════════════════════════════════════════════════════════════
# Logs
#═══════════════════════════════════════════════════════════════════════

show_logs() {
    local lines=50 follow="" since="" backend="" errors=false
    while [ $# -gt 0 ]; do
        case "$1" in
            -n|--lines)
                [[ "${2:-}" =~ ^[0-9]+$ ]] || { log_error "$1 needs a number"; return 2; }
                lines="$2"; shift 2 ;;
            -n[0-9]*) lines="${1#-n}"; shift ;;
            --lines=*) lines="${1#--lines=}"; shift ;;
            -f|--follow) follow=true; shift ;;
            --no-follow) follow=false; shift ;;
            --since)
                [ -n "${2:-}" ] || { log_error "--since needs a value (e.g. '1 hour ago', 2024-01-01)"; return 2; }
                since="$2"; shift 2 ;;
            --since=*) since="${1#--since=}"; shift ;;
            --backend)
                [ -n "${2:-}" ] || { log_error "--backend needs 'paqet' or 'gfk'"; return 2; }
                backend="$2"; shift 2 ;;
            --backend=*) backend="${1#--backend=}"; shift ;;
            --errors) errors=true; shift ;;
            *) log_error "Unknown option for logs: $1"; echo "  Usage: paqctl logs [-n N] [--no-follow] [--since TIME] [--backend paqet|gfk] [--errors]" >&2; return 2 ;;
        esac
    done
    [[ "$lines" =~ ^[0-9]+$ ]] || { log_error "Invalid line count: $lines"; return 2; }
    case "$backend" in
        ""|paqet|gfk) ;;
        gfw-knocker) backend="gfk" ;;
        *) log_error "--backend must be 'paqet' or 'gfk'"; return 2 ;;
    esac
    # Follow by default only when someone is watching
    if [ -z "$follow" ]; then
        if [ -t 1 ]; then follow=true; else follow=false; fi
    fi

    # Pick a log source: a backend's own log file when asked (and present),
    # otherwise the service journal / log file.
    local src_file="" use_journal=false
    if [ "$backend" = "gfk" ] && [ -f /var/log/gfk-backend.log ]; then
        src_file=/var/log/gfk-backend.log
    elif [ "$backend" = "paqet" ] && [ -f /var/log/paqet-backend.log ]; then
        src_file=/var/log/paqet-backend.log
    elif command -v journalctl &>/dev/null && [ -d /run/systemd/system ]; then
        use_journal=true
    elif [ -f /var/log/paqctl.log ]; then
        src_file=/var/log/paqctl.log
    elif [ -f /var/log/paqet-backend.log ]; then
        src_file=/var/log/paqet-backend.log
    elif [ -f /var/log/gfk-backend.log ]; then
        src_file=/var/log/gfk-backend.log
    else
        log_warn "No logs found. Is paqctl running?"
        return 1
    fi
    if [ -n "$since" ] && [ "$use_journal" != true ]; then
        log_warn "--since is only supported with the systemd journal; showing the last $lines lines of $src_file"
    fi

    local -a cmd
    if [ "$use_journal" = true ]; then
        cmd=(journalctl -u paqctl.service --no-pager -n "$lines")
        [ -n "$since" ] && cmd+=(--since "$since")
        [ "$follow" = true ] && cmd+=(-f)
    else
        cmd=(tail -n "$lines")
        [ "$follow" = true ] && cmd+=(-f)
        cmd+=("$src_file")
    fi

    if [ "$follow" = true ]; then
        echo ""
        log_info "Showing logs$([ -n "$src_file" ] && echo " from $src_file") (Ctrl+C to stop)..."
        echo ""
        # Trap Ctrl+C to return to menu instead of exiting
        trap 'echo ""; log_info "Stopped following logs."; return 0' INT
    fi

    if [ "$errors" = true ]; then
        "${cmd[@]}" 2>&1 | grep --line-buffered -iE 'error|fail|fatal|panic|warn|refused|timeout' || true
    else
        "${cmd[@]}"
    fi
    local rc=$?

    [ "$follow" = true ] && trap - INT
    return $rc
}

#═══════════════════════════════════════════════════════════════════════
# Health Check
#═══════════════════════════════════════════════════════════════════════

_print_section() {
    [ "$JSON_OUTPUT" = true ] && return 0
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  $1${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

# Check results: "status<US>message<US>hint<US>fix-id" (US = \x1f)
_HC_RESULTS=()
_HC_FAILS=0
_HC_WARNS=0
_HC_SHOW_HINTS=false
_HC_QUIET=false

# _hc ok|fail|warn|info "message" ["hint"] ["fix-id"]
_hc() {
    local st="$1" msg="$2" hint="${3:-}" fix="${4:-}"
    _HC_RESULTS+=("${st}"$'\x1f'"${msg}"$'\x1f'"${hint}"$'\x1f'"${fix}")
    case "$st" in
        fail) _HC_FAILS=$((_HC_FAILS + 1)) ;;
        warn) _HC_WARNS=$((_HC_WARNS + 1)) ;;
    esac
    if [ "$JSON_OUTPUT" = true ] || [ "$_HC_QUIET" = true ]; then
        return 0
    fi
    _hc_print_line "$st" "$msg" "$hint"
}

_hc_print_line() {
    local st="$1" msg="$2" hint="${3:-}"
    case "$st" in
        ok)   echo -e "  ${GREEN}✓${NC} ${msg}" ;;
        fail) echo -e "  ${RED}✗${NC} ${msg}" ;;
        warn) echo -e "  ${YELLOW}!${NC} ${msg}" ;;
        *)    echo -e "  ${DIM}• ${msg}${NC}" ;;
    esac
    if [ "$_HC_SHOW_HINTS" = true ] && [ -n "$hint" ] && [ "$st" != "ok" ]; then
        echo -e "      ${CYAN}→${NC} ${hint}"
    fi
}

_hc_iptables_has() { command -v iptables &>/dev/null && iptables "$@" 2>/dev/null; }

_run_health_checks() {
    local doctor="${1:-false}"
    _HC_RESULTS=(); _HC_FAILS=0; _HC_WARNS=0

    if [ "$BACKEND" = "gfw-knocker" ]; then
        if [ -f "$GFK_DIR/mainserver.py" ] && [ -f "$GFK_DIR/mainclient.py" ]; then
            _hc ok "GFW-knocker scripts found"
        else
            _hc fail "GFW-knocker scripts missing from $GFK_DIR" "Reinstall GFK: sudo paqctl update"
        fi

        if [ -x "$INSTALL_DIR/venv/bin/python" ] && "$INSTALL_DIR/venv/bin/python" -c "import scapy; import aioquic" 2>/dev/null; then
            _hc ok "Python dependencies OK (scapy, aioquic)"
        else
            _hc fail "Python dependencies missing (venv not set up)" "Reinstall them: $INSTALL_DIR/venv/bin/pip install scapy aioquic (or re-run the installer)"
        fi

        if [ -f "$GFK_DIR/parameters.py" ]; then
            _hc ok "GFK configuration found"
        else
            _hc fail "GFK configuration missing" "Regenerate it: sudo paqctl config"
        fi

        if [ -f "$GFK_DIR/cert.pem" ] && [ -f "$GFK_DIR/key.pem" ]; then
            _hc ok "QUIC certificates found"
        else
            _hc fail "QUIC certificates missing" "Restore them (sudo paqctl restore latest) or re-run the installer"
        fi

        if is_running; then
            _hc ok "GFW-knocker is running"
        else
            _hc fail "GFW-knocker is not running" "Start it: sudo paqctl start (logs: sudo paqctl logs --backend gfk --errors --no-follow)" start
        fi

        if [ "$ROLE" = "server" ]; then
            # Tagged rules come from _apply_firewall, untagged ones from older installs
            local _vio_port="${GFK_VIO_PORT:-45000}"
            if _hc_iptables_has -C INPUT -p tcp --dport "$_vio_port" -m comment --comment "paqctl" -j DROP || \
               _hc_iptables_has -C INPUT -p tcp --dport "$_vio_port" -j DROP; then
                _hc ok "VIO port ${_vio_port} INPUT blocked"
            else
                _hc fail "VIO port ${_vio_port} INPUT NOT blocked" "Apply firewall rules: sudo paqctl firewall (option 1)" firewall
            fi
            if _hc_iptables_has -C OUTPUT -p tcp --sport "$_vio_port" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP || \
               _hc_iptables_has -C OUTPUT -p tcp --sport "$_vio_port" --tcp-flags RST RST -j DROP; then
                _hc ok "VIO port ${_vio_port} RST DROP in place"
            else
                _hc fail "VIO port ${_vio_port} RST DROP missing" "Apply firewall rules: sudo paqctl firewall (option 1)" firewall
            fi
        fi

        if [ "$ROLE" = "client" ] && is_running; then
            local _socks_vio
            _socks_vio=$(_gfk_client_socks_port)
            if ss -tlnp 2>/dev/null | grep -q ":${_socks_vio} "; then
                _hc ok "SOCKS5 port ${_socks_vio} is listening"
            else
                _hc fail "SOCKS5 port ${_socks_vio} not listening" "Check the logs: sudo paqctl logs --backend gfk --errors --no-follow"
            fi
        fi
    else
        if [ -x "$INSTALL_DIR/bin/paqet" ]; then
            _hc ok "paqet binary found"
        else
            _hc fail "paqet binary not found at $INSTALL_DIR/bin/paqet" "Reinstall it: sudo paqctl update"
        fi

        if [ -f "$INSTALL_DIR/config.yaml" ]; then
            _hc ok "Configuration file found"
        elif [ -n "${INTERFACE:-}" ] && [ -n "${LOCAL_IP:-}" ] && [ -n "${GATEWAY_MAC:-}" ] && [ -n "${ENCRYPTION_KEY:-}" ]; then
            _hc fail "Configuration file missing" "Regenerate it from settings: sudo paqctl doctor --fix" regen-config
        else
            _hc fail "Configuration file missing" "Create it: sudo paqctl config"
        fi

        if is_running; then
            _hc ok "paqet is running"
        else
            _hc fail "paqet is not running" "Start it: sudo paqctl start (logs: sudo paqctl logs --errors --no-follow)" start
        fi

        if ldconfig -p 2>/dev/null | grep -q libpcap; then
            _hc ok "libpcap is available"
        else
            _hc warn "libpcap not found in ldconfig (may still work)" "Install it: apt install libpcap0.8 | dnf install libpcap | apk add libpcap"
        fi

        if [ "$ROLE" = "server" ]; then
            if _hc_iptables_has -t raw -C PREROUTING -p tcp --dport "$LISTEN_PORT" -m comment --comment "paqctl" -j NOTRACK; then
                _hc ok "iptables NOTRACK rules in place (port $LISTEN_PORT)"
            else
                _hc fail "iptables NOTRACK rules missing for port $LISTEN_PORT" "Apply firewall rules: sudo paqctl firewall (option 1)" firewall
            fi
            if _hc_iptables_has -t mangle -C OUTPUT -p tcp --sport "$LISTEN_PORT" -m comment --comment "paqctl" --tcp-flags RST RST -j DROP; then
                _hc ok "iptables RST DROP rule in place"
            else
                _hc fail "iptables RST DROP rule missing" "Apply firewall rules: sudo paqctl firewall (option 1)" firewall
            fi
            if is_running; then
                if ss -tlnp 2>/dev/null | grep -q ":${LISTEN_PORT}"; then
                    _hc ok "Port $LISTEN_PORT is listening"
                else
                    _hc info "Port $LISTEN_PORT not shown in ss (expected: paqet uses raw sockets)"
                fi
            fi
        fi

        if [ "$ROLE" = "client" ] && is_running; then
            if [ "${ROUTING_MODE:-socks5}" = "forward" ]; then
                if ss -tlnp 2>/dev/null | grep -q ":${FORWARD_PORT:-14000} "; then
                    _hc ok "Forward port ${FORWARD_PORT:-14000} is listening"
                else
                    _hc fail "Forward port ${FORWARD_PORT:-14000} is not listening" "Check the logs: sudo paqctl logs --errors --no-follow"
                fi
            elif ss -tlnp 2>/dev/null | grep -q ":${SOCKS_PORT}"; then
                _hc ok "SOCKS5 port $SOCKS_PORT is listening"
            else
                _hc fail "SOCKS5 port $SOCKS_PORT is not listening" "Check the logs: sudo paqctl logs --errors --no-follow"
            fi
        fi

        # paqet ping is a client-side test (it needs a client config)
        if [ "$ROLE" = "client" ] && is_running && [ -x "$INSTALL_DIR/bin/paqet" ]; then
            [ "$JSON_OUTPUT" = true ] || [ "$_HC_QUIET" = true ] || echo -e "  ${DIM}Running paqet ping test...${NC}"
            local ping_result
            ping_result=$(timeout 10 "$INSTALL_DIR/bin/paqet" ping -c "$INSTALL_DIR/config.yaml" 2>&1 || true)
            if echo "$ping_result" | grep -qi "success\|pong\|ok\|alive\|rtt"; then
                _hc ok "Paqet ping: OK"
            elif [ -n "$ping_result" ]; then
                _hc warn "Paqet ping: $(echo "$ping_result" | head -1)" "Run it interactively: sudo paqctl ping"
            else
                _hc warn "Paqet ping: no response (may not be supported)"
            fi
        fi
    fi

    [ "$doctor" = true ] && _run_doctor_checks

    if curl -s --max-time 5 https://api.github.com &>/dev/null; then
        _hc ok "Internet connectivity: OK"
    else
        _hc warn "Cannot reach GitHub API (may be firewall/network)" "Check DNS and outbound HTTPS: curl -v https://api.github.com"
    fi

    if _boot_enabled; then
        _hc ok "Auto-start on boot: enabled"
    elif _init_system >/dev/null; then
        _hc warn "Auto-start on boot: disabled" "Enable it: sudo paqctl enable" enable-boot
    fi
}

# Extra checks that only 'paqctl doctor' runs (environment drift, conflicts)
_run_doctor_checks() {
    if [ "$BACKEND" != "gfw-knocker" ]; then
        local iface="${INTERFACE:-}"
        if [ -n "$iface" ] && ip link show "$iface" &>/dev/null; then
            _hc ok "Interface $iface exists"

            if [ -n "${LOCAL_IP:-}" ]; then
                if ip -4 addr show dev "$iface" 2>/dev/null | grep -qw "inet ${LOCAL_IP}"; then
                    _hc ok "Local IP ${LOCAL_IP} is assigned to $iface"
                else
                    local cur_ip
                    cur_ip=$(ip -4 addr show dev "$iface" 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)
                    _hc fail "Local IP ${LOCAL_IP} is no longer assigned to $iface${cur_ip:+ (now: $cur_ip)}" \
                        "Update it: sudo paqctl config set LOCAL_IP=${cur_ip:-<ip>}"
                fi
            fi

            local gw gw_mac=""
            gw=$(ip route show default 2>/dev/null | awk '{print $3; exit}')
            [ -n "$gw" ] && gw_mac=$(ip neigh show "$gw" 2>/dev/null | awk '/lladdr/{print $5; exit}')
            if [ -n "$gw_mac" ] && [ -n "${GATEWAY_MAC:-}" ]; then
                if [ "${gw_mac,,}" = "${GATEWAY_MAC,,}" ]; then
                    _hc ok "Gateway MAC matches ($gw_mac)"
                else
                    _hc fail "Gateway MAC changed: configured ${GATEWAY_MAC}, current ${gw_mac}" \
                        "Update it: sudo paqctl config set GATEWAY_MAC=${gw_mac}"
                fi
            fi

            local if_mtu kcp_mtu="${KCP_MTU:-1350}"
            if_mtu=$(cat "/sys/class/net/$iface/mtu" 2>/dev/null || true)
            if [[ "$if_mtu" =~ ^[0-9]+$ ]] && [[ "$kcp_mtu" =~ ^[0-9]+$ ]]; then
                # Leave room for IP/TCP headers (and IPv6 / nested tunnels)
                if [ "$kcp_mtu" -gt $((if_mtu - 100)) ]; then
                    _hc warn "KCP MTU ${kcp_mtu} leaves little headroom on $iface (MTU ${if_mtu})" \
                        "Lower it on both ends: sudo paqctl config set KCP_MTU=$((if_mtu - 150))"
                else
                    _hc ok "KCP MTU ${kcp_mtu} fits interface MTU ${if_mtu}"
                fi
            fi
        else
            local def_if
            def_if=$(ip route show default 2>/dev/null | awk '{print $5; exit}')
            _hc fail "Network interface '${iface:-<unset>}' not found" "Update it: sudo paqctl config set INTERFACE=${def_if:-<name>}"
        fi

        if [ "$ROLE" = "client" ] && [ "${ROUTING_MODE:-socks5}" != "forward" ] && ! is_paqet_running; then
            if ss -tlnp 2>/dev/null | grep -qE "[:.]${SOCKS_PORT:-1080}[[:space:]]"; then
                _hc fail "SOCKS5 port ${SOCKS_PORT:-1080} is already used by another process" \
                    "Free the port (ss -tlnp | grep :${SOCKS_PORT:-1080}) or pick another: sudo paqctl config set SOCKS_PORT=<port>"
            fi
        fi

        if [ -f "$INSTALL_DIR/config.yaml" ] && [ -n "${ENCRYPTION_KEY:-}" ]; then
            if grep -qF -- "$ENCRYPTION_KEY" "$INSTALL_DIR/config.yaml"; then
                _hc ok "config.yaml matches settings.conf (key)"
            else
                _hc fail "config.yaml key differs from settings.conf (manual edit or interrupted key rotation?)" \
                    "Regenerate config.yaml from settings: sudo paqctl doctor --fix" regen-config
            fi
        fi
    fi

    local avail mnt
    avail=$(df -Pk "$INSTALL_DIR" 2>/dev/null | awk 'NR==2{print $4}')
    mnt=$(df -Pk "$INSTALL_DIR" 2>/dev/null | awk 'NR==2{print $6}')
    if [[ "$avail" =~ ^[0-9]+$ ]]; then
        if [ "$avail" -lt 51200 ]; then
            _hc warn "Low disk space on ${mnt:-/}: $((avail / 1024)) MB free" "Free some space: sudo paqctl cleanup --journal"
        else
            _hc ok "Disk space OK ($((avail / 1024)) MB free on ${mnt:-/})"
        fi
    fi

    if command -v getent &>/dev/null; then
        if getent hosts github.com &>/dev/null; then
            _hc ok "DNS resolution works"
        else
            _hc warn "DNS resolution failed (github.com)" "Check /etc/resolv.conf"
        fi
    fi

    if [ "${WATCHDOG_ENABLED:-false}" != "true" ]; then
        _hc info "Self-healing watchdog is off (optional: sudo paqctl watchdog enable)"
    fi
}

# Print the summary (text) or the whole result set (JSON). Returns 1 if any check failed.
_hc_report() {
    if [ "$JSON_OUTPUT" = true ]; then
        local first=true r st msg hint fix
        printf '{"ok":%s,"failures":%d,"warnings":%d,"checks":[' \
            "$(_json_bool "$([ "$_HC_FAILS" -eq 0 ] && echo true)")" "$_HC_FAILS" "$_HC_WARNS"
        for r in "${_HC_RESULTS[@]}"; do
            IFS=$'\x1f' read -r st msg hint fix <<< "$r"
            [ "$first" = true ] || printf ','
            first=false
            printf '{"status":%s,"message":%s' "$(_json_str "$st")" "$(_json_str "$msg")"
            [ -n "$hint" ] && printf ',"hint":%s' "$(_json_str "$hint")"
            [ -n "$fix" ] && printf ',"fixable":true'
            printf '}'
        done
        printf ']}\n'
    else
        echo ""
        if [ "$_HC_FAILS" -eq 0 ]; then
            if [ "$_HC_WARNS" -gt 0 ]; then
                echo -e "  ${GREEN}${BOLD}All checks passed${NC} (${_HC_WARNS} warning(s))"
            else
                echo -e "  ${GREEN}${BOLD}All checks passed!${NC}"
            fi
        else
            echo -e "  ${RED}${BOLD}${_HC_FAILS} issue(s) found${NC}"
            [ "$_HC_SHOW_HINTS" = true ] || echo -e "  ${DIM}Run 'sudo paqctl doctor' for suggested fixes.${NC}"
        fi
        echo ""
    fi
    [ "$_HC_FAILS" -eq 0 ]
}

health_check() {
    _print_section "HEALTH CHECK"
    _HC_SHOW_HINTS=false
    _run_health_checks false
    _hc_report
}

# Fix ids of failing/warning checks, de-duplicated, in order
_hc_fix_ids() {
    local r st msg hint fix seen=" "
    for r in "${_HC_RESULTS[@]}"; do
        IFS=$'\x1f' read -r st msg hint fix <<< "$r"
        [ -n "$fix" ] && [ "$st" != "ok" ] || continue
        case "$seen" in *" $fix "*) continue ;; esac
        seen="${seen}${fix} "
        echo "$fix"
    done
}

run_doctor() {
    local do_fix=false a
    for a in "$@"; do
        case "$a" in
            --fix) do_fix=true ;;
            *) log_error "Unknown option for doctor: $a"; echo "  Usage: paqctl doctor [--fix] [--json]" >&2; return 2 ;;
        esac
    done

    _print_section "DOCTOR"
    _HC_SHOW_HINTS=true
    _run_health_checks true

    local -a fixes=()
    local f
    while IFS= read -r f; do [ -n "$f" ] && fixes+=("$f"); done < <(_hc_fix_ids)

    if [ "$do_fix" != true ] || [ ${#fixes[@]} -eq 0 ]; then
        if [ "$JSON_OUTPUT" != true ] && [ ${#fixes[@]} -gt 0 ]; then
            echo ""
            echo -e "  ${CYAN}${#fixes[@]} problem type(s) can be fixed automatically: ${BOLD}sudo paqctl doctor --fix${NC}"
        fi
        _hc_report
        return
    fi

    echo "" | _log_fd
    log_info "Applying fixes: ${fixes[*]}"
    local need_start=false need_restart=false
    for f in "${fixes[@]}"; do
        case "$f" in
            firewall)
                if _apply_firewall; then log_success "Firewall rules applied"; else log_error "Could not apply firewall rules"; fi ;;
            regen-config)
                if _write_paqet_config; then log_success "config.yaml regenerated from settings.conf"; need_restart=true; fi ;;
            enable-boot)
                _set_boot enable || true ;;
            start)
                need_start=true ;;
        esac
    done
    if [ "$need_restart" = true ] && is_running; then
        { restart_paqet || true; } | _log_fd
    elif [ "$need_start" = true ] || [ "$need_restart" = true ]; then
        { start_paqet || true; } | _log_fd
    fi

    # Re-check and show what is still wrong
    _HC_QUIET=true
    _run_health_checks true
    _HC_QUIET=false
    if [ "$JSON_OUTPUT" != true ]; then
        echo ""
        echo -e "  ${BOLD}After fixes:${NC}"
        local r st msg hint fix remaining=0
        for r in "${_HC_RESULTS[@]}"; do
            IFS=$'\x1f' read -r st msg hint fix <<< "$r"
            if [ "$st" = "fail" ] || [ "$st" = "warn" ]; then
                _hc_print_line "$st" "$msg" "$hint"
                remaining=$((remaining + 1))
            fi
        done
        [ "$remaining" -eq 0 ] && echo -e "  ${GREEN}✓${NC} No remaining problems"
    fi
    _hc_report
}
