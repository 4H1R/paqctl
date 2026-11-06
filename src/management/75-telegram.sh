#═══════════════════════════════════════════════════════════════════════
# Telegram Integration
#═══════════════════════════════════════════════════════════════════════

# Secure Telegram API curl - writes token to temp file to avoid /proc exposure
_telegram_api_curl() {
    local endpoint="$1"
    shift
    local _tg_tmp
    _tg_tmp=$(mktemp "${INSTALL_DIR}/.tg_curl.XXXXXXXX") || return 1
    chmod 600 "$_tg_tmp" 2>/dev/null
    printf 'url = "https://api.telegram.org/bot%s/%s"\n' "$TELEGRAM_BOT_TOKEN" "$endpoint" > "$_tg_tmp"
    local _result
    _result=$(curl -s --max-time 10 --max-filesize 1048576 -K "$_tg_tmp" "$@" 2>/dev/null)
    local _exit=$?
    rm -f "$_tg_tmp"
    [ $_exit -eq 0 ] && echo "$_result"
    return $_exit
}

escape_telegram_markdown() {
    local text="$1"
    text="${text//\\/\\\\}"
    text="${text//\*/\\*}"
    text="${text//_/\\_}"
    text="${text//\`/\\\`}"
    text="${text//\[/\\[}"
    text="${text//\]/\\]}"
    echo "$text"
}

telegram_send_message() {
    local message="$1"
    { [ -z "$TELEGRAM_BOT_TOKEN" ] || [ -z "$TELEGRAM_CHAT_ID" ]; } && return 1
    local label="${TELEGRAM_SERVER_LABEL:-$(hostname 2>/dev/null || echo 'unknown')}"
    label=$(escape_telegram_markdown "$label")
    local _ip=$(curl -s --max-time 3 https://api.ipify.org 2>/dev/null || echo "")
    if [ -n "$_ip" ]; then
        message="[${label} | ${_ip}] ${message}"
    else
        message="[${label}] ${message}"
    fi
    local response
    response=$(_telegram_api_curl "sendMessage" \
        -X POST \
        --data-urlencode "chat_id=$TELEGRAM_CHAT_ID" \
        --data-urlencode "text=$message" \
        --data-urlencode "parse_mode=Markdown")
    [ $? -ne 0 ] && return 1
    echo "$response" | grep -q '"ok":true' && return 0
    return 1
}

telegram_get_chat_id() {
    local response
    response=$(_telegram_api_curl "getUpdates")
    [ -z "$response" ] && return 1
    echo "$response" | grep -q '"ok":true' || return 1
    local chat_id=""
    if command -v python3 &>/dev/null; then
        chat_id=$(python3 -c "
import json,sys
try:
    d=json.loads(sys.stdin.read())
    msgs=d.get('result',[])
    if msgs:
        print(msgs[-1]['message']['chat']['id'])
except: pass
" <<< "$response" 2>/dev/null)
    fi
    if [ -z "$chat_id" ]; then
        chat_id=$(echo "$response" | grep -o '"chat"[[:space:]]*:[[:space:]]*{[[:space:]]*"id"[[:space:]]*:[[:space:]]*-\?[0-9]\+' | grep -o -- '-\?[0-9]\+$' | tail -1 2>/dev/null)
    fi
    if [ -n "$chat_id" ] && echo "$chat_id" | grep -qE '^-?[0-9]+$'; then
        TELEGRAM_CHAT_ID="$chat_id"
        return 0
    fi
    return 1
}

telegram_build_report() {
    local report="📊 *Paqet Status Report*"
    report+=$'\n'
    report+="🕐 $(date '+%Y-%m-%d %H:%M %Z')"
    report+=$'\n\n'

    if is_running; then
        report+="✅ Status: Running"
    else
        report+="❌ Status: Stopped"
    fi
    report+=$'\n'
    report+="📡 Role: ${ROLE}"
    report+=$'\n'
    report+="📦 Version: ${PAQET_VERSION}"
    report+=$'\n'

    if [ "$ROLE" = "server" ]; then
        report+="🔌 Port: ${LISTEN_PORT}"
        report+=$'\n'
        if iptables -t raw -C PREROUTING -p tcp --dport "$LISTEN_PORT" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null; then
            report+="🛡 Firewall: Rules active"
        else
            report+="⚠️ Firewall: Rules missing"
        fi
    else
        report+="🔗 Server: ${REMOTE_SERVER}"
        report+=$'\n'
        report+="🧦 SOCKS: port ${SOCKS_PORT}"
    fi
    report+=$'\n'

    # Uptime
    if is_running && command -v systemctl &>/dev/null && [ -d /run/systemd/system ]; then
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
                    report+="⏱ Uptime: ${days}d ${hours}h ${mins}m"
                else
                    report+="⏱ Uptime: ${hours}h ${mins}m"
                fi
                report+=$'\n'
            fi
        fi
    fi

    # CPU/RAM
    local pid
    if [ "$BACKEND" = "gfw-knocker" ]; then
        pid=$(pgrep -f "mainserver.py|mainclient.py" 2>/dev/null | head -1)
    else
        pid=$(pgrep -f "paqet run -c" 2>/dev/null | head -1)
    fi
    if [ -n "$pid" ]; then
        local cpu_mem
        cpu_mem=$(ps -p "$pid" -o %cpu=,%mem= 2>/dev/null | head -1)
        if [ -n "$cpu_mem" ]; then
            local cpu=$(echo "$cpu_mem" | awk '{print $1}')
            local mem=$(echo "$cpu_mem" | awk '{print $2}')
            report+="💻 CPU: ${cpu}% | RAM: ${mem}%"
            report+=$'\n'
        fi
    fi

    echo "$report"
}

telegram_test_message() {
    local interval_label="${TELEGRAM_INTERVAL:-6}"
    local report=$(telegram_build_report)
    local backend_name="${BACKEND:-paqet}"

    # Backend-specific description
    local tech_desc=""
    if [ "$BACKEND" = "gfw-knocker" ]; then
        tech_desc="🔗 *What is GFW-Knocker?*
An advanced anti-censorship tool using 'violated TCP' packets + QUIC tunneling.
Designed for heavy DPI environments like the Great Firewall.
• Raw socket layer bypasses kernel TCP stack
• QUIC tunnel provides encrypted transport
• Requires Xray on server for SOCKS5 proxy"
    else
        tech_desc="🔗 *What is Paqet?*
A raw-socket encrypted proxy using KCP protocol.
Simple all-in-one solution with built-in SOCKS5 proxy.
• KCP over raw TCP packets with custom flags bypasses DPI
• Built-in SOCKS5 proxy (no extra software needed)
• Easy setup with just IP, port, and key"
    fi

    local message="✅ *paqctl Connected!*

📦 *About paqctl*
A unified management tool for bypass proxies.
Supports two backends for different network conditions:
• *paqet* — Simple KCP-based proxy (recommended)
• *gfw-knocker* — Advanced violated-TCP + QUIC tunnel

━━━━━━━━━━━━━━━━━━━━
${tech_desc}

📬 *What this bot sends you every ${interval_label}h:*
• Service status & uptime
• CPU & RAM usage
• Configuration summary
• Firewall rule status

⚠️ *Alerts:*
If the service goes down or is restarted, you will receive an immediate alert.

━━━━━━━━━━━━━━━━━━━━
🎮 *Available Commands:*
━━━━━━━━━━━━━━━━━━━━
/status — Full status report
/health — Run health check
/restart — Restart ${backend_name}
/stop — Stop ${backend_name}
/start — Start ${backend_name}
/version — Show version info

━━━━━━━━━━━━━━━━━━━━
📊 *Your first report:*
━━━━━━━━━━━━━━━━━━━━

${report}"
    telegram_send_message "$message"
}

telegram_generate_notify_script() {
    local script_path="$INSTALL_DIR/paqctl-telegram.sh"
    local _tmp
    _tmp=$(mktemp "${script_path}.XXXXXXXX")
    cat > "$_tmp" << 'TGSCRIPT'
#!/bin/bash
# paqctl Telegram notification daemon

INSTALL_DIR="REPLACE_ME_INSTALL_DIR"

# Safe settings loader - parses key=value with validation
_load_settings() {
    [ -f "$INSTALL_DIR/settings.conf" ] || return 0
    while IFS='=' read -r key value; do
        [[ "$key" =~ ^[A-Z_][A-Z_0-9]*$ ]] || continue
        value="${value#\"}"; value="${value%\"}"
        # Skip values with dangerous shell characters
        [[ "$value" =~ [\`\$\(] ]] && continue
        case "$key" in
            BACKEND|ROLE|PAQET_VERSION|PAQCTL_VERSION|INTERFACE|LOCAL_IP|GATEWAY_MAC|\
            ENCRYPTION_KEY|REMOTE_SERVER|GFK_AUTH_CODE|GFK_PORT_MAPPINGS|GFK_SERVER_IP|\
            XRAY_PANEL_DETECTED|\
            TELEGRAM_BOT_TOKEN|TELEGRAM_CHAT_ID|TELEGRAM_SERVER_LABEL|\
            TELEGRAM_ENABLED|TELEGRAM_ALERTS_ENABLED|TELEGRAM_DAILY_SUMMARY|TELEGRAM_WEEKLY_SUMMARY)
                export "$key=$value" ;;
            LISTEN_PORT|SOCKS_PORT|GFK_VIO_PORT|GFK_VIO_CLIENT_PORT|GFK_QUIC_PORT|GFK_QUIC_CLIENT_PORT|MICROSOCKS_PORT|\
            GFK_SOCKS_PORT|GFK_SOCKS_VIO_PORT|\
            TELEGRAM_INTERVAL|TELEGRAM_START_HOUR)
                [[ "$value" =~ ^[0-9]*$ ]] && export "$key=$value" ;;
        esac
    done < <(grep '^[A-Z_][A-Z_0-9]*=' "$INSTALL_DIR/settings.conf")
}
_load_settings

TELEGRAM_BOT_TOKEN=${TELEGRAM_BOT_TOKEN:-}
TELEGRAM_CHAT_ID=${TELEGRAM_CHAT_ID:-}
TELEGRAM_INTERVAL=${TELEGRAM_INTERVAL:-6}
TELEGRAM_ALERTS_ENABLED=${TELEGRAM_ALERTS_ENABLED:-true}
TELEGRAM_DAILY_SUMMARY=${TELEGRAM_DAILY_SUMMARY:-true}
TELEGRAM_WEEKLY_SUMMARY=${TELEGRAM_WEEKLY_SUMMARY:-true}
TELEGRAM_START_HOUR=${TELEGRAM_START_HOUR:-0}

{ [ -z "$TELEGRAM_BOT_TOKEN" ] || [ -z "$TELEGRAM_CHAT_ID" ]; } && exit 1

escape_telegram_markdown() {
    local text="$1"
    text="${text//\\/\\\\}"
    text="${text//\*/\\*}"
    text="${text//_/\\_}"
    text="${text//\`/\\\`}"
    text="${text//\[/\\[}"
    text="${text//\]/\\]}"
    echo "$text"
}

# Secure Telegram API curl - writes token to temp file to avoid /proc exposure
_tg_api_curl() {
    local endpoint="$1"
    shift
    local _tg_tmp
    _tg_tmp=$(mktemp "${INSTALL_DIR}/.tg_curl.XXXXXXXX") || return 1
    chmod 600 "$_tg_tmp" 2>/dev/null
    printf 'url = "https://api.telegram.org/bot%s/%s"\n' "$TELEGRAM_BOT_TOKEN" "$endpoint" > "$_tg_tmp"
    local _result
    _result=$(curl -s --max-time 10 --max-filesize 1048576 -K "$_tg_tmp" "$@" 2>/dev/null)
    local _exit=$?
    rm -f "$_tg_tmp"
    [ $_exit -eq 0 ] && echo "$_result"
    return $_exit
}

send_message() {
    local message="$1"
    { [ -z "$TELEGRAM_BOT_TOKEN" ] || [ -z "$TELEGRAM_CHAT_ID" ]; } && return 1
    local label="${TELEGRAM_SERVER_LABEL:-$(hostname 2>/dev/null || echo 'unknown')}"
    label=$(escape_telegram_markdown "$label")
    local _ip=$(curl -s --max-time 3 https://api.ipify.org 2>/dev/null || echo "")
    [ -n "$_ip" ] && message="[${label} | ${_ip}] ${message}" || message="[${label}] ${message}"
    local response
    response=$(_tg_api_curl "sendMessage" \
        -X POST \
        --data-urlencode "chat_id=$TELEGRAM_CHAT_ID" \
        --data-urlencode "text=$message" \
        --data-urlencode "parse_mode=Markdown")
    [ $? -ne 0 ] && return 1
    echo "$response" | grep -q '"ok":true' && return 0
    return 1
}

get_main_pid() {
    if [ -f /run/paqctl.pid ]; then
        local _pid=$(cat /run/paqctl.pid 2>/dev/null)
        if [[ "$_pid" =~ ^[0-9]+$ ]] && kill -0 "$_pid" 2>/dev/null; then
            echo "$_pid"
            return 0
        fi
    fi
    if command -v systemctl &>/dev/null && [ -d /run/systemd/system ] && systemctl is-active paqctl.service &>/dev/null; then
        local _pid=$(systemctl show -p MainPID paqctl.service 2>/dev/null | cut -d= -f2)
        if [[ "$_pid" =~ ^[0-9]+$ ]] && [ "$_pid" -gt 0 ]; then
            echo "$_pid"
            return 0
        fi
    fi
    if [ "$BACKEND" = "gfw-knocker" ]; then
        if [ "$ROLE" = "server" ]; then
            pgrep -f "${GFK_DIR}/mainserver.py" 2>/dev/null | head -1
        else
            pgrep -f "${GFK_DIR}/mainclient.py|${INSTALL_DIR}/bin/gfk-client.sh" 2>/dev/null | head -1
        fi
    else
        pgrep -f "${INSTALL_DIR}/bin/paqet run -c ${INSTALL_DIR}/config.yaml" 2>/dev/null | head -1
    fi
}

build_report() {
    local report="📊 *${BACKEND} Status Report*"$'\n'
    report+="🕐 $(date '+%Y-%m-%d %H:%M %Z')"$'\n\n'
    if is_running; then
        report+="✅ Status: Running"
    else
        report+="❌ Status: Stopped"
    fi
    report+=$'\n'"📡 Role: ${ROLE:-unknown}"$'\n'
    report+="📦 Version: ${PAQET_VERSION:-unknown}"$'\n'
    local pid=$(get_main_pid)
    if [ -n "$pid" ]; then
        local cpu_mem=$(ps -p "$pid" -o %cpu=,%mem= 2>/dev/null | head -1)
        if [ -n "$cpu_mem" ]; then
            local cpu=$(echo "$cpu_mem" | awk '{print $1}')
            local mem=$(echo "$cpu_mem" | awk '{print $2}')
            report+="💻 CPU: ${cpu}% | RAM: ${mem}%"$'\n'
        fi
    fi
    echo "$report"
}

LAST_COMMAND_TIME=0
COMMAND_COOLDOWN=5

check_commands() {
    local response
    response=$(_tg_api_curl "getUpdates" \
        -X POST \
        --data-urlencode "offset=${LAST_UPDATE_ID:-0}" \
        --data-urlencode "limit=10")
    [ -z "$response" ] && return
    echo "$response" | grep -q '"ok":true' || return

    if command -v python3 &>/dev/null; then
        local cmds
        local _safe_chat_id
        _safe_chat_id=$(printf '%s' "$TELEGRAM_CHAT_ID" | tr -cd '0-9-')
        [ -z "$_safe_chat_id" ] && return
        cmds=$(python3 -c "
import json,sys
try:
    d=json.loads(sys.stdin.read())
    chat_id=sys.argv[1]
    if not chat_id: sys.exit(0)
    for r in d.get('result',[]):
        uid=r['update_id']
        txt=r.get('message',{}).get('text','').replace('|','')
        cid=str(r.get('message',{}).get('chat',{}).get('id',''))
        if cid==chat_id and txt.startswith('/'):
            print(f'{uid}|{txt}')
except: pass
" "$_safe_chat_id" <<< "$response" 2>/dev/null)

        while IFS='|' read -r uid cmd; do
            [ -z "$uid" ] && continue
            # Validate uid is numeric
            [[ "$uid" =~ ^[0-9]+$ ]] || continue
            LAST_UPDATE_ID=$((uid + 1))
            cmd="${cmd%% *}"  # strip arguments, match command only

            # Rate limiting
            local _now
            _now=$(date +%s)
            if [ $((_now - LAST_COMMAND_TIME)) -lt $COMMAND_COOLDOWN ]; then
                continue
            fi
            LAST_COMMAND_TIME=$_now

            case "$cmd" in
                /status)  send_message "$(build_report)" ;;
                /health)  send_message "$(/usr/local/bin/paqctl health 2>&1 | head -30)" ;;
                /restart) /usr/local/bin/paqctl restart 2>&1; send_message "🔄 Service restarted" ;;
                /stop)    /usr/local/bin/paqctl stop 2>&1; send_message "⏹ Service stopped" ;;
                /start)   /usr/local/bin/paqctl start 2>&1; send_message "▶️ Service started" ;;
                /version) send_message "📦 Version: ${PAQET_VERSION:-unknown} | paqctl: ${PAQCTL_VERSION:-unknown}" ;;
                /config|/info)
                    local _ip="${REMOTE_SERVER:-${LOCAL_IP:-$(curl -s --max-time 3 https://api.ipify.org 2>/dev/null || echo 'unknown')}}"
                    local _cfg="⚙️ *Connection Configuration*"$'\n\n'
                    if [ "$BACKEND" = "gfw-knocker" ]; then
                        _cfg+="🔹 *Backend:* GFW-knocker"$'\n'
                        _cfg+="🌐 *Server IP:* \`${GFK_SERVER_IP:-$_ip}\`"$'\n'
                        _cfg+="🔑 *Auth Code:* \`${GFK_AUTH_CODE:-not set}\`"$'\n'
                        _cfg+="🔌 *Port Mappings:* \`${GFK_PORT_MAPPINGS:-14000:443}\`"$'\n'
                        _cfg+="🧦 *Client SOCKS5:* \`127.0.0.1:${GFK_SOCKS_VIO_PORT:-14000}\`"
                    else
                        _cfg+="🔹 *Backend:* Paqet"$'\n'
                        _cfg+="🌐 *Server IP:* \`$_ip\`"$'\n'
                        _cfg+="🔌 *Port:* \`${LISTEN_PORT:-8443}\`"$'\n'
                        _cfg+="🔑 *Key:* \`${ENCRYPTION_KEY:-not set}\`"$'\n'
                        _cfg+="🧦 *Client SOCKS5:* \`127.0.0.1:${SOCKS_PORT:-1080}\`"
                    fi
                    send_message "$_cfg"
                    ;;
            esac
        done <<< "$cmds"
    fi
}

# Alert state
LAST_STATE="unknown"
LAST_REPORT=0
LAST_DAILY=0
LAST_WEEKLY=0
LAST_UPDATE_ID=0

# Initialize update offset
init_response=$(_tg_api_curl "getUpdates" \
    -X POST \
    --data-urlencode "offset=-1")
if command -v python3 &>/dev/null; then
    LAST_UPDATE_ID=$(python3 -c "
import json,sys
try:
    d=json.loads(sys.stdin.read())
    r=d.get('result',[])
    if r: print(r[-1]['update_id']+1)
    else: print(0)
except: print(0)
" <<< "$init_response" 2>/dev/null)
fi
LAST_UPDATE_ID=${LAST_UPDATE_ID:-0}

# Send startup notification
send_message "🚀 *Telegram notifications started*"$'\n'"Reports every ${TELEGRAM_INTERVAL}h | Alerts: ${TELEGRAM_ALERTS_ENABLED}"

while true; do
    # Reload settings periodically (safe parser, no code execution)
    _load_settings

    # Check commands from Telegram
    check_commands

    # Service state alerts
    current_state="stopped"
    is_running && current_state="running"

    if [ "$TELEGRAM_ALERTS_ENABLED" = "true" ]; then
        if [ "$LAST_STATE" = "running" ] && [ "$current_state" = "stopped" ]; then
            send_message "🚨 *ALERT:* ${BACKEND} service has stopped!"
        elif [ "$LAST_STATE" = "stopped" ] && [ "$current_state" = "running" ]; then
            send_message "✅ ${BACKEND} service is back up"
        fi

        # High CPU alert
        _pid=$(get_main_pid)
        if [ -n "$_pid" ]; then
            _cpu=$(ps -p "$_pid" -o %cpu= 2>/dev/null | awk '{printf "%.0f", $1}')
            if [ "${_cpu:-0}" -gt 80 ] 2>/dev/null; then
                send_message "⚠️ High CPU usage: ${_cpu}%"
            fi
        fi
    fi
    LAST_STATE="$current_state"

    # Periodic reports
    _now=$(date +%s)
    _interval_secs=$(( ${TELEGRAM_INTERVAL:-6} * 3600 ))
    if [ $((_now - LAST_REPORT)) -ge "$_interval_secs" ]; then
        send_message "$(build_report)"
        LAST_REPORT=$_now
    fi

    # Daily summary
    _hour=$(date +%H)
    _day_of_week=$(date +%u)
    if [ "$TELEGRAM_DAILY_SUMMARY" = "true" ] && [ "$_hour" = "$(printf '%02d' ${TELEGRAM_START_HOUR:-0})" ]; then
        if [ $((_now - LAST_DAILY)) -ge 86400 ]; then
            send_message "📅 *Daily Summary*"$'\n'"$(build_report)"
            LAST_DAILY=$_now
        fi
    fi

    # Weekly summary (Monday)
    if [ "$TELEGRAM_WEEKLY_SUMMARY" = "true" ] && [ "$_day_of_week" = "1" ] && [ "$_hour" = "$(printf '%02d' ${TELEGRAM_START_HOUR:-0})" ]; then
        if [ $((_now - LAST_WEEKLY)) -ge 604800 ]; then
            send_message "📆 *Weekly Summary*"$'\n'"$(build_report)"
            LAST_WEEKLY=$_now
        fi
    fi

    sleep 30
done
TGSCRIPT

    sed "s#REPLACE_ME_INSTALL_DIR#$INSTALL_DIR#g" "$_tmp" > "$_tmp.sed" && mv "$_tmp.sed" "$_tmp"
    if ! chmod +x "$_tmp"; then
        log_error "Failed to make Telegram script executable"
        rm -f "$_tmp"
        return 1
    fi
    if ! mv "$_tmp" "$script_path"; then
        log_error "Failed to install Telegram script"
        rm -f "$_tmp"
        return 1
    fi
}

setup_telegram_service() {
    telegram_generate_notify_script

    if command -v systemctl &>/dev/null && [ -d /run/systemd/system ]; then
        cat > /etc/systemd/system/paqctl-telegram.service << EOF
[Unit]
Description=paqctl Telegram Notification Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$(command -v bash) ${INSTALL_DIR}/paqctl-telegram.sh
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload 2>/dev/null || true
        systemctl enable paqctl-telegram.service 2>/dev/null || true
        systemctl start paqctl-telegram.service 2>/dev/null || true
        log_success "Telegram service started"
    else
        log_warn "Systemd not available. Run the Telegram daemon manually:"
        log_info "  nohup bash $INSTALL_DIR/paqctl-telegram.sh &"
    fi
}

stop_telegram_service() {
    if command -v systemctl &>/dev/null && [ -d /run/systemd/system ]; then
        systemctl stop paqctl-telegram.service 2>/dev/null || true
        systemctl disable paqctl-telegram.service 2>/dev/null || true
    fi
    pkill -f "paqctl-telegram.sh" 2>/dev/null || true
    log_success "Telegram service stopped"
}

show_telegram_menu() {
    local redraw=true
    while true; do
        if [ "$redraw" = true ]; then
            clear
            echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
            echo -e "${BOLD}  TELEGRAM NOTIFICATIONS${NC}"
            echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
            echo ""

            if [ "$TELEGRAM_ENABLED" = "true" ]; then
                echo -e "  Status: ${GREEN}Enabled${NC}"
                if command -v systemctl &>/dev/null && systemctl is-active paqctl-telegram.service &>/dev/null; then
                    echo -e "  Service: ${GREEN}Running${NC}"
                else
                    echo -e "  Service: ${RED}Stopped${NC}"
                fi
            else
                echo -e "  Status: ${DIM}Disabled${NC}"
            fi

            echo ""
            echo "  1. Setup / Change bot"
            echo "  2. Test notification"
            echo "  3. Enable & start service"
            echo "  4. Disable & stop service"
            echo "  5. Set check interval (currently: ${TELEGRAM_INTERVAL}h)"
            echo "  6. Set server label (currently: ${TELEGRAM_SERVER_LABEL:-hostname})"
            echo "  7. Toggle alerts (currently: ${TELEGRAM_ALERTS_ENABLED})"
            echo "  b. Back"
            echo ""
            redraw=false
        fi

        read -p "  Choice: " tg_choice < /dev/tty || break
        case "$tg_choice" in
            1)
                echo ""
                echo -e "${BOLD}Telegram Bot Setup${NC}"
                echo ""
                echo "  1. Open Telegram and message @BotFather"
                echo "  2. Send /newbot and follow the steps"
                echo "  3. Copy the bot token"
                echo ""
                read -p "  Enter bot token: " input < /dev/tty || true
                if [ -n "$input" ]; then
                    TELEGRAM_BOT_TOKEN="$input"
                    echo ""
                    echo "  Now send any message to your bot in Telegram..."
                    echo ""
                    for _i in $(seq 15 -1 1); do
                        printf "\r  Waiting: %2ds " "$_i"
                        sleep 1
                    done
                    printf "\r                    \r"
                    if telegram_get_chat_id; then
                        log_success "Chat ID detected: $TELEGRAM_CHAT_ID"
                        # Save
                        _safe_update_setting "TELEGRAM_BOT_TOKEN" "$TELEGRAM_BOT_TOKEN" "$INSTALL_DIR/settings.conf"
                        _safe_update_setting "TELEGRAM_CHAT_ID" "$TELEGRAM_CHAT_ID" "$INSTALL_DIR/settings.conf"
                    else
                        log_error "Could not detect chat ID. Make sure you sent a message to the bot."
                        echo ""
                        read -p "  Enter chat ID manually (or press Enter to cancel): " input < /dev/tty || true
                        if [ -n "$input" ]; then
                            TELEGRAM_CHAT_ID="$input"
                            _safe_update_setting "TELEGRAM_BOT_TOKEN" "$TELEGRAM_BOT_TOKEN" "$INSTALL_DIR/settings.conf"
                            _safe_update_setting "TELEGRAM_CHAT_ID" "$TELEGRAM_CHAT_ID" "$INSTALL_DIR/settings.conf"
                        fi
                    fi
                fi
                redraw=true
                ;;
            2)
                if [ -z "$TELEGRAM_BOT_TOKEN" ] || [ -z "$TELEGRAM_CHAT_ID" ]; then
                    log_error "Bot not configured. Run setup first."
                else
                    if telegram_test_message; then
                        log_success "Test message sent!"
                    else
                        log_error "Failed to send. Check token and chat ID."
                    fi
                fi
                read -n 1 -s -r -p "  Press any key..." < /dev/tty || true
                redraw=true
                ;;
            3)
                if [ -z "$TELEGRAM_BOT_TOKEN" ] || [ -z "$TELEGRAM_CHAT_ID" ]; then
                    log_error "Bot not configured. Run setup first."
                else
                    TELEGRAM_ENABLED=true
                    _safe_update_setting "TELEGRAM_ENABLED" "true" "$INSTALL_DIR/settings.conf"
                    setup_telegram_service
                fi
                read -n 1 -s -r -p "  Press any key..." < /dev/tty || true
                redraw=true
                ;;
            4)
                TELEGRAM_ENABLED=false
                _safe_update_setting "TELEGRAM_ENABLED" "false" "$INSTALL_DIR/settings.conf"
                stop_telegram_service
                read -n 1 -s -r -p "  Press any key..." < /dev/tty || true
                redraw=true
                ;;
            5)
                echo ""
                read -p "  Check interval in hours [1-24]: " input < /dev/tty || true
                if [[ "$input" =~ ^[0-9]+$ ]] && [ "$input" -ge 1 ] && [ "$input" -le 24 ]; then
                    TELEGRAM_INTERVAL="$input"
                    _safe_update_setting "TELEGRAM_INTERVAL" "$input" "$INSTALL_DIR/settings.conf"
                    log_success "Interval set to ${input}h"
                    # Restart service if running
                    if command -v systemctl &>/dev/null && systemctl is-active paqctl-telegram.service &>/dev/null; then
                        telegram_generate_notify_script
                        systemctl restart paqctl-telegram.service 2>/dev/null || true
                    fi
                else
                    log_warn "Invalid value"
                fi
                redraw=true
                ;;
            6)
                echo ""
                read -p "  Server label: " input < /dev/tty || true
                if [ -n "$input" ]; then
                    TELEGRAM_SERVER_LABEL="$input"
                    _safe_update_setting "TELEGRAM_SERVER_LABEL" "$input" "$INSTALL_DIR/settings.conf"
                    log_success "Label set to: $input"
                fi
                redraw=true
                ;;
            7)
                if [ "$TELEGRAM_ALERTS_ENABLED" = "true" ]; then
                    TELEGRAM_ALERTS_ENABLED=false
                else
                    TELEGRAM_ALERTS_ENABLED=true
                fi
                _safe_update_setting "TELEGRAM_ALERTS_ENABLED" "$TELEGRAM_ALERTS_ENABLED" "$INSTALL_DIR/settings.conf"
                log_info "Alerts: $TELEGRAM_ALERTS_ENABLED"
                redraw=true
                ;;
            b|B) return ;;
            "") ;;
            *) echo -e "  ${RED}Invalid choice${NC}" ;;
        esac
    done
}
