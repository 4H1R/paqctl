#═══════════════════════════════════════════════════════════════════════
# Diagnostics, Monitoring, Security & Maintenance
#═══════════════════════════════════════════════════════════════════════

show_active_clients() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  ACTIVE CLIENTS & CONNECTION MONITOR${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    _load_settings
    local port="${LISTEN_PORT:-8443}"
    [ "$BACKEND" = "gfw-knocker" ] && port="${GFK_QUIC_PORT:-25000}"
    echo -e "  ${BOLD}Listening Port:${NC} $port | ${BOLD}Role:${NC} ${ROLE:-unknown}"
    echo ""
    if command -v ss &>/dev/null; then
        echo -e "  ${YELLOW}Active Connections (ss):${NC}"
        ss -tu state established "( sport = :$port or dport = :$port )" 2>/dev/null | head -30 || true
        local count=$(ss -tu state established "( sport = :$port or dport = :$port )" 2>/dev/null | grep -v "Netid" | wc -l 2>/dev/null || echo "0")
        echo ""
        echo -e "  ${GREEN}Total Established Tunnel Connections:${NC} ${BOLD}$count${NC}"
    elif command -v netstat &>/dev/null; then
        echo -e "  ${YELLOW}Active Connections (netstat):${NC}"
        netstat -tun 2>/dev/null | grep ":$port " | head -30 || true
        local count=$(netstat -tun 2>/dev/null | grep ":$port " | grep "ESTABLISHED" | wc -l 2>/dev/null || echo "0")
        echo ""
        echo -e "  ${GREEN}Total Established Tunnel Connections:${NC} ${BOLD}$count${NC}"
    else
        log_warn "Neither 'ss' nor 'netstat' found on this system."
    fi
    echo ""
    if [ "$ROLE" = "server" ] && command -v ss &>/dev/null; then
        echo -e "  ${YELLOW}Unique Client IP Addresses:${NC}"
        ss -tn state established "( sport = :$port )" 2>/dev/null | awk '{print $5}' | cut -d: -f1 | grep -v "Address" | grep -v "^$" | sort -u | head -20 || true
        echo ""
    fi
}

run_speedtest() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  SERVER SPEED & BANDWIDTH TEST${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    if command -v speedtest-cli &>/dev/null; then
        log_info "Running speedtest-cli..."
        speedtest-cli --simple 2>/dev/null || speedtest-cli 2>/dev/null || log_warn "speedtest-cli encountered an error."
    elif command -v speedtest &>/dev/null; then
        log_info "Running Ookla speedtest..."
        speedtest 2>/dev/null || log_warn "Ookla speedtest encountered an error."
    else
        log_info "Testing download speed using Cloudflare benchmark..."
        if command -v curl &>/dev/null; then
            curl -o /dev/null --progress-bar -w "  Download Speed: %{speed_download} bytes/sec (Time: %{time_total}s)\n" https://speed.cloudflare.com/__down?bytes=50000000 2>/dev/null || \
            curl -o /dev/null --progress-bar https://speed.cloudflare.com/__down?bytes=25000000 2>/dev/null || \
            log_warn "Speedtest failed. You can install speedtest-cli for detailed metrics: sudo apt install speedtest-cli"
        else
            log_warn "curl not found. Cannot perform speed test."
        fi
    fi
    echo ""
}

check_proxy_routing() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  DNS LEAK & PROXY ROUTING VERIFICATION${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    _load_settings
    local socks_port="${SOCKS_PORT:-1080}"
    [ "$BACKEND" = "gfw-knocker" ] && socks_port="${GFK_SOCKS_VIO_PORT:-14000}"
    
    echo -e "  ${BOLD}1. Checking Direct Public IP (ISP):${NC}"
    local direct_ip=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null || echo "failed")
    echo -e "     Direct IP: ${YELLOW}${direct_ip}${NC}"
    echo ""
    
    echo -e "  ${BOLD}2. Checking Proxy Tunnel IP (via SOCKS5 127.0.0.1:$socks_port):${NC}"
    if command -v curl &>/dev/null; then
        local proxy_ip=$(curl -s --max-time 8 --socks5-hostname "127.0.0.1:$socks_port" https://api.ipify.org 2>/dev/null || echo "failed/unreachable")
        if [ "$proxy_ip" = "failed/unreachable" ]; then
            echo -e "     Proxy IP:  ${RED}${proxy_ip}${NC}"
            log_warn "Proxy tunnel is not responding on port $socks_port. Is the client running?"
        elif [ "$proxy_ip" = "$direct_ip" ] && [ "$direct_ip" != "failed" ]; then
            echo -e "     Proxy IP:  ${YELLOW}${proxy_ip}${NC}"
            log_warn "Proxy IP matches direct IP! Notice: If you are running this on the server itself, this is normal."
        else
            echo -e "     Proxy IP:  ${GREEN}${proxy_ip}${NC}"
            log_success "Proxy routing verified! Traffic is tunneling properly."
        fi
    else
        log_warn "curl not found."
    fi
    echo ""
    echo -e "  ${BOLD}3. Checking DNS Resolution via Proxy:${NC}"
    local dns_check=$(curl -s --max-time 8 --socks5-hostname "127.0.0.1:$socks_port" https://edns.ip-api.com/json 2>/dev/null || echo "")
    if [ -n "$dns_check" ]; then
        local dns_ip=$(echo "$dns_check" | grep -o '"dns":{"ip":"[^"]*' 2>/dev/null | cut -d'"' -f5 2>/dev/null || echo "resolved")
        echo -e "     DNS Resolver IP via tunnel: ${GREEN}${dns_ip:-resolved}${NC}"
        log_success "No DNS leaks detected via socks5-hostname resolution!"
    else
        echo -e "     ${DIM}DNS leak check endpoint unreachable or timed out.${NC}"
    fi
    echo ""
}

#───────────────────────────────────────────────────────────────────────
# IP bans: tagged "paqctl-ban", tracked in $INSTALL_DIR/banned_ips and
# re-applied by _apply_firewall (service start / boot).
#───────────────────────────────────────────────────────────────────────
_BAN_FILE="$INSTALL_DIR/banned_ips"
_BAN_TAG="paqctl-ban"

# _parse_ban_target "1.2.3.4" -> "4 1.2.3.4";  "2001:db8::/32" -> "6 2001:db8::/32"
_parse_ban_target() {
    local t="$1" addr prefix=""
    [ -n "$t" ] && [ ${#t} -le 64 ] || return 1
    addr="${t%%/*}"
    if [[ "$t" == */* ]]; then
        prefix="${t#*/}"
        [[ "$prefix" =~ ^[0-9]{1,3}$ ]] || return 1
    fi
    if _validate_ip "$addr"; then
        [ -z "$prefix" ] || [ "$prefix" -le 32 ] || return 1
        echo "4 $t"
        return 0
    fi
    if [[ "$addr" == *:*:* ]] && [[ "$addr" =~ ^[0-9a-fA-F:]+$ ]] && [[ "$addr" != *:::* ]]; then
        local without="${addr//::/}"
        [ $(( (${#addr} - ${#without}) / 2 )) -le 1 ] || return 1
        local g IFS=':'
        for g in $addr; do
            [ ${#g} -le 4 ] || return 1
        done
        [ -z "$prefix" ] || [ "$prefix" -le 128 ] || return 1
        echo "6 $t"
        return 0
    fi
    return 1
}

# _ban_rule add|del|check FAMILY(4|6) ADDR
_ban_rule() {
    local op="$1" fam="$2" addr="$3"
    if _is_firewalld_active; then
        local ipv="ipv${fam}" rc=1
        local -a rule=("$ipv" filter INPUT 0 -s "$addr" -m comment --comment "$_BAN_TAG" -j DROP)
        case "$op" in
            check) firewall-cmd --direct --query-rule "${rule[@]}" &>/dev/null; return ;;
            add)
                firewall-cmd --direct --query-rule "${rule[@]}" &>/dev/null || \
                    firewall-cmd --direct --add-rule "${rule[@]}" &>/dev/null || return 1
                firewall-cmd --permanent --direct --add-rule "${rule[@]}" &>/dev/null || true
                return 0 ;;
            del)
                firewall-cmd --direct --remove-rule "${rule[@]}" &>/dev/null && rc=0
                firewall-cmd --permanent --direct --remove-rule "${rule[@]}" &>/dev/null || true
                # Untagged rule from older paqctl versions
                firewall-cmd --direct --remove-rule "$ipv" filter INPUT 0 -s "$addr" -j DROP &>/dev/null && rc=0
                return $rc ;;
        esac
        return 1
    fi
    local ipt=iptables
    [ "$fam" = "6" ] && ipt=ip6tables
    command -v "$ipt" &>/dev/null || return 1
    case "$op" in
        check) "$ipt" -C INPUT -s "$addr" -m comment --comment "$_BAN_TAG" -j DROP 2>/dev/null ;;
        add)
            "$ipt" -C INPUT -s "$addr" -m comment --comment "$_BAN_TAG" -j DROP 2>/dev/null || \
                "$ipt" -I INPUT 1 -s "$addr" -m comment --comment "$_BAN_TAG" -j DROP 2>/dev/null ;;
        del)
            local rc=1 n=0
            while [ $n -lt 20 ] && "$ipt" -D INPUT -s "$addr" -m comment --comment "$_BAN_TAG" -j DROP 2>/dev/null; do rc=0; n=$((n + 1)); done
            # Untagged rule from older paqctl versions
            n=0
            while [ $n -lt 20 ] && "$ipt" -D INPUT -s "$addr" -j DROP 2>/dev/null; do rc=0; n=$((n + 1)); done
            return $rc ;;
        *) return 1 ;;
    esac
}

_banlist_has() { [ -f "$_BAN_FILE" ] && grep -qxF -- "$1" "$_BAN_FILE"; }
_banlist_add() {
    _banlist_has "$1" && return 0
    (umask 077; echo "$1" >> "$_BAN_FILE")
}
_banlist_remove() {
    [ -f "$_BAN_FILE" ] || return 0
    local tmp
    tmp=$(mktemp "${_BAN_FILE}.XXXXXXXX") || return 1
    grep -vxF -- "$1" "$_BAN_FILE" > "$tmp" || true
    mv -f "$tmp" "$_BAN_FILE" && chmod 600 "$_BAN_FILE" 2>/dev/null
}

# Re-apply every tracked ban (idempotent). Called from _apply_firewall.
_reapply_bans() {
    [ -s "$_BAN_FILE" ] || return 0
    local t parsed
    while IFS= read -r t; do
        [ -n "$t" ] || continue
        parsed=$(_parse_ban_target "$t") || continue
        _ban_rule add "${parsed%% *}" "${parsed#* }" || true
    done < "$_BAN_FILE"
}

_ban_list() {
    local t parsed active first=true
    if [ "$JSON_OUTPUT" = true ]; then
        printf '['
        if [ -s "$_BAN_FILE" ]; then
            while IFS= read -r t; do
                [ -n "$t" ] || continue
                parsed=$(_parse_ban_target "$t") || continue
                active=false
                _ban_rule check "${parsed%% *}" "${parsed#* }" && active=true
                [ "$first" = true ] || printf ','
                first=false
                printf '{"target":%s,"active":%s}' "$(_json_str "$t")" "$(_json_bool "$active")"
            done < "$_BAN_FILE"
        fi
        printf ']\n'
        return 0
    fi
    echo ""
    echo -e "  ${BOLD}IPs banned by paqctl:${NC}"
    if [ ! -s "$_BAN_FILE" ]; then
        echo "  (none)"
    else
        while IFS= read -r t; do
            [ -n "$t" ] || continue
            parsed=$(_parse_ban_target "$t") || { echo -e "  ${YELLOW}?${NC} $t ${DIM}(invalid entry, ignored)${NC}"; continue; }
            if _ban_rule check "${parsed%% *}" "${parsed#* }"; then
                echo -e "  ${GREEN}●${NC} $t"
            else
                echo -e "  ${RED}○${NC} $t ${DIM}(not active - re-apply with: sudo paqctl firewall → Apply, or restart)${NC}"
            fi
        done < "$_BAN_FILE"
    fi
    echo ""
    echo -e "  ${DIM}Only bans made with paqctl are listed. Bans from older paqctl versions can still be removed with: paqctl unban <ip>${NC}"
    echo ""
}

# Best-effort address of the SSH session running this command
_current_ssh_ip() {
    local ip="${SSH_CLIENT%% *}"
    [ -z "$ip" ] && ip="${SSH_CONNECTION%% *}"
    [ -z "$ip" ] && ip=$(who am i 2>/dev/null | sed -n 's/.*(\([^)]*\)).*/\1/p')
    echo "$ip"
}

# manage_ip_ban [ban|unban|list] [TARGET]   (no arguments: interactive menu)
manage_ip_ban() {
    local action="${1:-}" target="${2:-}"

    if [ -z "$action" ]; then
        if ! _has_tty; then
            log_error "Usage: paqctl ban <IP[/CIDR]> | paqctl unban <IP[/CIDR]> | paqctl ban list"
            return 2
        fi
        _print_section "IP BAN MANAGER"
        echo "  1. Ban an IP address or range (drop all its traffic)"
        echo "  2. Unban an IP address or range"
        echo "  3. List banned IPs"
        echo "  b. Back"
        echo ""
        local ban_choice
        read -r -p "  Choice: " ban_choice < /dev/tty || return 0
        case "$ban_choice" in
            1) read -r -p "  IP or CIDR to ban: " target < /dev/tty || return 0; [ -z "$target" ] && return 0; action="ban" ;;
            2) read -r -p "  IP or CIDR to unban: " target < /dev/tty || return 0; [ -z "$target" ] && return 0; action="unban" ;;
            3) action="list" ;;
            *) return 0 ;;
        esac
        local _rc=0
        manage_ip_ban "$action" "$target" || _rc=$?
        read -n 1 -s -r -p "  Press any key..." < /dev/tty || true
        return $_rc
    fi

    if [ "$action" = "list" ] || { [ "$action" = "ban" ] && [ "$target" = "list" ]; }; then
        _ban_list
        return 0
    fi

    if [ -z "$target" ]; then
        log_error "Usage: paqctl $action <IP[/CIDR]>"
        return 2
    fi
    local parsed
    if ! parsed=$(_parse_ban_target "$target"); then
        log_error "Invalid IP address or CIDR range: $target"
        return 2
    fi
    local fam="${parsed%% *}" addr="${parsed#* }"
    if ! _is_firewalld_active; then
        local ipt=iptables
        [ "$fam" = "6" ] && ipt=ip6tables
        if ! command -v "$ipt" &>/dev/null; then
            log_error "$ipt not found; cannot manage bans"
            return 1
        fi
    fi

    case "$action" in
        ban)
            local me
            me=$(_current_ssh_ip)
            if [ -n "$me" ] && [ "$me" = "$addr" ]; then
                log_warn "$addr is the address of your current SSH session - banning it will lock you out."
                _confirm "Ban it anyway?" || { log_info "Cancelled"; return 1; }
            fi
            if _ban_rule check "$fam" "$addr"; then
                _banlist_add "$addr"
                log_info "$addr is already banned"
                return 0
            fi
            if _ban_rule add "$fam" "$addr"; then
                _banlist_add "$addr"
                log_success "Banned $addr (persists across restarts and reboots)"
                return 0
            fi
            log_error "Failed to add a firewall rule for $addr"
            return 1
            ;;
        unban)
            local was_listed=false
            _banlist_has "$addr" && was_listed=true
            _banlist_remove "$addr"
            if _ban_rule del "$fam" "$addr"; then
                log_success "Unbanned $addr"
                return 0
            fi
            if [ "$was_listed" = true ]; then
                log_success "Unbanned $addr (its rule was not active)"
                return 0
            fi
            log_warn "$addr was not banned"
            return 1
            ;;
        *)
            log_error "Unknown ban action: $action"
            return 2
            ;;
    esac
}

#───────────────────────────────────────────────────────────────────────
# Credential rotation
#───────────────────────────────────────────────────────────────────────
rotate_key() {
    _print_section "ENCRYPTION KEY / AUTH CODE ROTATION"
    _load_settings
    if [ "$ROLE" != "server" ]; then
        log_warn "Key rotation is done on the server. On clients, import the new string: sudo paqctl import '<string>'"
        return 1
    fi
    echo -e "  ${YELLOW}⚠️ WARNING: Rotating the encryption key / auth code will disconnect${NC}"
    echo -e "  ${YELLOW}   all connected clients until they import the new config string!${NC}"
    echo ""
    _confirm "Rotate credentials now?" || { log_info "Rotation cancelled."; return 1; }

    local bk
    if ! bk=$(backup_config --quiet --label pre-rotate); then
        log_error "Could not back up the current configuration; not rotating."
        return 1
    fi
    log_info "Previous credentials backed up to: $bk"

    local was_running=false
    is_running && was_running=true

    local new_secret label
    if [ "$BACKEND" = "gfw-knocker" ]; then
        label="GFK Auth Code"
        new_secret=$(openssl rand -hex 8 2>/dev/null || od -An -N8 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n')
        [ -n "$new_secret" ] || { log_error "Could not generate a new auth code"; return 1; }
        GFK_AUTH_CODE="$new_secret"
        save_settings || { log_error "Failed to save settings"; return 1; }
        generate_gfk_config || { log_error "Failed to regenerate GFK config. Roll back with: sudo paqctl restore $(basename "$bk")"; return 1; }
    else
        label="Paqet Encryption Key"
        new_secret=$("$INSTALL_DIR/bin/paqet" secret 2>/dev/null || true)
        [ -n "$new_secret" ] || new_secret=$(openssl rand -hex 32 2>/dev/null || true)
        [ -n "$new_secret" ] || { log_error "Could not generate a new key"; return 1; }
        ENCRYPTION_KEY="$new_secret"
        save_settings || { log_error "Failed to save settings"; return 1; }
        # config.yaml nests the key under transport.kcp, so regenerate it rather than editing in place
        _write_paqet_config || { log_error "Failed to update config.yaml. Roll back with: sudo paqctl restore $(basename "$bk")"; return 1; }
    fi

    if [ "$was_running" = true ]; then
        if ! restart_paqet; then
            log_error "The service did not come back up with the new credentials."
            log_error "Roll back with: sudo paqctl restore $(basename "$bk")"
            return 1
        fi
    else
        log_info "Service is not running; the new credentials apply on next start."
    fi

    log_success "${label} rotated"
    echo -e "  ${GREEN}${BOLD}New ${label}: ${new_secret}${NC}"
    local host uri
    if host=$(_export_host "") && uri=$(_build_export_uri "$host"); then
        echo ""
        echo -e "  ${BOLD}Give every client this new config string:${NC}"
        echo -e "  ${GREEN}${uri}${NC}"
        echo -e "  ${DIM}On each client: sudo paqctl import '<string>'${NC}"
    fi
    echo ""
}

#───────────────────────────────────────────────────────────────────────
# Cleanup (paqctl's own files only)
#───────────────────────────────────────────────────────────────────────
system_cleanup() {
    local do_journal=false a
    for a in "$@"; do
        case "$a" in
            --journal) do_journal=true ;;
            *) log_error "Unknown option for cleanup: $a"; echo "  Usage: paqctl cleanup [--journal]" >&2; return 2 ;;
        esac
    done
    _print_section "PAQCTL CLEANUP"

    # 1. Rotated / archived paqctl logs (the live log files are kept)
    local f n=0
    for f in /var/log/paqctl*.gz /var/log/paqctl*.old \
             /var/log/paqctl.log.[0-9]* /var/log/paqet-backend.log.[0-9]* /var/log/gfk-backend.log.[0-9]*; do
        [ -f "$f" ] || continue
        rm -f "$f" && n=$((n + 1))
    done
    log_success "Removed $n archived paqctl log file(s)"

    # 2. Leftover temp files from interrupted paqctl operations (older than 1 hour)
    local t=0
    t=$(find /tmp -maxdepth 1 \( -name 'paqctl-update-*' -o -name 'paqet-download-*' -o -name 'paqet-update-*' \
            -o -name 'paqet-extract-*' -o -name '99-paqctl-turbo.conf' -o -name '.tg_curl*' \) -mmin +60 -print 2>/dev/null | wc -l)
    find /tmp -maxdepth 1 \( -name 'paqctl-update-*' -o -name 'paqet-download-*' -o -name 'paqet-update-*' \
            -o -name 'paqet-extract-*' -o -name '99-paqctl-turbo.conf' -o -name '.tg_curl*' \) -mmin +60 \
            -exec rm -rf {} + 2>/dev/null || true
    local s=0
    if [ -d "$INSTALL_DIR" ]; then
        s=$(find "$INSTALL_DIR" "$GFK_DIR" -maxdepth 1 -type f \( -name 'settings.conf.????????' -o -name 'config.yaml.????????' \
                -o -name 'paqctl.????????' -o -name 'banned_ips.????????' -o -name 'parameters.py.????????' \) -mmin +60 -print 2>/dev/null | wc -l)
        find "$INSTALL_DIR" "$GFK_DIR" -maxdepth 1 -type f \( -name 'settings.conf.????????' -o -name 'config.yaml.????????' \
                -o -name 'paqctl.????????' -o -name 'banned_ips.????????' -o -name 'parameters.py.????????' \) -mmin +60 \
                -delete 2>/dev/null || true
    fi
    log_success "Removed $((t + s)) stale temp file(s)"

    # 3. Old backups
    local pruned
    pruned=$(_prune_backups)
    log_success "Removed ${pruned:-0} old backup(s) (keeping the newest ${PAQCTL_BACKUP_KEEP})"

    # 4. The systemd journal is shared by every service, so only touch it when asked
    if [ "$do_journal" != true ] && [ "$MENU_MODE" = true ] && _has_tty && command -v journalctl &>/dev/null; then
        echo ""
        echo -e "  ${DIM}The systemd journal holds logs for ALL services on this machine.${NC}"
        local _ans
        read -r -p "  Also vacuum journal entries older than 7 days? [y/N]: " _ans < /dev/tty || true
        [[ "$_ans" =~ ^[Yy]$ ]] && do_journal=true
    fi
    if [ "$do_journal" = true ]; then
        if command -v journalctl &>/dev/null; then
            journalctl --vacuum-time=7d 2>/dev/null || true
            log_success "Systemd journal vacuumed (entries older than 7 days, all services)"
        else
            log_warn "journalctl not found; skipping journal vacuum"
        fi
    elif command -v journalctl &>/dev/null; then
        echo -e "  ${DIM}Journal not touched (it is system-wide). Use 'paqctl cleanup --journal' to vacuum entries older than 7 days.${NC}"
    fi

    echo ""
    log_success "Cleanup completed"
    echo ""
}

#───────────────────────────────────────────────────────────────────────
# Config sharing (export / import)
#───────────────────────────────────────────────────────────────────────
_is_private_ipv4() {
    [[ "$1" =~ ^10\. ]] || [[ "$1" =~ ^192\.168\. ]] || [[ "$1" =~ ^127\. ]] || \
    [[ "$1" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]] || \
    [[ "$1" =~ ^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\. ]]
}

# Address clients should use: explicit override > configured > public lookup
_export_host() {
    local override="${1:-}" h=""
    if [ -n "$override" ]; then
        echo "$override"
        return 0
    fi
    [ "$BACKEND" = "gfw-knocker" ] && h="${GFK_SERVER_IP:-}"
    [ -z "$h" ] && h="${REMOTE_SERVER:-${LOCAL_IP:-}}"
    if [ -z "$h" ]; then
        log_info "Looking up this server's public IP via api.ipify.org (pass --ip to skip)..." >&2
        h=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null || true)
        [ -z "$h" ] && h=$(hostname -I 2>/dev/null | awk '{print $1}')
    fi
    [ -n "$h" ] || return 1
    echo "$h"
}

# Build paqet://... or gfk://... for the active backend
_build_export_uri() {
    local _ip="$1" raw
    if [ "$BACKEND" = "gfw-knocker" ]; then
        raw="gfk|${_ip}|${GFK_AUTH_CODE}|${GFK_PORT_MAPPINGS:-14000:443}|${GFK_SOCKS_VIO_PORT:-14000}"
        printf 'gfk://%s\n' "$(printf '%s' "$raw" | base64 | tr -d '\r\n')"
        return 0
    fi
    local port="${LISTEN_PORT:-8443}"
    if [[ "$_ip" =~ ^([0-9a-zA-Z\.\-_]+|\[[0-9a-fA-F:]+\]):([0-9]+)$ ]]; then
        port="${BASH_REMATCH[2]}"
        _ip="${BASH_REMATCH[1]}"
    fi
    local key="${ENCRYPTION_KEY:-}"
    if [ -z "$key" ] && [ -f "$INSTALL_DIR/config.yaml" ]; then
        key=$(grep -E '^[[:space:]]*key:' "$INSTALL_DIR/config.yaml" 2>/dev/null | head -1 | awk '{print $2}' | tr -d '"' || true)
    fi
    local _mtu="${KCP_MTU:-}"
    if [ -z "$_mtu" ] && [ -f "$INSTALL_DIR/config.yaml" ]; then
        _mtu=$(grep -E '^[[:space:]]*mtu:' "$INSTALL_DIR/config.yaml" 2>/dev/null | head -1 | awk '{print $2}' | tr -d '"' || true)
    fi
    _mtu="${_mtu:-1350}"
    raw="paqet|${_ip}|${port}|${key}|${SOCKS_PORT:-1080}|${ROUTING_MODE:-socks5}|${FORWARD_PORT:-14000}|${FORWARD_TARGET:-127.0.0.1:80}|${KCP_PROFILE:-standard}|${_mtu}"
    printf 'paqet://%s\n' "$(printf '%s' "$raw" | base64 | tr -d '\r\n')"
}

# export_config_string [--ip ADDR] [--qr]
export_config_string() {
    local override="" want_qr=false
    while [ $# -gt 0 ]; do
        case "$1" in
            --ip)
                [ -n "${2:-}" ] || { log_error "--ip needs an address"; return 2; }
                override="$2"; shift 2 ;;
            --ip=*) override="${1#--ip=}"; shift ;;
            --qr) want_qr=true; shift ;;
            *) log_error "Unknown option for export: $1"; echo "  Usage: paqctl export [--ip ADDR] [--qr] [--json]" >&2; return 2 ;;
        esac
    done
    if [ -n "$override" ]; then
        # Bare IPv6 -> [IPv6]
        if [[ "$override" =~ ^[0-9a-fA-F:]+$ ]] && [[ "$override" == *:*:* ]]; then
            override="[$override]"
        fi
        if ! [[ "$override" =~ ^[A-Za-z0-9.-]+$ ]] && ! [[ "$override" =~ ^\[[0-9a-fA-F:]+\]$ ]]; then
            log_error "Invalid --ip value: $override (use an IPv4 address, [IPv6] or hostname)"
            return 2
        fi
    fi

    _load_settings
    local host uri
    if ! host=$(_export_host "$override"); then
        log_error "Could not determine the server address. Pass it explicitly: paqctl export --ip <address>"
        return 1
    fi
    uri=$(_build_export_uri "$host") || return 1

    if [ "$JSON_OUTPUT" = true ]; then
        printf '{"backend":%s,"host":%s,"uri":%s}\n' "$(_json_str "$BACKEND")" "$(_json_str "$host")" "$(_json_str "$uri")"
        return 0
    fi

    _print_section "CONFIG EXPORT / STRING SHARING"
    local name="Paqet"
    [ "$BACKEND" = "gfw-knocker" ] && name="GFK"
    echo -e "  ${BOLD}Shareable ${name} Client String:${NC}"
    echo -e "  ${GREEN}${uri}${NC}"
    echo ""
    echo -e "  ${YELLOW}⚠ This string contains your encryption key / auth code. Treat it like a password${NC}"
    echo -e "  ${YELLOW}  and share it only over a private channel.${NC}"
    local bare="${host%%:*}"
    if _is_private_ipv4 "$bare"; then
        echo ""
        echo -e "  ${YELLOW}!${NC} ${bare} is a private/internal address. Clients outside this network need"
        echo -e "    the public one: ${BOLD}sudo paqctl export --ip <public-ip>${NC}"
    fi
    if [ "$want_qr" = true ]; then
        echo ""
        if command -v qrencode &>/dev/null; then
            qrencode -t ansiutf8 "$uri"
        else
            log_warn "qrencode is not installed (apt install qrencode | dnf install qrencode | apk add libqrencode-tools)"
        fi
    elif command -v qrencode &>/dev/null; then
        echo -e "  ${DIM}Tip: 'paqctl export --qr' shows this as a QR code.${NC}"
    fi
    echo ""
    echo -e "  ${DIM}On the client: sudo paqctl import '<string>'  (or 'Import Config' in the menu)${NC}"
    echo ""
}

_valid_hostport() { [[ "$1" =~ ^([A-Za-z0-9.-]+|\[[0-9a-fA-F:]+\]):([0-9]+)$ ]] && _validate_port "${BASH_REMATCH[2]}"; }
_valid_host() { [[ "$1" =~ ^[A-Za-z0-9.-]+$ ]] || [[ "$1" =~ ^\[[0-9a-fA-F:]+\]$ ]]; }

# import_config_string [STRING | -]
import_config_string() {
    local input_str="${1:-}"
    _print_section "CONFIG IMPORT FROM STRING"
    if [ "$input_str" = "-" ]; then
        IFS= read -r input_str || true
    elif [ -z "$input_str" ]; then
        if ! _has_tty; then
            log_error "No terminal. Usage: paqctl import <string>   or   paqctl import - < file"
            return 2
        fi
        read -r -p "  Paste config string (paqet://... or gfk://...): " input_str < /dev/tty || return 1
    fi
    input_str="${input_str//[[:space:]]/}"
    if [ -z "$input_str" ]; then
        log_error "Empty config string"
        return 1
    fi
    if [[ "$input_str" != *://* ]]; then
        log_error "Expected a string starting with paqet:// or gfk://"
        return 1
    fi

    local proto="${input_str%%://*}"
    local b64="${input_str#*://}"
    local decoded
    decoded=$(printf '%s' "$b64" | base64 -d 2>/dev/null || printf '%s' "$b64" | base64 -D 2>/dev/null || true)
    if [ -z "$decoded" ]; then
        log_error "Invalid or corrupted base64 config string."
        return 1
    fi

    _load_settings
    if [ "$ROLE" = "server" ]; then
        log_error "This machine is configured as a server; config strings are imported on clients."
        echo "  To turn it into a client, run: sudo paqctl config" >&2
        return 1
    fi

    if [ "$proto" = "paqet" ]; then
        local _p p1 p2 p3 p4 p5 p6 p7 p8 p9
        local _ip _port _key _socks _rmode _fport _ftgt _profile _mtu
        IFS='|' read -r _p p1 p2 p3 p4 p5 p6 p7 p8 p9 <<< "$decoded"
        if [ "$_p" != "paqet" ] || [ -z "$p1" ] || [ -z "$p2" ]; then
            log_error "Invalid paqet string format."
            return 1
        fi
        if [[ "$p1" =~ ^([0-9a-zA-Z\.\-_]+|\[[0-9a-fA-F:]+\]):([0-9]+)$ ]]; then
            # Combined format: paqet|IP:PORT|KEY|SOCKS|RMODE|FPORT|FTGT|PROF|MTU
            _ip="${BASH_REMATCH[1]}"; _port="${BASH_REMATCH[2]}"; _key="$p2"
            _socks="${p3:-1080}"; _rmode="${p4:-socks5}"; _fport="${p5:-14000}"
            _ftgt="${p6:-127.0.0.1:80}"; _profile="${p7:-standard}"; _mtu="${p8:-1350}"
        else
            # Separate format: paqet|IP|PORT|KEY|SOCKS|RMODE|FPORT|FTGT|PROF|MTU
            _ip="$p1"; _port="$p2"; _key="$p3"
            _socks="${p4:-1080}"; _rmode="${p5:-socks5}"; _fport="${p6:-14000}"
            _ftgt="${p7:-127.0.0.1:80}"; _profile="${p8:-standard}"; _mtu="${p9:-1350}"
        fi

        local bad=""
        _valid_host "$_ip" || bad="server address '$_ip'"
        [ -z "$bad" ] && ! _validate_port "$_port" && bad="port '$_port'"
        [ -z "$bad" ] && ! [[ "$_key" =~ ^[A-Za-z0-9+/=_-]{8,128}$ ]] && bad="encryption key"
        [ -z "$bad" ] && ! _validate_port "$_socks" && bad="SOCKS port '$_socks'"
        [ -z "$bad" ] && [ "$_rmode" != "socks5" ] && [ "$_rmode" != "forward" ] && bad="routing mode '$_rmode'"
        [ -z "$bad" ] && ! _validate_port "$_fport" && bad="forward port '$_fport'"
        [ -z "$bad" ] && ! _valid_hostport "$_ftgt" && bad="forward target '$_ftgt'"
        [ -z "$bad" ] && ! [[ "$_profile" =~ ^[A-Za-z0-9_-]{1,32}$ ]] && bad="profile '$_profile'"
        [ -z "$bad" ] && { ! [[ "$_mtu" =~ ^[0-9]+$ ]] || [ "$_mtu" -lt 500 ] || [ "$_mtu" -gt 9000 ]; } && bad="MTU '$_mtu'"
        if [ -n "$bad" ]; then
            log_error "Config string has an invalid ${bad}; nothing was changed."
            return 1
        fi

        local bk
        bk=$(backup_config --quiet --label pre-import 2>/dev/null) && log_info "Previous configuration backed up to: $bk"
        log_info "Importing Paqet Client Config (Server: $_ip:$_port)..."

        # Keep a lower local MTU so this link never overflows
        if [[ "${KCP_MTU:-}" =~ ^[0-9]+$ ]] && [ "$KCP_MTU" -gt 0 ] && [ "$KCP_MTU" -lt "$_mtu" ]; then
            log_info "Preserving local lower MTU (${KCP_MTU}) over imported server MTU (${_mtu}) to prevent local link overflow."
            _mtu="$KCP_MTU"
        fi

        REMOTE_SERVER="$_ip:$_port"; LISTEN_PORT="$_port"; ENCRYPTION_KEY="$_key"
        SOCKS_PORT="$_socks"; ROUTING_MODE="$_rmode"; FORWARD_PORT="$_fport"
        FORWARD_TARGET="$_ftgt"; KCP_PROFILE="$_profile"; KCP_MTU="$_mtu"

        if [ -z "$INTERFACE" ] || [ -z "$LOCAL_IP" ] || [ -z "$GATEWAY_MAC" ]; then
            detect_network
            [ -n "$DETECTED_IFACE" ] && INTERFACE="$DETECTED_IFACE"
            [ -n "$DETECTED_IP" ] && LOCAL_IP="$DETECTED_IP"
            [ -n "$DETECTED_GW_MAC" ] && GATEWAY_MAC="$DETECTED_GW_MAC"
        fi

        save_settings || { log_error "Failed to save settings"; return 1; }
        _write_paqet_config || return 1
        log_success "Paqet client configuration imported! Restarting service..."
    elif [ "$proto" = "gfk" ]; then
        local _p _ip _auth _map _socks
        IFS='|' read -r _p _ip _auth _map _socks <<< "$decoded"
        if [ "$_p" != "gfk" ] || [ -z "$_ip" ] || [ -z "$_auth" ]; then
            log_error "Invalid gfk string format."
            return 1
        fi
        local bad=""
        _validate_ip "$_ip" || bad="server address '$_ip' (GFK needs an IPv4 address)"
        [ -z "$bad" ] && ! [[ "$_auth" =~ ^[A-Za-z0-9_-]{4,128}$ ]] && bad="auth code"
        [ -z "$bad" ] && [ -n "$_map" ] && ! [[ "$_map" =~ ^[0-9]+:[0-9]+(,[0-9]+:[0-9]+)*$ ]] && bad="port mappings '$_map'"
        [ -z "$bad" ] && [ -n "$_socks" ] && ! _validate_port "$_socks" && bad="SOCKS port '$_socks'"
        if [ -n "$bad" ]; then
            log_error "Config string has an invalid ${bad}; nothing was changed."
            return 1
        fi

        local bk
        bk=$(backup_config --quiet --label pre-import 2>/dev/null) && log_info "Previous configuration backed up to: $bk"
        log_info "Importing GFK Client Config (Server: $_ip)..."
        GFK_SERVER_IP="$_ip"; GFK_AUTH_CODE="$_auth"
        [ -n "$_map" ] && GFK_PORT_MAPPINGS="$_map"
        [ -n "$_socks" ] && GFK_SOCKS_VIO_PORT="$_socks"
        save_settings || { log_error "Failed to save settings"; return 1; }
        generate_gfk_config 2>/dev/null || true
        log_success "GFK client configuration imported! Restarting service..."
    else
        log_error "Unknown protocol prefix: $proto (expected paqet:// or gfk://)"
        return 1
    fi

    local rc=0
    if is_running; then
        restart_paqet || rc=1
    else
        start_paqet || rc=1
    fi
    echo ""
    return $rc
}
