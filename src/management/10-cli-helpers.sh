#═══════════════════════════════════════════════════════════════════════
# CLI helpers: prompts, JSON, locking, backend detection
#═══════════════════════════════════════════════════════════════════════

# True when a terminal is available for interactive prompts
_has_tty() { { : < /dev/tty; } 2>/dev/null; }

# _confirm "Question?"  -> 0 on yes. Honours -y/--yes; fails safely without a terminal.
_confirm() {
    [ "$ASSUME_YES" = true ] && return 0
    if ! _has_tty; then
        log_error "Confirmation required but no terminal is available. Re-run with -y to confirm."
        return 1
    fi
    local _reply
    read -r -p "  $1 [y/N]: " _reply < /dev/tty || return 1
    [[ "$_reply" =~ ^[Yy]$ ]]
}

_json_str() {
    local s="$1"
    s="${s//\\/\\\\}"; s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"; s="${s//$'\r'/\\r}"; s="${s//$'\t'/\\t}"
    printf '"%s"' "$s"
}
_json_bool() { if [ "$1" = true ]; then printf 'true'; else printf 'false'; fi; }
_json_num() { if [[ "$1" =~ ^[0-9]+$ ]]; then printf '%s' "$1"; else printf 'null'; fi; }

# Mutual exclusion between paqctl invocations (e.g. watchdog vs. update).
# Uses an atomic mkdir instead of flock so background daemons started by a
# locked command never inherit (and keep holding) the lock.
_PAQCTL_LOCK_DIR="/run/paqctl.lock"
[ -d /run ] && [ -w /run ] || _PAQCTL_LOCK_DIR="$INSTALL_DIR/.lock"
_PAQCTL_LOCK_HELD=false
_acquire_lock() {
    local mode="${1:-wait}" waited=0 empty_pid=0 _pid
    [ "$_PAQCTL_LOCK_HELD" = true ] && return 0
    while ! mkdir "$_PAQCTL_LOCK_DIR" 2>/dev/null; do
        _pid=$(cat "$_PAQCTL_LOCK_DIR/pid" 2>/dev/null || true)
        if [ -n "$_pid" ] && ! kill -0 "$_pid" 2>/dev/null; then
            rm -rf "$_PAQCTL_LOCK_DIR" 2>/dev/null || true
            continue
        fi
        if [ -z "$_pid" ]; then
            empty_pid=$((empty_pid + 1))
            # Holder died between mkdir and writing its pid
            [ "$empty_pid" -ge 5 ] && { rm -rf "$_PAQCTL_LOCK_DIR" 2>/dev/null || true; continue; }
        fi
        [ "$mode" = "nowait" ] && return 1
        [ "$waited" -eq 0 ] && log_info "Another paqctl command is running (pid ${_pid:-?}); waiting for it to finish..."
        sleep 1
        waited=$((waited + 1))
        if [ "$waited" -ge 180 ]; then
            log_error "Timed out waiting for another paqctl command. If none is running, remove $_PAQCTL_LOCK_DIR"
            return 1
        fi
    done
    echo "$$" > "$_PAQCTL_LOCK_DIR/pid"
    _PAQCTL_LOCK_HELD=true
    trap '_release_lock' EXIT
}
_release_lock() {
    [ "$_PAQCTL_LOCK_HELD" = true ] || return 0
    [ "$(cat "$_PAQCTL_LOCK_DIR/pid" 2>/dev/null)" = "$$" ] && rm -rf "$_PAQCTL_LOCK_DIR" 2>/dev/null
    _PAQCTL_LOCK_HELD=false
}

_paqet_installed() { [ -f "$INSTALL_DIR/bin/paqet" ]; }
_gfk_installed() {
    if [ "$ROLE" = "server" ]; then
        [ -d "$GFK_DIR" ] && [ -f "$GFK_DIR/quic_server.py" ]
    else
        [ -d "$GFK_DIR" ] && [ -f "$GFK_DIR/quic_client.py" ]
    fi
}

# Local SOCKS5 port a GFK client exposes
_gfk_client_socks_port() {
    if [ -n "${GFK_SOCKS_VIO_PORT:-}" ]; then
        echo "$GFK_SOCKS_VIO_PORT"
    else
        echo "${GFK_PORT_MAPPINGS:-14000:443}" | cut -d, -f1 | cut -d: -f1
    fi
}

# Write config.yaml atomically from current settings (never leaves a half-written file)
_write_paqet_config() {
    local target="${1:-$INSTALL_DIR/config.yaml}" tmp
    tmp=$(mktemp "${target}.XXXXXXXX") || { log_error "Failed to create temp file"; return 1; }
    chmod 600 "$tmp" 2>/dev/null
    if ! (umask 077; generate_paqet_yaml "$tmp"); then
        rm -f "$tmp"; log_error "Failed to generate config.yaml"; return 1
    fi
    if ! mv -f "$tmp" "$target"; then
        rm -f "$tmp"; log_error "Failed to write $target"; return 1
    fi
    chmod 600 "$target" 2>/dev/null
    return 0
}

# Used by the watchdog; no-op unless Telegram is configured
send_telegram_alert() {
    [ "${TELEGRAM_ENABLED:-false}" = "true" ] || return 0
    telegram_send_message "$1"
}

# Which init system manages paqctl: systemd | openrc | sysv (returns 1 if none)
_init_system() {
    if command -v systemctl &>/dev/null && [ -d /run/systemd/system ]; then
        echo systemd
    elif command -v rc-update &>/dev/null && [ -f /etc/init.d/paqctl ]; then
        echo openrc
    elif [ -f /etc/init.d/paqctl ]; then
        echo sysv
    else
        return 1
    fi
}

_boot_enabled() {
    case "$(_init_system 2>/dev/null)" in
        systemd) systemctl is-enabled paqctl.service &>/dev/null ;;
        openrc)  rc-update show default 2>/dev/null | grep -qw paqctl ;;
        sysv)    ls /etc/rc[2345].d/S*paqctl &>/dev/null ;;
        *)       return 1 ;;
    esac
}

# _set_boot enable|disable
_set_boot() {
    local action="$1" init rc=1
    init=$(_init_system) || { log_error "No supported init system found (systemd, OpenRC or SysVinit with /etc/init.d/paqctl)"; return 1; }
    case "$init:$action" in
        systemd:enable)  systemctl enable paqctl.service &>/dev/null && rc=0 ;;
        systemd:disable) systemctl disable paqctl.service &>/dev/null && rc=0 ;;
        openrc:enable)   rc-update add paqctl default &>/dev/null && rc=0 ;;
        openrc:disable)  rc-update del paqctl default &>/dev/null && rc=0 ;;
        sysv:enable)
            if command -v update-rc.d &>/dev/null; then
                { update-rc.d paqctl defaults && update-rc.d paqctl enable; } &>/dev/null && rc=0
            elif command -v chkconfig &>/dev/null; then
                { chkconfig --add paqctl; chkconfig paqctl on; } &>/dev/null && rc=0
            fi ;;
        sysv:disable)
            if command -v update-rc.d &>/dev/null; then
                update-rc.d paqctl disable &>/dev/null && rc=0
            elif command -v chkconfig &>/dev/null; then
                chkconfig paqctl off &>/dev/null && rc=0
            fi ;;
        *) log_error "Unknown boot action: $action"; return 2 ;;
    esac
    if [ "$rc" -ne 0 ]; then
        log_error "Failed to ${action} auto-start ($init)"
        return 1
    fi
    if [ "$action" = "enable" ]; then
        log_success "Auto-start on boot enabled ($init)"
    else
        log_success "Auto-start on boot disabled ($init)"
    fi
}

# Safe sed: escape replacement string to prevent metachar injection
_sed_escape() { printf '%s\n' "$1" | sed 's/[&/\]/\\&/g'; }
_safe_update_setting() {
    local key="$1" value="$2" file="$3"
    [ ! -f "$file" ] && touch "$file" 2>/dev/null
    if grep -q "^${key}=" "$file" 2>/dev/null; then
        local escaped_value
        escaped_value=$(_sed_escape "$value")
        sed "s/^${key}=.*/${key}=\"${escaped_value}\"/" "$file" > "$file.tmp" 2>/dev/null && mv "$file.tmp" "$file" || true
    else
        echo "${key}=\"${value}\"" >> "$file" 2>/dev/null || true
    fi
}
