# shellcheck shell=bash
# Shared helpers used by both the installer and the management script.
# Included into both the installer and the management script by build.sh.

#═══════════════════════════════════════════════════════════════════════
# Input validation
#═══════════════════════════════════════════════════════════════════════

_validate_port() { [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }

_validate_ip() {
    [[ "$1" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || return 1
    local IFS='.'; set -- $1
    [ "$1" -le 255 ] && [ "$2" -le 255 ] && [ "$3" -le 255 ] && [ "$4" -le 255 ]
}

_validate_mac() { [[ "$1" =~ ^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$ ]]; }

_validate_iface() { [[ "$1" =~ ^[a-zA-Z0-9._-]+$ ]] && [ ${#1} -le 64 ]; }

_validate_version_tag() {
    # Strict validation: only allow vX.Y.Z or X.Y.Z format with optional -suffix
    [[ "$1" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9._-]+)?$ ]]
}

#═══════════════════════════════════════════════════════════════════════
# Logging & output
#═══════════════════════════════════════════════════════════════════════

# In --json mode, human-readable log lines go to stderr so stdout stays valid JSON
_log_fd() { if [ "${JSON_OUTPUT:-false}" = true ]; then cat >&2; else cat; fi; }
log_info()    { echo -e "${BLUE}[INFO]${NC} $1" | _log_fd; }
log_success() { echo -e "${GREEN}[✓]${NC} $1" | _log_fd; }
log_warn()    { echo -e "${YELLOW}[!]${NC} $1" | _log_fd; }
log_error()   { echo -e "${RED}[✗]${NC} $1" >&2; }

print_header() {
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║                  PAQCTL - Paqet Manager v${VERSION}                   ║"
    echo "║        Raw-socket encrypted proxy - bypass firewalls           ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

#═══════════════════════════════════════════════════════════════════════
# Network & system detection
#═══════════════════════════════════════════════════════════════════════

# Retry helper with exponential backoff for API requests
_curl_with_retry() {
    local url="$1"
    local max_attempts="${2:-3}"
    local attempt=1
    local delay=2
    local response=""
    while [ $attempt -le $max_attempts ]; do
        response=$(curl -s --max-time 15 "$url" 2>/dev/null)
        if [ -n "$response" ]; then
            # Check for rate limit response
            if echo "$response" | grep -q '"message".*rate limit'; then
                log_warn "GitHub API rate limited, waiting ${delay}s (attempt $attempt/$max_attempts)"
                sleep $delay
                delay=$((delay * 2))
                attempt=$((attempt + 1))
                continue
            fi
            echo "$response"
            return 0
        fi
        [ $attempt -lt $max_attempts ] && sleep $delay
        delay=$((delay * 2))
        attempt=$((attempt + 1))
    done
    return 1
}

detect_arch() {
    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64|amd64) echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        armv7l|armv7|armhf) echo "arm32" ;;
        mips64el|mips64le) echo "mips64le" ;;
        mips64) echo "mips64" ;;
        mipsel|mipsle) echo "mipsle" ;;
        mips) echo "mips" ;;
        *)
            log_error "Unsupported architecture: $arch"
            log_error "Paqet supports amd64, arm64, arm32, and MIPS variants"
            return 1
            ;;
    esac
}

detect_network() {
    log_info "Auto-detecting network configuration..."

    # Default interface - handle both standard "via X dev Y" and OpenVZ "dev Y scope link" formats
    # Standard: "default via 192.168.1.1 dev eth0" -> $5 = eth0
    # OpenVZ:   "default dev venet0 scope link"   -> $3 = venet0
    local _route_line
    _route_line=$(ip route show default 2>/dev/null | head -1)
    if [[ "$_route_line" == *" via "* ]]; then
        # Standard format with gateway
        DETECTED_IFACE=$(echo "$_route_line" | awk '{print $5}')
    elif [[ "$_route_line" == *" dev "* ]]; then
        # OpenVZ/direct format without gateway
        DETECTED_IFACE=$(echo "$_route_line" | awk '{print $3}')
    fi

    # Validate detected interface exists
    if [ -n "$DETECTED_IFACE" ] && ! ip link show "$DETECTED_IFACE" &>/dev/null; then
        DETECTED_IFACE=""
    fi

    if [ -z "$DETECTED_IFACE" ]; then
        # Skip loopback, docker, veth, bridge, and other virtual interfaces
        # Note: grep -v returns exit 1 if no matches, so we add || true for pipefail
        DETECTED_IFACE=$(ip -o link show 2>/dev/null | awk -F': ' '{gsub(/ /,"",$2); print $2}' | { grep -vE '^(lo|docker[0-9]|br-|veth|virbr|tun|tap|wg)' || true; } | head -1)
    fi

    # Local IP - wrap entire pipeline to prevent pipefail exit
    if [ -n "$DETECTED_IFACE" ]; then
        # Note: wrap in subshell with || true to handle cases where interface is invalid or has no IP
        DETECTED_IP=$( (ip -4 addr show "$DETECTED_IFACE" 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | { grep -o '[0-9.]*' || true; } | head -1) || true )
    fi
    if [ -z "$DETECTED_IP" ]; then
        DETECTED_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
        [ -z "$DETECTED_IP" ] && DETECTED_IP=$(ip -4 addr show scope global 2>/dev/null | awk '/inet /{gsub(/\/.*/, "", $2); print $2; exit}')
    fi

    # Gateway IP - only present in standard "via X" format, not in OpenVZ
    if [[ "$_route_line" == *" via "* ]]; then
        DETECTED_GATEWAY=$(echo "$_route_line" | awk '{print $3}')
    else
        DETECTED_GATEWAY=""
    fi

    # Gateway MAC
    DETECTED_GW_MAC=""
    if [ -n "$DETECTED_GATEWAY" ]; then
        # Try ip neigh first (most reliable on Linux)
        DETECTED_GW_MAC=$(ip neigh show "$DETECTED_GATEWAY" 2>/dev/null | awk '/lladdr/{print $5; exit}')
        if [ -z "$DETECTED_GW_MAC" ]; then
            # Trigger ARP resolution
            ping -c 1 -W 2 "$DETECTED_GATEWAY" &>/dev/null || true
            sleep 1
            DETECTED_GW_MAC=$(ip neigh show "$DETECTED_GATEWAY" 2>/dev/null | awk '/lladdr/{print $5; exit}')
        fi
        if [ -z "$DETECTED_GW_MAC" ] && command -v arp &>/dev/null; then
            # Fallback: parse arp output looking for MAC pattern
            # Note: grep returns exit 1 if no matches, so we add || true for pipefail
            DETECTED_GW_MAC=$(arp -n "$DETECTED_GATEWAY" 2>/dev/null | { grep -oE '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' || true; } | head -1)
        fi
    fi

    log_info "Interface: ${DETECTED_IFACE:-unknown}"
    log_info "Local IP:  ${DETECTED_IP:-unknown}"
    log_info "Gateway:   ${DETECTED_GATEWAY:-unknown}"
    log_info "GW MAC:    ${DETECTED_GW_MAC:-unknown}"
}

# Package manager for install_package. The installer sets PKG_MANAGER in
# detect_os; the management script detects it on first use.
_ensure_pkg_manager() {
    [ -n "${PKG_MANAGER:-}" ] && [ "$PKG_MANAGER" != "unknown" ] && return 0
    if command -v apt-get &>/dev/null; then PKG_MANAGER="apt"
    elif command -v dnf &>/dev/null; then PKG_MANAGER="dnf"
    elif command -v yum &>/dev/null; then PKG_MANAGER="yum"
    elif command -v pacman &>/dev/null; then PKG_MANAGER="pacman"
    elif command -v zypper &>/dev/null; then PKG_MANAGER="zypper"
    elif command -v apk &>/dev/null; then PKG_MANAGER="apk"
    else PKG_MANAGER="unknown"
    fi
}

install_package() {
    local package="$1"
    _ensure_pkg_manager
    log_info "Installing $package..."

    case "$PKG_MANAGER" in
        apt)
            apt-get update -q 2>/dev/null || log_warn "apt-get update failed, attempting install anyway..."
            if apt-get install -y -q "$package"; then
                log_success "$package installed successfully"
            else
                log_error "Failed to install $package"
                return 1
            fi
            ;;
        dnf)
            if dnf install -y -q "$package"; then
                log_success "$package installed successfully"
            else
                log_error "Failed to install $package"
                return 1
            fi
            ;;
        yum)
            if yum install -y -q "$package"; then
                log_success "$package installed successfully"
            else
                log_error "Failed to install $package"
                return 1
            fi
            ;;
        pacman)
            if pacman -Sy --noconfirm "$package"; then
                log_success "$package installed successfully"
            else
                log_error "Failed to install $package"
                return 1
            fi
            ;;
        zypper)
            if zypper install -y -n "$package"; then
                log_success "$package installed successfully"
            else
                log_error "Failed to install $package"
                return 1
            fi
            ;;
        apk)
            if apk add --no-cache "$package"; then
                log_success "$package installed successfully"
            else
                log_error "Failed to install $package"
                return 1
            fi
            ;;
        *)
            log_warn "Unknown package manager. Please install $package manually."
            return 1
            ;;
    esac
}

#═══════════════════════════════════════════════════════════════════════
# Firewall persistence
#═══════════════════════════════════════════════════════════════════════

_is_firewalld_active() {
    command -v firewall-cmd &>/dev/null && firewall-cmd --state 2>/dev/null | grep -q running
}

persist_iptables_rules() {
    if _is_firewalld_active; then
        firewall-cmd --runtime-to-permanent 2>/dev/null || true
        return 0
    fi
    if [ -x /etc/init.d/iptables ]; then
        /etc/init.d/iptables save 2>/dev/null || true
    fi
    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save 2>/dev/null || true
    elif command -v iptables-save &>/dev/null; then
        if [ -d /etc/iptables ]; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
            command -v ip6tables-save &>/dev/null && { ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true; }
        elif [ -f /etc/debian_version ]; then
            mkdir -p /etc/iptables
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
            command -v ip6tables-save &>/dev/null && { ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true; }
        elif [ -d /etc/sysconfig ]; then
            iptables-save > /etc/sysconfig/iptables 2>/dev/null || true
            command -v ip6tables-save &>/dev/null && { ip6tables-save > /etc/sysconfig/ip6tables 2>/dev/null || true; }
        fi
    fi
    if command -v nft &>/dev/null && [ -f /etc/nftables.conf ]; then
        nft list ruleset > /etc/nftables.conf 2>/dev/null || true
    fi
}

#═══════════════════════════════════════════════════════════════════════
# Settings (settings.conf)
#═══════════════════════════════════════════════════════════════════════

# _load_settings [KEY...]
# Load settings.conf into shell variables (no eval). With KEY arguments only
# those keys are loaded, e.g. to carry Telegram settings over a reinstall.
_load_settings() {
    # Unreadable (e.g. non-root running 'paqctl help') is not an error
    [ -r "$INSTALL_DIR/settings.conf" ] || return 0
    local _only=" $* " key value
    while IFS='=' read -r key value; do
        [[ "$key" =~ ^[A-Z_][A-Z_0-9]*$ ]] || continue
        [ $# -eq 0 ] || [[ "$_only" == *" $key "* ]] || continue
        value="${value#\"}"; value="${value%\"}"
        # Skip values with dangerous shell characters
        [[ "$value" =~ [\`\$\(] ]] && continue
        case "$key" in
            BACKEND) BACKEND="$value" ;;
            ROLE) ROLE="$value" ;;
            PAQET_VERSION) PAQET_VERSION="$value" ;;
            PAQCTL_VERSION) PAQCTL_VERSION="$value" ;;
            LISTEN_PORT) [[ "$value" =~ ^[0-9]*$ ]] && LISTEN_PORT="$value" ;;
            SOCKS_PORT) [[ "$value" =~ ^[0-9]*$ ]] && SOCKS_PORT="$value" ;;
            INTERFACE) INTERFACE="$value" ;;
            LOCAL_IP) LOCAL_IP="$value" ;;
            GATEWAY_MAC) GATEWAY_MAC="$value" ;;
            ENCRYPTION_KEY) ENCRYPTION_KEY="$value" ;;
            PAQET_TCP_LOCAL_FLAG) [[ "$value" =~ ^[FSRPAUEC]+(,[FSRPAUEC]+)*$ ]] && PAQET_TCP_LOCAL_FLAG="$value" ;;
            PAQET_TCP_REMOTE_FLAG) [[ "$value" =~ ^[FSRPAUEC]+(,[FSRPAUEC]+)*$ ]] && PAQET_TCP_REMOTE_FLAG="$value" ;;
            REMOTE_SERVER) REMOTE_SERVER="$value" ;;
            GFK_VIO_PORT) [[ "$value" =~ ^[0-9]*$ ]] && GFK_VIO_PORT="$value" ;;
            GFK_VIO_CLIENT_PORT) [[ "$value" =~ ^[0-9]*$ ]] && GFK_VIO_CLIENT_PORT="$value" ;;
            GFK_QUIC_PORT) [[ "$value" =~ ^[0-9]*$ ]] && GFK_QUIC_PORT="$value" ;;
            GFK_QUIC_CLIENT_PORT) [[ "$value" =~ ^[0-9]*$ ]] && GFK_QUIC_CLIENT_PORT="$value" ;;
            GFK_AUTH_CODE) GFK_AUTH_CODE="$value" ;;
            GFK_PORT_MAPPINGS) GFK_PORT_MAPPINGS="$value" ;;
            GFK_SOCKS_PORT) [[ "$value" =~ ^[0-9]*$ ]] && GFK_SOCKS_PORT="$value" ;;
            GFK_SOCKS_VIO_PORT) [[ "$value" =~ ^[0-9]*$ ]] && GFK_SOCKS_VIO_PORT="$value" ;;
            XRAY_PANEL_DETECTED) XRAY_PANEL_DETECTED="$value" ;;
            MICROSOCKS_PORT) [[ "$value" =~ ^[0-9]*$ ]] && MICROSOCKS_PORT="$value" ;;
            GFK_SERVER_IP) GFK_SERVER_IP="$value" ;;
            GFK_TCP_FLAGS) [[ "$value" =~ ^[FSRPAUEC]+$ ]] && GFK_TCP_FLAGS="$value" ;;
            TELEGRAM_BOT_TOKEN) TELEGRAM_BOT_TOKEN="$value" ;;
            TELEGRAM_CHAT_ID) TELEGRAM_CHAT_ID="$value" ;;
            TELEGRAM_INTERVAL) [[ "$value" =~ ^[0-9]+$ ]] && TELEGRAM_INTERVAL="$value" ;;
            TELEGRAM_ENABLED) TELEGRAM_ENABLED="$value" ;;
            TELEGRAM_ALERTS_ENABLED) TELEGRAM_ALERTS_ENABLED="$value" ;;
            TELEGRAM_DAILY_SUMMARY) TELEGRAM_DAILY_SUMMARY="$value" ;;
            TELEGRAM_WEEKLY_SUMMARY) TELEGRAM_WEEKLY_SUMMARY="$value" ;;
            TELEGRAM_SERVER_LABEL) TELEGRAM_SERVER_LABEL="$value" ;;
            TELEGRAM_START_HOUR) [[ "$value" =~ ^[0-9]+$ ]] && TELEGRAM_START_HOUR="$value" ;;
            ROUTING_MODE) ROUTING_MODE="$value" ;;
            FORWARD_PORT) FORWARD_PORT="$value" ;;
            FORWARD_TARGET) FORWARD_TARGET="$value" ;;
            KCP_PROFILE) KCP_PROFILE="$value" ;;
            KCP_CONN) KCP_CONN="$value" ;;
            KCP_MTU) KCP_MTU="$value" ;;
            KCP_SNDWND) KCP_SNDWND="$value" ;;
            KCP_RCVWND) KCP_RCVWND="$value" ;;
            KCP_NODELAY) KCP_NODELAY="$value" ;;
            KCP_INTERVAL) KCP_INTERVAL="$value" ;;
            KCP_RESEND) KCP_RESEND="$value" ;;
            KCP_NOCONGESTION) KCP_NOCONGESTION="$value" ;;
            KCP_SOCKBUF) KCP_SOCKBUF="$value" ;;
            KCP_SMUXBUF) KCP_SMUXBUF="$value" ;;
            TURBO_ENABLED) TURBO_ENABLED="$value" ;;
            WATCHDOG_ENABLED) WATCHDOG_ENABLED="$value" ;;
        esac
    done < <(grep '^[A-Z_][A-Z_0-9]*=' "$INSTALL_DIR/settings.conf")
}

# Write settings.conf atomically from the current shell variables.
save_settings() {
    local _tg_token="${TELEGRAM_BOT_TOKEN:-}"
    local _tg_chat="${TELEGRAM_CHAT_ID:-}"
    local _tg_interval="${TELEGRAM_INTERVAL:-6}"
    local _tg_enabled="${TELEGRAM_ENABLED:-false}"
    local _tg_alerts="${TELEGRAM_ALERTS_ENABLED:-true}"
    local _tg_daily="${TELEGRAM_DAILY_SUMMARY:-true}"
    local _tg_weekly="${TELEGRAM_WEEKLY_SUMMARY:-true}"
    local _tg_label="${TELEGRAM_SERVER_LABEL:-}"
    local _tg_start_hour="${TELEGRAM_START_HOUR:-0}"
    # Sanitize sensitive values - remove shell metacharacters and control chars
    _sanitize_value() {
        printf '%s' "$1" | tr -d '"$`\\'\''(){}[]<>|;&!\n\r\t'
    }
    local _safe_key; _safe_key=$(_sanitize_value "${ENCRYPTION_KEY:-}")
    local _safe_auth; _safe_auth=$(_sanitize_value "${GFK_AUTH_CODE:-}")
    local _tmp
    _tmp=$(mktemp "$INSTALL_DIR/settings.conf.XXXXXXXX") || { log_error "Failed to create temp file"; return 1; }
    (umask 077; cat > "$_tmp" << SEOF
BACKEND="${BACKEND:-paqet}"
ROLE="${ROLE}"
PAQET_VERSION="${PAQET_VERSION:-unknown}"
PAQCTL_VERSION="${VERSION}"
LISTEN_PORT="${LISTEN_PORT:-}"
SOCKS_PORT="${SOCKS_PORT:-}"
INTERFACE="${INTERFACE:-${IFACE:-}}"
LOCAL_IP="${LOCAL_IP:-}"
GATEWAY_MAC="${GATEWAY_MAC:-${GW_MAC:-}}"
ENCRYPTION_KEY="${_safe_key}"
PAQET_TCP_LOCAL_FLAG="${PAQET_TCP_LOCAL_FLAG:-PA}"
PAQET_TCP_REMOTE_FLAG="${PAQET_TCP_REMOTE_FLAG:-PA}"
REMOTE_SERVER="${REMOTE_SERVER:-}"
GFK_VIO_PORT="${GFK_VIO_PORT:-}"
GFK_VIO_CLIENT_PORT="${GFK_VIO_CLIENT_PORT:-}"
GFK_QUIC_PORT="${GFK_QUIC_PORT:-}"
GFK_QUIC_CLIENT_PORT="${GFK_QUIC_CLIENT_PORT:-}"
GFK_AUTH_CODE="${_safe_auth}"
GFK_PORT_MAPPINGS="${GFK_PORT_MAPPINGS:-}"
GFK_SOCKS_PORT="${GFK_SOCKS_PORT:-}"
GFK_SOCKS_VIO_PORT="${GFK_SOCKS_VIO_PORT:-}"
XRAY_PANEL_DETECTED="${XRAY_PANEL_DETECTED:-false}"
MICROSOCKS_PORT="${MICROSOCKS_PORT:-}"
GFK_SERVER_IP="${GFK_SERVER_IP:-}"
GFK_TCP_FLAGS="${GFK_TCP_FLAGS:-AP}"
TELEGRAM_BOT_TOKEN="${_tg_token}"
TELEGRAM_CHAT_ID="${_tg_chat}"
TELEGRAM_INTERVAL=${_tg_interval}
TELEGRAM_ENABLED=${_tg_enabled}
TELEGRAM_ALERTS_ENABLED=${_tg_alerts}
TELEGRAM_DAILY_SUMMARY=${_tg_daily}
TELEGRAM_WEEKLY_SUMMARY=${_tg_weekly}
TELEGRAM_SERVER_LABEL="${_tg_label}"
TELEGRAM_START_HOUR=${_tg_start_hour}
ROUTING_MODE="${ROUTING_MODE:-socks5}"
FORWARD_PORT="${FORWARD_PORT:-14000}"
FORWARD_TARGET="${FORWARD_TARGET:-127.0.0.1:80}"
KCP_PROFILE="${KCP_PROFILE:-standard}"
KCP_CONN="${KCP_CONN:-2}"
KCP_MTU="${KCP_MTU:-1350}"
KCP_SNDWND="${KCP_SNDWND:-1024}"
KCP_RCVWND="${KCP_RCVWND:-1024}"
KCP_NODELAY="${KCP_NODELAY:-0}"
KCP_INTERVAL="${KCP_INTERVAL:-20}"
KCP_RESEND="${KCP_RESEND:-2}"
KCP_NOCONGESTION="${KCP_NOCONGESTION:-0}"
KCP_SOCKBUF="${KCP_SOCKBUF:-4194304}"
KCP_SMUXBUF="${KCP_SMUXBUF:-4194304}"
TURBO_ENABLED="${TURBO_ENABLED:-false}"
WATCHDOG_ENABLED="${WATCHDOG_ENABLED:-false}"
SEOF
    )
    if ! mv "$_tmp" "$INSTALL_DIR/settings.conf"; then
        log_error "Failed to save settings"
        rm -f "$_tmp"
        return 1
    fi
    chmod 600 "$INSTALL_DIR/settings.conf" 2>/dev/null
}
