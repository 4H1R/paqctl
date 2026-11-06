#!/bin/bash
#
# ╔═══════════════════════════════════════════════════════════════════╗
# ║      PAQCTL - Paqet Manager v1.2.0                                ║
# ║                                                                   ║
# ║  One-click setup for Paqet raw-socket proxy                       ║
# ║                                                                   ║
# ║  * Installs paqet binary + libpcap                                ║
# ║  * Auto-detects network config                                    ║
# ║  * Configures server or client mode                               ║
# ║  * Manages iptables rules                                         ║
# ║  * Auto-start on boot via systemd/OpenRC/SysVinit                 ║
# ║  * Easy management via CLI or interactive menu                    ║
# ║                                                                   ║
# ║  Paqet: https://github.com/SamNet-dev/paqctl                       ║
# ╚═══════════════════════════════════════════════════════════════════╝
#
# Usage:
# curl -sL https://raw.githubusercontent.com/4H1R/paqctl/main/paqctl.sh | sudo bash
#
# Or: wget paqctl.sh && sudo bash paqctl.sh
#

set -eo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

# Require bash
if [ -z "$BASH_VERSION" ]; then
    echo "Error: This script requires bash. Please run with: bash $0"
    exit 1
fi

# GENERATED FILE - do not edit paqctl.sh directly.
# Edit the sources in src/ and run ./build.sh (CI checks that they match).

INSTALL_DIR="${INSTALL_DIR:-/opt/paqctl}"
BACKEND="${BACKEND:-paqet}"
# shellcheck shell=bash
# Versions, repositories and colours shared by the installer and the management script.
# INSTALL_DIR must be set before this file is included.

VERSION="1.3.0"

# Pinned versions for stability (update these after testing new releases)
PAQET_VERSION_PINNED="v1.0.0-alpha.21-a1"
XRAY_VERSION_PINNED="v26.2.4"
GFK_VERSION_PINNED="v1.0.0"

PAQET_REPO="4H1R/paqet"
PAQET_API_URL="https://api.github.com/repos/${PAQET_REPO}/releases/latest"
GFK_REPO="4H1R/paqctl"
GFK_BRANCH="main"
GFK_RAW_URL="https://raw.githubusercontent.com/${GFK_REPO}/${GFK_BRANCH}/gfk"
MICROSOCKS_REPO="rofl0r/microsocks"

BACKUP_DIR="$INSTALL_DIR/backups"
GFK_DIR="$INSTALL_DIR/gfk"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'
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
# paqet config.yaml
#═══════════════════════════════════════════════════════════════════════

# Escape a value for use inside a double-quoted YAML string. Callers always
# write the quotes themselves, so this never adds any.
_escape_yaml() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/}"
    s="${s//$'\r'/}"
    printf '%s' "$s"
}

# KCP mode in the current config.yaml (transport.kcp.mode), if any
_current_kcp_mode() {
    [ -f "$INSTALL_DIR/config.yaml" ] || return 0
    awk '/^  kcp:/{k=1; next} k && /^[^ ]|^  [^ ]/{k=0} k && /^    mode:/{gsub(/["\047]/, "", $2); print $2; exit}' "$INSTALL_DIR/config.yaml" 2>/dev/null || true
}

generate_paqet_yaml() {
    local target_file="$1"
    local _y_iface _y_ip _y_mac _y_key _y_server _tcp_local_flags _tcp_remote_flags
    _y_iface=$(_escape_yaml "${INTERFACE:-${IFACE:-eth0}}")
    _y_ip=$(_escape_yaml "${LOCAL_IP:-}")
    _y_mac=$(_escape_yaml "${GATEWAY_MAC:-${GW_MAC:-}}")
    _y_key=$(_escape_yaml "${ENCRYPTION_KEY:-${KEY:-}}")
    _tcp_local_flags=$(echo "${PAQET_TCP_LOCAL_FLAG:-PA}" | sed 's/,/", "/g; s/.*/["&"]/')
    _tcp_remote_flags=$(echo "${PAQET_TCP_REMOTE_FLAG:-PA}" | sed 's/,/", "/g; s/.*/["&"]/')

    # KCP mode: setting > mode already in config.yaml > "fast". Keeping the
    # current mode means regenerating (config set, rotate-key, import...) never
    # silently changes how an existing server behaves.
    local _mode="${KCP_MODE:-}"
    [ -n "$_mode" ] || _mode=$(_current_kcp_mode)
    case "$_mode" in normal|fast|fast2|fast3|manual) ;; *) _mode="fast" ;; esac
    # nodelay/interval/resend/nocongestion only take effect in manual mode
    local _manual=""
    if [ "$_mode" = "manual" ]; then
        _manual="
    nodelay: ${KCP_NODELAY:-0}
    interval: ${KCP_INTERVAL:-20}
    resend: ${KCP_RESEND:-2}
    nocongestion: ${KCP_NOCONGESTION:-0}"
    fi

    local _conn="${KCP_CONN:-2}"
    local _mtu="${KCP_MTU:-1350}"
    local _sndwnd="${KCP_SNDWND:-1024}"
    local _rcvwnd="${KCP_RCVWND:-1024}"
    local _nodelay="${KCP_NODELAY:-0}"
    local _interval="${KCP_INTERVAL:-20}"
    local _resend="${KCP_RESEND:-2}"
    local _nocongestion="${KCP_NOCONGESTION:-0}"
    local _sockbuf="${KCP_SOCKBUF:-4194304}"
    local _smuxbuf="${KCP_SMUXBUF:-4194304}"

    if [ "$ROLE" = "server" ]; then
        cat > "$target_file" << EOF
role: "server"

log:
  level: "info"

listen:
  addr: ":${LISTEN_PORT:-8443}"

network:
  interface: "${_y_iface}"
  ipv4:
    addr: "${_y_ip}:${LISTEN_PORT:-8443}"
    router_mac: "${_y_mac}"
  tcp:
    local_flag: ${_tcp_local_flags}
    remote_flag: ${_tcp_remote_flags}
  pcap:
    sockbuf: $(( _sockbuf > 8388608 ? _sockbuf : 8388608 ))

transport:
  protocol: "kcp"
  kcp:
    mode: "${_mode}"${_manual}
    key: "${_y_key}"
    mtu: ${_mtu}
    sndwnd: ${_sndwnd}
    rcvwnd: ${_rcvwnd}
    smuxbuf: ${_smuxbuf}
EOF
    else
        _y_server=$(_escape_yaml "${REMOTE_SERVER:-}")
        local _routing_section=""
        if [ "${ROUTING_MODE:-socks5}" = "forward" ]; then
            _routing_section="forward:
  - listen: \"0.0.0.0:${FORWARD_PORT:-14000}\"
    target: \"${FORWARD_TARGET:-127.0.0.1:80}\""
        else
            _routing_section="socks5:
  - listen: \"127.0.0.1:${SOCKS_PORT:-1080}\""
        fi

        cat > "$target_file" << EOF
role: "client"

log:
  level: "info"

${_routing_section}

network:
  interface: "${_y_iface}"
  ipv4:
    addr: "${_y_ip}:0"
    router_mac: "${_y_mac}"
  tcp:
    local_flag: ${_tcp_local_flags}
    remote_flag: ${_tcp_remote_flags}
  pcap:
    sockbuf: ${_sockbuf}

server:
  addr: "${_y_server}"

transport:
  protocol: "kcp"
  conn: ${_conn}
  kcp:
    mode: "${_mode}"${_manual}
    key: "${_y_key}"
    mtu: ${_mtu}
    sndwnd: ${_sndwnd}
    rcvwnd: ${_rcvwnd}
    smuxbuf: ${_smuxbuf}
EOF
    fi
}

#═══════════════════════════════════════════════════════════════════════
# Firewall persistence
#═══════════════════════════════════════════════════════════════════════

_is_firewalld_active() {
    command -v firewall-cmd &>/dev/null && firewall-cmd --state 2>/dev/null | grep -q running
}

persist_iptables_rules() {
    # The egress guard binds to paqet's running cgroup and cannot be restored
    # at boot (the restore would fail as a whole): keep it out of saved rules.
    # It is rebuilt on every service start.
    if declare -F _egress_guard_active >/dev/null && _egress_guard_active; then
        _egress_guard_remove
        _persist_iptables_rules_now
        _egress_guard_apply >/dev/null 2>&1 || true
        return 0
    fi
    _persist_iptables_rules_now
}

_persist_iptables_rules_now() {
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
            KCP_MODE) [[ "$value" =~ ^(normal|fast|fast2|fast3|manual)?$ ]] && KCP_MODE="$value" ;;
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
            EGRESS_GUARD) [[ "$value" =~ ^(true|false)$ ]] && EGRESS_GUARD="$value" ;;
            EGRESS_ALLOW) _egress_valid_allow "$value" && EGRESS_ALLOW="$value" ;;
        esac
    done < <(grep '^[A-Z_][A-Z_0-9]*=' "$INSTALL_DIR/settings.conf")
    # An invalid value on the last line must not make loading "fail"
    return 0
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
KCP_MODE="${KCP_MODE:-}"
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
EGRESS_GUARD="${EGRESS_GUARD:-true}"
EGRESS_ALLOW="${EGRESS_ALLOW:-}"
SEOF
    )
    if ! mv "$_tmp" "$INSTALL_DIR/settings.conf"; then
        log_error "Failed to save settings"
        rm -f "$_tmp"
        return 1
    fi
    chmod 600 "$INSTALL_DIR/settings.conf" 2>/dev/null
}
#═══════════════════════════════════════════════════════════════════════
# Egress guard (paqet server)
#
# A paqet server dials whatever address a client asks for. Without this
# guard anyone holding the key can reach this host's loopback services, its
# Docker/private networks and the cloud metadata service (169.254.169.254).
#
# The guard rejects such connections for processes in paqctl.service only
# (iptables cgroup match). paqet's tunnel packets are injected below iptables
# and are not affected; neither is anything else on the host.
#
# The cgroup match binds to the cgroup that exists when the rule is added,
# so the rules are rebuilt on every start (ExecStartPre -> _apply_firewall)
# and kept out of saved rulesets, where they would fail to restore at boot.
#
# Settings: EGRESS_GUARD=true|false (default true)
#           EGRESS_ALLOW="127.0.0.1:80, 10.0.0.0/8, [fd00::1]:443"
#═══════════════════════════════════════════════════════════════════════

_EGRESS_CHAIN="PAQCTL_EGRESS"
_EGRESS_DENY="PAQCTL_EGRESS_DENY"
_EGRESS_TAG="paqctl-egress"
_EGRESS_LOG_PREFIX="paqctl-egress: "
_EGRESS_CGROUP="system.slice/paqctl.service"
_EGRESS_RESOLV_CONF="/etc/resolv.conf"
# Loopback, "this host", RFC1918, CGNAT, link-local (cloud metadata),
# IETF/benchmark ranges, multicast and reserved
_EGRESS_BLOCK4="0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.168.0.0/16 198.18.0.0/15 224.0.0.0/4 240.0.0.0/4"
# Unspecified, loopback, link-local, site-local, unique-local, multicast
_EGRESS_BLOCK6="::/128 ::1/128 fe80::/10 fec0::/10 fc00::/7 ff00::/8"

# Is the guard wanted for this install? (paqet server, not switched off)
_egress_guard_wanted() {
    [ "${BACKEND:-paqet}" = "paqet" ] && [ "${ROLE:-}" = "server" ] && [ "${EGRESS_GUARD:-true}" = "true" ]
}

_egress_valid_ip6() {
    [[ "$1" == *:* ]] && [[ "$1" =~ ^[0-9A-Fa-f:.]+$ ]] && [ ${#1} -le 45 ] || return 1
    local rest="${1#*::}"
    [[ "$rest" != *::* ]]   # at most one "::"
}

# _egress_parse_allow ENTRY -> "FAMILY|CIDR|PORT" (PORT may be empty); 1 if invalid
# Accepts: 1.2.3.4  1.2.3.0/24  1.2.3.4:80  1.2.3.0/24:80  fd00::1  fd00::/8  [fd00::1]:80  [fd00::/8]:80
_egress_parse_allow() {
    local e="$1" addr port="" ip pfx="" fam
    if [[ "$e" =~ ^\[([^]]+)\]:([0-9]+)$ ]]; then
        addr="${BASH_REMATCH[1]}"; port="${BASH_REMATCH[2]}"
    elif [[ "$e" =~ ^([0-9./]+):([0-9]+)$ ]]; then
        addr="${BASH_REMATCH[1]}"; port="${BASH_REMATCH[2]}"
    else
        addr="$e"
    fi
    ip="${addr%%/*}"
    [[ "$addr" == */* ]] && pfx="${addr#*/}"
    if _validate_ip "$ip"; then
        fam=4
        [ -z "$pfx" ] || { [[ "$pfx" =~ ^[0-9]{1,2}$ ]] && [ "$pfx" -le 32 ]; } || return 1
    elif _egress_valid_ip6 "$ip"; then
        fam=6
        [ -z "$pfx" ] || { [[ "$pfx" =~ ^[0-9]{1,3}$ ]] && [ "$pfx" -le 128 ]; } || return 1
    else
        return 1
    fi
    [ -z "$port" ] || _validate_port "$port" || return 1
    printf '%s|%s|%s\n' "$fam" "$addr" "$port"
}

# EGRESS_ALLOW split on commas and whitespace
_egress_allow_list() {
    local list="${EGRESS_ALLOW:-}"
    list="${list//,/ }"
    local e
    for e in $list; do printf '%s\n' "$e"; done
}

# Every EGRESS_ALLOW entry valid? (empty is valid)
_egress_valid_allow() {
    local e
    for e in $(EGRESS_ALLOW="$1" _egress_allow_list); do
        _egress_parse_allow "$e" >/dev/null || return 1
    done
    return 0
}

# DNS resolvers paqet needs to reach (they are often on loopback, e.g. 127.0.0.53)
_egress_resolvers() {
    local fam="$1" ns any=false
    while read -r _ ns _; do
        any=true
        ns="${ns%%\%*}"
        if [ "$fam" = 4 ] && _validate_ip "$ns"; then
            echo "$ns"
        elif [ "$fam" = 6 ] && _egress_valid_ip6 "$ns"; then
            echo "$ns"
        fi
    done < <(grep -E '^[[:space:]]*nameserver[[:space:]]' "$_EGRESS_RESOLV_CONF" 2>/dev/null)
    # No nameserver line: resolvers fall back to localhost
    if [ "$any" = false ]; then
        if [ "$fam" = 4 ]; then echo "127.0.0.1"; else echo "::1"; fi
    fi
}

# Root of the cgroup v2 hierarchy (unified or hybrid mode)
_egress_cgroup_root() {
    if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
        echo /sys/fs/cgroup
    elif [ -f /sys/fs/cgroup/unified/cgroup.controllers ]; then
        echo /sys/fs/cgroup/unified
    else
        return 1
    fi
}

# _egress_build_family iptables|ip6tables  - (re)create the guard chains
_egress_build_family() {
    local ipt="$1" fam=4 rej="icmp-admin-prohibited" block="$_EGRESS_BLOCK4"
    if [ "$ipt" = "ip6tables" ]; then
        fam=6; rej="icmp6-adm-prohibited"; block="$_EGRESS_BLOCK6"
    fi
    local c
    for c in "$_EGRESS_DENY" "$_EGRESS_CHAIN"; do
        "$ipt" -w -N "$c" 2>/dev/null || "$ipt" -w -F "$c" 2>/dev/null || return 1
    done

    # Deny: log (rate-limited, for 'paqctl doctor') and fail fast
    "$ipt" -w -A "$_EGRESS_DENY" -m limit --limit 10/min --limit-burst 20 \
        -j LOG --log-prefix "$_EGRESS_LOG_PREFIX" --log-level info 2>/dev/null || true
    "$ipt" -w -A "$_EGRESS_DENY" -p tcp -j REJECT --reject-with tcp-reset || return 1
    "$ipt" -w -A "$_EGRESS_DENY" -j REJECT --reject-with "$rej" || return 1

    # Published ports (e.g. Docker): the client asked for a public or local
    # address that was DNATed to a private one - allowed, as from anywhere else
    "$ipt" -w -A "$_EGRESS_CHAIN" -m conntrack --ctstate DNAT -j RETURN || return 1

    local r proto
    while IFS= read -r r; do
        [ -n "$r" ] || continue
        for proto in udp tcp; do
            "$ipt" -w -A "$_EGRESS_CHAIN" -d "$r" -p "$proto" --dport 53 -j RETURN || return 1
        done
    done < <(_egress_resolvers "$fam")

    local e parsed f cidr port
    while IFS= read -r e; do
        parsed=$(_egress_parse_allow "$e") || continue
        IFS='|' read -r f cidr port <<< "$parsed"
        [ "$f" = "$fam" ] || continue
        if [ -n "$port" ]; then
            for proto in tcp udp; do
                "$ipt" -w -A "$_EGRESS_CHAIN" -d "$cidr" -p "$proto" --dport "$port" -j RETURN || return 1
            done
        else
            "$ipt" -w -A "$_EGRESS_CHAIN" -d "$cidr" -j RETURN || return 1
        fi
    done < <(_egress_allow_list)

    for cidr in $block; do
        "$ipt" -w -A "$_EGRESS_CHAIN" -d "$cidr" -j "$_EGRESS_DENY" || return 1
    done
}

# Delete every OUTPUT jump to the guard (by number: the cgroup a stale rule
# points to may no longer exist), then the chains
_egress_remove_family() {
    local ipt="$1" n
    command -v "$ipt" &>/dev/null || return 0
    for _ in $(seq 1 20); do
        n=$("$ipt" -w -L OUTPUT -n --line-numbers 2>/dev/null | awk -v c="$_EGRESS_CHAIN" '$2 == c {print $1; exit}')
        [ -n "$n" ] || break
        "$ipt" -w -D OUTPUT "$n" 2>/dev/null || break
    done
    local c
    for c in "$_EGRESS_CHAIN" "$_EGRESS_DENY"; do
        "$ipt" -w -F "$c" 2>/dev/null || true
        "$ipt" -w -X "$c" 2>/dev/null || true
    done
}

_egress_guard_remove() {
    _egress_remove_family iptables
    _egress_remove_family ip6tables
}

# Is the guard jump in place (IPv4)?
_egress_guard_active() {
    command -v iptables &>/dev/null || return 1
    iptables -w -L OUTPUT -n 2>/dev/null | awk -v c="$_EGRESS_CHAIN" '$1 == c {f = 1} END {exit !f}'
}

# Rebuild the guard, or remove it when it is not wanted.
# Returns 0 when done (or not wanted), 2 when paqet is not running (the guard
# is installed at the next start), 1 on failure.
_egress_guard_apply() {
    _egress_guard_remove
    _egress_guard_wanted || return 0

    if _is_firewalld_active; then
        echo -e "${YELLOW}[!]${NC} Egress guard is not available with firewalld: paqet clients can reach this host's private networks." >&2
        return 1
    fi
    if ! command -v iptables &>/dev/null; then
        echo -e "${YELLOW}[!]${NC} Egress guard needs iptables." >&2
        return 1
    fi
    if [ ! -d /run/systemd/system ]; then
        echo -e "${YELLOW}[!]${NC} Egress guard needs systemd: paqet clients can reach this host's private networks." >&2
        return 1
    fi
    local root
    if ! root=$(_egress_cgroup_root); then
        echo -e "${YELLOW}[!]${NC} Egress guard needs cgroup v2 (not available on this system)." >&2
        return 1
    fi
    # The service cgroup only exists while it runs (ExecStartPre included)
    [ -d "$root/$_EGRESS_CGROUP" ] || return 2
    modprobe xt_cgroup 2>/dev/null || true

    local ok=true
    if _egress_build_family iptables; then
        iptables -w -I OUTPUT 1 -m cgroup --path "$_EGRESS_CGROUP" -m comment --comment "$_EGRESS_TAG" \
            -j "$_EGRESS_CHAIN" 2>/dev/null || ok=false
    else
        ok=false
    fi
    if command -v ip6tables &>/dev/null && [ -d /proc/sys/net/ipv6 ]; then
        if _egress_build_family ip6tables; then
            ip6tables -w -I OUTPUT 1 -m cgroup --path "$_EGRESS_CGROUP" -m comment --comment "$_EGRESS_TAG" \
                -j "$_EGRESS_CHAIN" 2>/dev/null || ok=false
        else
            ok=false
        fi
    fi
    if [ "$ok" != true ]; then
        echo -e "${YELLOW}[!]${NC} Could not install the egress guard (iptables cgroup match unavailable?)." >&2
        return 1
    fi
    return 0
}

# Prove the guard works: from inside paqet's cgroup, connect to a TCP port
# that is reachable from outside it. Prints "blocked", "open" or "skipped".
_egress_selftest() {
    local root dir port
    root=$(_egress_cgroup_root) || { echo skipped; return 0; }
    dir="$root/$_EGRESS_CGROUP"
    [ -w "$dir/cgroup.procs" ] || { echo skipped; return 0; }
    # A loopback-reachable TCP listener, not DNS and not allow-listed
    port=$(ss -Hltn 2>/dev/null | awk '{print $4}' | grep -E '^(127\.0\.0\.1|0\.0\.0\.0|\*):[0-9]+$' \
        | sed 's/.*://' | grep -vx 53 | sort -un | head -1)
    [ -n "$port" ] || { echo skipped; return 0; }
    local e
    for e in $(_egress_allow_list); do
        case "$e" in 127.*|0.*) echo skipped; return 0 ;; esac
    done
    timeout 3 bash -c "exec 3<>/dev/tcp/127.0.0.1/$port" 2>/dev/null || { echo skipped; return 0; }
    # shellcheck disable=SC2016  # expanded by the inner shell
    if timeout 3 bash -c 'echo "$BASHPID" > "$1/cgroup.procs" && exec 3<>"/dev/tcp/127.0.0.1/$2"' _ "$dir" "$port" 2>/dev/null; then
        echo open
    else
        echo blocked
    fi
}

# Client side: a forward-mode target on the server's private side (e.g. a
# panel on its 127.0.0.1) has to be allowed on the server
_egress_forward_hint() {
    local target="$1" host
    host="${target%:*}"; host="${host#[}"; host="${host%]}"
    case "$host" in
        localhost|127.*|0.*|10.*|192.168.*|169.254.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|\
        100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*|::1|[fF][cCdD]*|[fF][eE]80*) ;;
        *) return 0 ;;
    esac
    echo -e "  ${YELLOW}Note:${NC} paqet servers block private/loopback targets by default. Allow this one on the server:"
    echo -e "    ${BOLD}sudo paqctl config set EGRESS_ALLOW=\"${target/localhost/127.0.0.1}\"${NC}"
}

# Connections the guard rejected recently (kernel log, rate-limited): "COUNT DST:PORT" lines
_egress_recent_blocks() {
    local since="${1:-24 hours ago}"
    command -v journalctl &>/dev/null || return 0
    journalctl -k --since "$since" --no-pager -o cat 2>/dev/null | grep -F "$_EGRESS_LOG_PREFIX" \
        | sed -nE 's/.* DST=([^ ]+) .*PROTO=([A-Z0-9]+)( .* DPT=([0-9]+))?.*/\1:\4 (\2)/p' \
        | sed 's/: (/ (/' | sort | uniq -c | sort -rn
}
# shellcheck shell=bash
# Backend install/config helpers (paqet binary, GFW-knocker scripts).
# Included into both the installer and the management script by build.sh.

#═══════════════════════════════════════════════════════════════════════
# paqet binary
#═══════════════════════════════════════════════════════════════════════

download_paqet() {
    local version="$1"
    local arch
    arch=$(detect_arch) || return 1
    local os_name="linux"
    local ext="tar.gz"
    local filename="paqet-${os_name}-${arch}-${version}.${ext}"
    local url="https://github.com/${PAQET_REPO}/releases/download/${version}/${filename}"

    log_info "Downloading paqet ${version} for ${os_name}/${arch}..."

    if ! mkdir -p "$INSTALL_DIR/bin"; then
        log_error "Failed to create directory $INSTALL_DIR/bin"
        return 1
    fi
    local tmp_file
    tmp_file=$(mktemp "/tmp/paqet-download-XXXXXXXX.${ext}") || { log_error "Failed to create temp file"; return 1; }

    # Try curl first, fallback to wget
    local download_ok=false
    if curl -sL --max-time 180 --retry 3 --retry-delay 5 --fail -o "$tmp_file" "$url" 2>/dev/null; then
        download_ok=true
    elif command -v wget &>/dev/null; then
        log_info "curl failed, trying wget..."
        rm -f "$tmp_file"
        if wget -q --timeout=180 --tries=3 -O "$tmp_file" "$url" 2>/dev/null; then
            download_ok=true
        fi
    fi

    if [ "$download_ok" != "true" ]; then
        log_error "Failed to download: $url"
        log_error "Try manual download: wget '$url' and place binary in $INSTALL_DIR/bin/"
        rm -f "$tmp_file"
        return 1
    fi

    # Validate download
    local fsize
    fsize=$(stat -c%s "$tmp_file" 2>/dev/null || stat -f%z "$tmp_file" 2>/dev/null || wc -c < "$tmp_file" 2>/dev/null || echo 0)
    if [ "$fsize" -lt 1000 ]; then
        log_error "Downloaded file is too small ($fsize bytes). Download may have failed."
        rm -f "$tmp_file"
        return 1
    fi

    # Extract
    log_info "Extracting..."
    local tmp_extract
    tmp_extract=$(mktemp -d "/tmp/paqet-extract-XXXXXXXX") || { log_error "Failed to create temp file"; return 1; }
    if ! tar -xzf "$tmp_file" -C "$tmp_extract" 2>/dev/null; then
        log_error "Failed to extract archive"
        rm -f "$tmp_file"
        rm -rf "$tmp_extract"
        return 1
    fi

    # Find the binary in extracted files
    local binary_name="paqet_${os_name}_${arch}"
    local found_binary=""
    found_binary=$(find "$tmp_extract" -name "$binary_name" -type f 2>/dev/null | head -1)
    if [ -z "$found_binary" ]; then
        # Try alternate name patterns
        found_binary=$(find "$tmp_extract" -name "paqet*" -type f -executable 2>/dev/null | head -1)
    fi
    if [ -z "$found_binary" ]; then
        found_binary=$(find "$tmp_extract" -name "paqet*" -type f 2>/dev/null | head -1)
    fi

    if [ -z "$found_binary" ]; then
        log_error "Could not find paqet binary in archive"
        rm -f "$tmp_file"
        rm -rf "$tmp_extract"
        return 1
    fi

    # Stop paqet if running to avoid "Text file busy" error
    if pgrep -f "$INSTALL_DIR/bin/paqet" &>/dev/null; then
        log_info "Stopping paqet to update binary..."
        pkill -f "$INSTALL_DIR/bin/paqet" 2>/dev/null || true
        sleep 1
    fi

    if ! cp "$found_binary" "$INSTALL_DIR/bin/paqet"; then
        log_error "Failed to copy paqet binary to $INSTALL_DIR/bin/"
        rm -f "$tmp_file"
        rm -rf "$tmp_extract"
        return 1
    fi
    if ! chmod +x "$INSTALL_DIR/bin/paqet"; then
        log_error "Failed to make paqet binary executable"
        return 1
    fi

    # Copy example configs if they exist
    find "$tmp_extract" -name "*.yaml.example" -exec cp {} "$INSTALL_DIR/" \; 2>/dev/null || true

    rm -f "$tmp_file"
    rm -rf "$tmp_extract"

    # Verify binary runs
    if "$INSTALL_DIR/bin/paqet" version &>/dev/null; then
        log_success "paqet ${version} installed successfully"
    else
        log_warn "paqet binary installed but version check failed (may need libpcap)"
    fi
}

#═══════════════════════════════════════════════════════════════════════
# GFW-knocker
#═══════════════════════════════════════════════════════════════════════

install_python_deps() {
    log_info "Installing Python dependencies for GFW-knocker..."
    _ensure_pkg_manager
    if ! command -v python3 &>/dev/null; then
        install_package python3
    fi
    # Ensure python3 version >= 3.10
    local pyver
    pyver=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "0.0")
    local pymajor pyminor
    pymajor=$(echo "$pyver" | cut -d. -f1)
    pyminor=$(echo "$pyver" | cut -d. -f2)
    if [ "$pymajor" -lt 3 ] || { [ "$pymajor" -eq 3 ] && [ "$pyminor" -lt 10 ]; }; then
        log_error "Python 3.10+ required, found $pyver"
        return 1
    fi

    # Install venv support (varies by distro)
    # - Debian/Ubuntu: needs python3-venv or python3.X-venv package
    # - Fedora/RHEL/Arch/openSUSE: venv included with python3, just need pip
    # - Alpine: needs py3-pip
    case "$PKG_MANAGER" in
        apt)
            # Debian/Ubuntu needs python3-venv package (version-specific)
            local pyver_full
            pyver_full=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null)
            if [ -n "$pyver_full" ]; then
                install_package "python${pyver_full}-venv" || install_package "python3-venv"
            else
                install_package "python3-venv"
            fi
            ;;
        dnf)
            # Fedora/RHEL 8+: venv is included with python3, just ensure pip
            install_package "python3-pip" || true
            ;;
        yum)
            # Older RHEL/CentOS 7
            install_package "python3-pip" || true
            ;;
        pacman)
            # Arch Linux: venv included with python, pip is separate
            install_package "python-pip" || true
            ;;
        zypper)
            # openSUSE: venv included with python3
            install_package "python3-pip" || true
            ;;
        apk)
            # Alpine
            install_package "py3-pip" || true
            ;;
        *)
            # Try generic python3-venv, ignore if fails (venv may be built-in)
            install_package "python3-venv" 2>/dev/null || true
            ;;
    esac

    # Create virtual environment
    local VENV_DIR="$INSTALL_DIR/venv"
    # Check if venv exists AND is complete (has pip)
    if [ ! -x "$VENV_DIR/bin/pip" ]; then
        # Remove broken/incomplete venv if exists
        [ -d "$VENV_DIR" ] && rm -rf "$VENV_DIR"
        log_info "Creating Python virtual environment..."
        python3 -m venv "$VENV_DIR" || {
            log_error "Failed to create virtual environment (is python3-venv installed?)"
            return 1
        }
    fi

    # Verify pip exists after venv creation
    if [ ! -x "$VENV_DIR/bin/pip" ]; then
        log_error "venv created but pip missing (install python3-venv package)"
        return 1
    fi

    # Install packages in venv
    log_info "Installing scapy and aioquic in venv..."
    "$VENV_DIR/bin/pip" install --quiet --upgrade pip 2>/dev/null || true
    "$VENV_DIR/bin/pip" install --quiet scapy aioquic 2>/dev/null || {
        # Try with --break-system-packages as fallback (shouldn't be needed in venv)
        "$VENV_DIR/bin/pip" install scapy aioquic || {
            log_error "Failed to install Python packages (scapy, aioquic)"
            return 1
        }
    }

    # Verify
    if "$VENV_DIR/bin/python" -c "import scapy; import aioquic" 2>/dev/null; then
        log_success "Python dependencies installed (scapy, aioquic)"
    else
        log_error "Python package verification failed"
        return 1
    fi
}

install_microsocks() {
    log_info "Installing microsocks for SOCKS5 proxy..."
    if [ -x "$INSTALL_DIR/bin/microsocks" ]; then
        log_success "microsocks already installed"
        return 0
    fi
    # Build dependencies
    command -v gcc &>/dev/null || install_package gcc
    command -v make &>/dev/null || install_package make
    _ensure_pkg_manager
    # Alpine needs the libc headers to compile
    [ "$PKG_MANAGER" = "apk" ] && { [ -f /usr/include/stdio.h ] || install_package musl-dev || true; }
    local tmp_dir
    tmp_dir=$(mktemp -d)
    if ! curl -sL "https://github.com/${MICROSOCKS_REPO}/archive/refs/heads/master.tar.gz" -o "$tmp_dir/microsocks.tar.gz"; then
        log_error "Failed to download microsocks"
        rm -rf "$tmp_dir"
        return 1
    fi
    tar -xzf "$tmp_dir/microsocks.tar.gz" -C "$tmp_dir" 2>/dev/null || {
        log_error "Failed to extract microsocks"
        rm -rf "$tmp_dir"
        return 1
    }
    local src_dir
    src_dir=$(find "$tmp_dir" -maxdepth 1 -type d -name "microsocks*" | head -1)
    if [ -z "$src_dir" ]; then
        log_error "microsocks source directory not found"
        rm -rf "$tmp_dir"
        return 1
    fi
    if ! make -C "$src_dir" -j"$(nproc 2>/dev/null || echo 1)" 2>/dev/null; then
        log_error "Failed to compile microsocks"
        rm -rf "$tmp_dir"
        return 1
    fi
    mkdir -p "$INSTALL_DIR/bin"
    cp "$src_dir/microsocks" "$INSTALL_DIR/bin/microsocks"
    chmod 755 "$INSTALL_DIR/bin/microsocks"
    rm -rf "$tmp_dir"
    log_success "microsocks installed"
}

download_gfk() {
    log_info "Downloading GFW-knocker scripts..."
    if ! mkdir -p "$GFK_DIR"; then
        log_error "Failed to create $GFK_DIR"
        return 1
    fi
    # Note: parameters.py is generated by generate_gfk_config(), don't download it
    # Download server scripts from gfk/server/
    local server_files="mainserver.py quic_server.py vio_server.py"
    local f
    for f in $server_files; do
        if ! curl -sL "$GFK_RAW_URL/server/$f" -o "$GFK_DIR/$f"; then
            log_error "Failed to download $f"
            return 1
        fi
    done
    # Download client scripts from gfk/client/
    local client_files="mainclient.py quic_client.py vio_client.py"
    for f in $client_files; do
        if ! curl -sL "$GFK_RAW_URL/client/$f" -o "$GFK_DIR/$f"; then
            log_error "Failed to download $f"
            return 1
        fi
    done
    chmod 600 "$GFK_DIR"/*.py
    # Patch mainserver.py to use venv python for subprocesses
    if [ -f "$GFK_DIR/mainserver.py" ]; then
        sed -i "s|'python3'|'$INSTALL_DIR/venv/bin/python'|g" "$GFK_DIR/mainserver.py"
    fi
    log_success "GFW-knocker scripts downloaded to $GFK_DIR"
}

generate_gfk_certs() {
    if [ -f "$GFK_DIR/cert.pem" ] && [ -f "$GFK_DIR/key.pem" ]; then
        log_info "GFW-knocker certificates already exist"
        return 0
    fi
    if ! command -v openssl &>/dev/null; then
        log_info "Installing openssl..."
        install_package openssl || { log_error "Failed to install openssl"; return 1; }
    fi
    log_info "Generating QUIC TLS certificates..."
    if ! openssl req -x509 -newkey rsa:2048 -keyout "$GFK_DIR/key.pem" \
        -out "$GFK_DIR/cert.pem" -days 3650 -nodes -subj "/CN=gfk" 2>/dev/null; then
        log_error "Failed to generate certificates"
        return 1
    fi
    chmod 600 "$GFK_DIR/key.pem" "$GFK_DIR/cert.pem"
    log_success "QUIC certificates generated"
}

generate_gfk_config() {
    log_info "Generating GFW-knocker configuration..."
    # Ensure GFK directory exists
    mkdir -p "$GFK_DIR" || { log_error "Failed to create $GFK_DIR"; return 1; }
    local _tmp
    _tmp=$(mktemp "$GFK_DIR/parameters.py.XXXXXXXX") || { log_error "Failed to create temp file"; return 1; }

    # Determine port values based on role - validate they are numeric
    local vio_tcp_server_port="${GFK_VIO_PORT:-45000}"
    local vio_tcp_client_port="${GFK_VIO_CLIENT_PORT:-40000}"
    local vio_udp_server_port="${GFK_VIO_UDP_SERVER:-35000}"
    local vio_udp_client_port="${GFK_VIO_UDP_CLIENT:-30000}"
    local quic_server_port="${GFK_QUIC_PORT:-25000}"
    local quic_client_port="${GFK_QUIC_CLIENT_PORT:-20000}"

    # Validate all ports are numeric
    for _p in "$vio_tcp_server_port" "$vio_tcp_client_port" "$vio_udp_server_port" \
              "$vio_udp_client_port" "$quic_server_port" "$quic_client_port"; do
        if ! [[ "$_p" =~ ^[0-9]+$ ]]; then
            log_error "Invalid port number: $_p"
            rm -f "$_tmp"
            return 1
        fi
    done

    # Escape Python string - prevents code injection
    _escape_py_string() {
        local s="$1"
        s="${s//\\/\\\\}"   # Escape backslashes first
        s="${s//\"/\\\"}"   # Escape double quotes
        s="${s//\'/\\\'}"   # Escape single quotes
        s="${s//$'\n'/\\n}" # Escape newlines
        s="${s//$'\r'/\\r}" # Escape carriage returns
        printf '%s' "$s"
    }

    # Validate and escape server IP
    local safe_server_ip
    safe_server_ip=$(_escape_py_string "${GFK_SERVER_IP:-}")
    if ! _validate_ip "${GFK_SERVER_IP:-}"; then
        log_error "Invalid server IP: ${GFK_SERVER_IP:-}"
        rm -f "$_tmp"
        return 1
    fi

    # Validate and escape auth code
    local safe_auth_code
    safe_auth_code=$(_escape_py_string "${GFK_AUTH_CODE:-}")

    # Build port mapping dict string with validation
    local tcp_mapping="${GFK_PORT_MAPPINGS:-14000:443}"
    local mapping_str="{"
    local first=true
    local pair
    for pair in $(echo "$tcp_mapping" | tr ',' ' '); do
        local lport rport
        lport=$(echo "$pair" | cut -d: -f1)
        rport=$(echo "$pair" | cut -d: -f2)
        # Validate both ports are numeric
        if ! [[ "$lport" =~ ^[0-9]+$ ]] || ! [[ "$rport" =~ ^[0-9]+$ ]]; then
            log_error "Invalid port mapping: $pair (must be numeric:numeric)"
            rm -f "$_tmp"
            return 1
        fi
        if [ "$first" = true ]; then
            mapping_str="${mapping_str}${lport}: ${rport}"
            first=false
        else
            mapping_str="${mapping_str}, ${lport}: ${rport}"
        fi
    done
    mapping_str="${mapping_str}}"

    # Escape GFK_DIR for Python string
    local safe_gfk_dir
    safe_gfk_dir=$(_escape_py_string "${GFK_DIR}")

    (
    umask 077
    cat > "$_tmp" << PYEOF
# GFW-knocker parameters - auto-generated by paqctl
# Do not edit manually

vps_ip = "${safe_server_ip}"
xray_server_ip_address = "127.0.0.1"

tcp_port_mapping = ${mapping_str}
udp_port_mapping = {}

vio_tcp_server_port = ${vio_tcp_server_port}
vio_tcp_client_port = ${vio_tcp_client_port}
vio_udp_server_port = ${vio_udp_server_port}
vio_udp_client_port = ${vio_udp_client_port}

quic_server_port = ${quic_server_port}
quic_client_port = ${quic_client_port}
quic_local_ip = "127.0.0.1"

quic_idle_timeout = 86400
udp_timeout = 300
quic_mtu = ${KCP_MTU:-1350}
quic_verify_cert = False
quic_max_data = 1073741824
quic_max_stream_data = 1073741824

quic_auth_code = "${safe_auth_code}"

quic_cert_filepath = ("${safe_gfk_dir}/cert.pem", "${safe_gfk_dir}/key.pem")

tcp_flags = "${GFK_TCP_FLAGS:-AP}"
PYEOF
    )
    if ! mv "$_tmp" "$GFK_DIR/parameters.py"; then
        log_error "Failed to save GFW-knocker configuration"
        rm -f "$_tmp"
        return 1
    fi
    chmod 600 "$GFK_DIR/parameters.py"
    log_success "GFW-knocker configuration saved"
}

create_gfk_client_wrapper() {
    log_info "Creating GFW-knocker client wrapper..."
    local wrapper="$INSTALL_DIR/bin/gfk-client.sh"
    mkdir -p "$INSTALL_DIR/bin"
    cat > "$wrapper" << 'WRAPEOF'
#!/bin/bash
set -e
GFK_DIR="REPLACE_ME_GFK_DIR"
INSTALL_DIR="REPLACE_ME_INSTALL_DIR"

cd "$GFK_DIR"
"$INSTALL_DIR/venv/bin/python" mainclient.py &
PID1=$!
trap "kill $PID1 2>/dev/null; wait" EXIT INT TERM
wait
WRAPEOF
    sed "s#REPLACE_ME_GFK_DIR#${GFK_DIR}#g; s#REPLACE_ME_INSTALL_DIR#${INSTALL_DIR}#g" "$wrapper" > "$wrapper.sed" && mv "$wrapper.sed" "$wrapper"
    chmod 755 "$wrapper"
    log_success "Client wrapper created at $wrapper"
}
# shellcheck shell=bash
# Xray (SOCKS5 for the GFK server).
# Included into both the installer and the management script by build.sh.

#═══════════════════════════════════════════════════════════════════════
# Xray
#═══════════════════════════════════════════════════════════════════════

XRAY_CONFIG_DIR="/usr/local/etc/xray"
XRAY_CONFIG_FILE="$XRAY_CONFIG_DIR/config.json"

check_xray_installed() {
    command -v xray &>/dev/null && return 0
    [ -x /usr/local/bin/xray ] && return 0
    [ -x /usr/local/x-ui/bin/xray-linux-amd64 ] && return 0
    return 1
}

install_xray() {
    if check_xray_installed; then
        log_info "Xray is already installed"
        return 0
    fi

    log_info "Installing Xray ${XRAY_VERSION_PINNED}..."

    # Use official Xray install script with pinned version for stability
    local tmp_script
    tmp_script=$(mktemp)
    if ! curl -sL https://github.com/XTLS/Xray-install/raw/main/install-release.sh -o "$tmp_script"; then
        log_error "Failed to download Xray installer"
        rm -f "$tmp_script"
        return 1
    fi

    # Install specific version (not latest) for stability
    if ! bash "$tmp_script" install --version "$XRAY_VERSION_PINNED" 2>/dev/null; then
        log_error "Failed to install Xray"
        rm -f "$tmp_script"
        return 1
    fi
    rm -f "$tmp_script"

    log_success "Xray ${XRAY_VERSION_PINNED} installed"
}

configure_xray_socks() {
    local listen_port="${1:-443}"

    log_info "Configuring Xray SOCKS5 proxy on port $listen_port..."

    mkdir -p "$XRAY_CONFIG_DIR"

    # Create simple SOCKS5 inbound config
    cat > "$XRAY_CONFIG_FILE" << EOF
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "tag": "socks-in",
      "port": ${listen_port},
      "listen": "127.0.0.1",
      "protocol": "socks",
      "settings": {
        "auth": "noauth",
        "udp": true
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    }
  ],
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom",
      "settings": {}
    }
  ]
}
EOF
    chmod 644 "$XRAY_CONFIG_FILE"  # Xray service runs as 'nobody', needs read access
    log_success "Xray configured (SOCKS5 on 127.0.0.1:$listen_port)"
}

# Check if running xray is paqctl's own standalone install (not a real panel)
# Returns 0 if standalone (all inbounds are socks on 127.0.0.1), 1 if panel
_is_paqctl_standalone_xray() {
    [ -f "$XRAY_CONFIG_FILE" ] || return 1
    command -v python3 &>/dev/null || return 1
    python3 -c "
import json, sys
try:
    with open(sys.argv[1]) as f:
        cfg = json.load(f)
    inbounds = cfg.get('inbounds', [])
    if not inbounds:
        sys.exit(1)
    for i in inbounds:
        if i.get('protocol') != 'socks' or i.get('listen', '0.0.0.0') != '127.0.0.1':
            sys.exit(1)
    sys.exit(0)
except:
    sys.exit(1)
" "$XRAY_CONFIG_FILE" 2>/dev/null
}

# Add a SOCKS5 inbound to an existing xray config (panel) without touching other inbounds
_add_xray_gfk_socks() {
    local port="$1"
    python3 -c "
import json, sys
port = int(sys.argv[1])
config_path = sys.argv[2]
try:
    with open(config_path, 'r') as f:
        cfg = json.load(f)
except:
    cfg = {'inbounds': [], 'outbounds': [{'tag': 'direct', 'protocol': 'freedom', 'settings': {}}]}
cfg.setdefault('inbounds', [])
cfg['inbounds'] = [i for i in cfg['inbounds'] if i.get('tag') != 'gfk-socks']
cfg['inbounds'].append({
    'tag': 'gfk-socks',
    'port': port,
    'listen': '127.0.0.1',
    'protocol': 'socks',
    'settings': {'auth': 'noauth', 'udp': True},
    'sniffing': {'enabled': True, 'destOverride': ['http', 'tls']}
})
if not any(o.get('protocol') == 'freedom' for o in cfg.get('outbounds', [])):
    cfg.setdefault('outbounds', []).append({'tag': 'direct', 'protocol': 'freedom', 'settings': {}})
with open(config_path, 'w') as f:
    json.dump(cfg, f, indent=2)
" "$port" "$XRAY_CONFIG_FILE" 2>/dev/null
    if [ $? -ne 0 ]; then
        log_error "Failed to add SOCKS5 inbound to existing Xray config"
        return 1
    fi
    log_success "Added GFK SOCKS5 inbound on 127.0.0.1:$port"
}

start_xray() {
    log_info "Starting Xray service..."

    if command -v systemctl &>/dev/null && [ -d /run/systemd/system ]; then
        # Stop first, reload daemon, then start - with retry
        systemctl stop xray 2>/dev/null || true
        sleep 1
        systemctl daemon-reload 2>/dev/null || true
        systemctl enable xray 2>/dev/null || true

        # Try up to 3 times
        local attempt
        for attempt in 1 2 3; do
            systemctl start xray 2>/dev/null
            sleep 2
            if systemctl is-active --quiet xray; then
                log_success "Xray started"
                return 0
            fi
            [ "$attempt" -lt 3 ] && sleep 1
        done
        log_error "Failed to start Xray after 3 attempts"
        return 1
    else
        # Direct start for non-systemd
        local _xray_bin=""
        [ -x /usr/local/bin/xray ] && _xray_bin="/usr/local/bin/xray"
        [ -z "$_xray_bin" ] && [ -x /usr/local/x-ui/bin/xray-linux-amd64 ] && _xray_bin="/usr/local/x-ui/bin/xray-linux-amd64"
        if [ -n "$_xray_bin" ]; then
            pkill -x xray 2>/dev/null || true
            sleep 1
            nohup "$_xray_bin" run -c "$XRAY_CONFIG_FILE" > /var/log/xray.log 2>&1 &
            sleep 2
            if pgrep -f "xray" &>/dev/null; then
                log_success "Xray started"
                return 0
            fi
        fi
        log_error "Failed to start Xray"
        return 1
    fi
}

stop_xray() {
    if command -v systemctl &>/dev/null && [ -d /run/systemd/system ]; then
        systemctl stop xray 2>/dev/null || true
    else
        pkill -x xray 2>/dev/null || true
    fi
}

setup_xray_for_gfk() {
    local target_port
    target_port=$(echo "${GFK_PORT_MAPPINGS:-14000:443}" | cut -d: -f2 | cut -d, -f1)

    if pgrep -x xray &>/dev/null || pgrep -f "xray-linux" &>/dev/null; then
        # Check if this is paqctl's own standalone Xray (not a real panel)
        if _is_paqctl_standalone_xray; then
            log_info "Existing Xray is paqctl's standalone install — reconfiguring..."
            stop_xray
            sleep 1
            # Fall through to standalone install path below
        else
            XRAY_PANEL_DETECTED=true
            log_info "Existing Xray detected — adding SOCKS5 alongside panel..."

            # Clean up any leftover standalone GFK xray from prior installs
            pkill -f "xray run -c.*gfk-socks.json" 2>/dev/null || true
            rm -f "${XRAY_CONFIG_DIR}/gfk-socks.json" 2>/dev/null

            # Check all existing target ports from mappings
            local mapping pairs
            IFS=',' read -ra pairs <<< "${GFK_PORT_MAPPINGS:-14000:443}"
            for mapping in "${pairs[@]}"; do
                local vio_port="${mapping%%:*}"
                local tp="${mapping##*:}"
                if ss -tln 2>/dev/null | grep -q ":${tp} "; then
                    log_success "Port $tp is listening — GFK will forward VIO port $vio_port to this port"
                else
                    log_warn "Port $tp is NOT listening — make sure your panel inbound is on port $tp"
                fi
            done

            # Find free port for SOCKS5 (starting at 10443)
            local socks_port=10443
            while ss -tln 2>/dev/null | grep -q ":${socks_port} "; do
                socks_port=$((socks_port + 1))
                if [ "$socks_port" -gt 65000 ]; then
                    log_warn "Could not find free port for SOCKS5 — panel-only mode"
                    echo ""
                    local first_vio
                    first_vio=$(echo "${GFK_PORT_MAPPINGS:-14000:443}" | cut -d: -f1 | cut -d, -f1)
                    log_warn "For panel-to-panel: configure Iran panel outbound to 127.0.0.1:${first_vio}"
                    return 0
                fi
            done

            # Add SOCKS5 inbound to existing xray config
            _add_xray_gfk_socks "$socks_port" || {
                log_warn "Could not add SOCKS5 to panel config — panel-only mode"
                return 0
            }

            # Restart xray to load new config
            systemctl restart xray 2>/dev/null || pkill -SIGHUP xray 2>/dev/null || true
            sleep 2

            # Find next VIO port (highest existing + 1) and append SOCKS5 mapping
            local max_vio=0
            for mapping in "${pairs[@]}"; do
                local v="${mapping%%:*}"
                [ "$v" -gt "$max_vio" ] && max_vio="$v"
            done
            local socks_vio=$((max_vio + 1))
            GFK_PORT_MAPPINGS="${GFK_PORT_MAPPINGS},${socks_vio}:${socks_port}"
            GFK_SOCKS_PORT="$socks_port"
            GFK_SOCKS_VIO_PORT="$socks_vio"

            log_success "SOCKS5 proxy added on port $socks_port (VIO port $socks_vio)"
            echo ""
            log_info "Port mappings updated: ${GFK_PORT_MAPPINGS}"
            log_warn "Use these SAME mappings on the client side"
            echo ""
            local first_vio
            first_vio=$(echo "${GFK_PORT_MAPPINGS:-14000:443}" | cut -d: -f1 | cut -d, -f1)
            log_warn "For panel-to-panel: configure Iran panel outbound to 127.0.0.1:${first_vio}"
            log_warn "For direct SOCKS5: use 127.0.0.1:${socks_vio} as your proxy on client"
            return 0
        fi
    fi

    install_xray || return 1
    configure_xray_socks "$target_port" || return 1
    start_xray || return 1
}
#═══════════════════════════════════════════════════════════════════════
# Utility Functions
#═══════════════════════════════════════════════════════════════════════

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

detect_os() {
    OS="unknown"
    OS_VERSION="unknown"
    OS_FAMILY="unknown"
    HAS_SYSTEMD=false
    PKG_MANAGER="unknown"

    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS="$ID"
        OS_VERSION="${VERSION_ID:-unknown}"
    elif [ -f /etc/redhat-release ]; then
        OS="rhel"
    elif [ -f /etc/debian_version ]; then
        OS="debian"
    elif [ -f /etc/alpine-release ]; then
        OS="alpine"
    elif [ -f /etc/arch-release ]; then
        OS="arch"
    elif [ -f /etc/SuSE-release ] || [ -f /etc/SUSE-brand ]; then
        OS="opensuse"
    else
        OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    fi

    case "$OS" in
        ubuntu|debian|linuxmint|pop|elementary|zorin|kali|raspbian)
            OS_FAMILY="debian"
            PKG_MANAGER="apt"
            ;;
        rhel|centos|fedora|rocky|almalinux|oracle|amazon|amzn)
            OS_FAMILY="rhel"
            if command -v dnf &>/dev/null; then
                PKG_MANAGER="dnf"
            else
                PKG_MANAGER="yum"
            fi
            ;;
        arch|manjaro|endeavouros|garuda)
            OS_FAMILY="arch"
            PKG_MANAGER="pacman"
            ;;
        opensuse|opensuse-leap|opensuse-tumbleweed|sles)
            OS_FAMILY="suse"
            PKG_MANAGER="zypper"
            ;;
        alpine)
            OS_FAMILY="alpine"
            PKG_MANAGER="apk"
            ;;
        *)
            OS_FAMILY="unknown"
            PKG_MANAGER="unknown"
            ;;
    esac

    if command -v systemctl &>/dev/null && [ -d /run/systemd/system ]; then
        HAS_SYSTEMD=true
    fi

    log_info "Detected: $OS ($OS_FAMILY family), Package manager: $PKG_MANAGER"
}

check_dependencies() {
    if [ "$OS_FAMILY" = "alpine" ]; then
        if ! command -v bash &>/dev/null; then
            apk add --no-cache bash 2>/dev/null
        fi
    fi

    if ! command -v curl &>/dev/null; then
        install_package curl || log_warn "Could not install curl automatically"
    fi

    if ! command -v tar &>/dev/null; then
        install_package tar || log_warn "Could not install tar automatically"
    fi

    if ! command -v ip &>/dev/null; then
        case "$PKG_MANAGER" in
            apt) install_package iproute2 || log_warn "Could not install iproute2" ;;
            dnf|yum) install_package iproute || log_warn "Could not install iproute" ;;
            pacman) install_package iproute2 || log_warn "Could not install iproute2" ;;
            zypper) install_package iproute2 || log_warn "Could not install iproute2" ;;
            apk) install_package iproute2 || log_warn "Could not install iproute2" ;;
        esac
    fi

    if ! command -v tput &>/dev/null; then
        case "$PKG_MANAGER" in
            apt) install_package ncurses-bin || log_warn "Could not install ncurses-bin" ;;
            apk) install_package ncurses || log_warn "Could not install ncurses" ;;
            *) install_package ncurses || log_warn "Could not install ncurses" ;;
        esac
    fi

    # Firewall rules: use firewalld if active, otherwise iptables
    if _is_firewalld_active; then
        log_info "firewalld detected — will use firewall-cmd for rules"
    elif ! command -v iptables &>/dev/null; then
        log_info "Installing iptables..."
        case "$PKG_MANAGER" in
            apt) install_package iptables || log_warn "Could not install iptables - firewall rules may not work" ;;
            dnf|yum) install_package iptables || log_warn "Could not install iptables" ;;
            pacman) install_package iptables || log_warn "Could not install iptables" ;;
            zypper) install_package iptables || log_warn "Could not install iptables" ;;
            apk) install_package iptables || log_warn "Could not install iptables" ;;
            *) log_warn "Please install iptables manually for firewall rules to work" ;;
        esac
    fi

    # openssl is required for GFK certificate generation
    if ! command -v openssl &>/dev/null; then
        install_package openssl || log_warn "Could not install openssl"
    fi

    # libpcap is required by paqet
    install_libpcap
}

install_libpcap() {
    log_info "Checking for libpcap..."

    # Check if already available
    if ldconfig -p 2>/dev/null | grep -q libpcap; then
        log_success "libpcap already installed"
        return 0
    fi

    case "$PKG_MANAGER" in
        apt) install_package libpcap-dev ;;
        dnf|yum) install_package libpcap-devel ;;
        pacman) install_package libpcap ;;
        zypper) install_package libpcap-devel ;;
        apk) install_package libpcap-dev ;;
        *) log_warn "Please install libpcap manually for your distribution"; return 1 ;;
    esac

    # Fedora/RHEL: ensure libpcap.so.1 symlink exists (package may only install versioned .so)
    if [ "$PKG_MANAGER" = "dnf" ] || [ "$PKG_MANAGER" = "yum" ]; then
        if ! ldconfig -p 2>/dev/null | grep -q 'libpcap\.so\.1 '; then
            local _pcap_lib
            _pcap_lib=$(find /usr/lib64 /usr/lib /lib64 /lib -name 'libpcap.so.*' -type f 2>/dev/null | head -1)
            if [ -n "$_pcap_lib" ]; then
                local _libdir
                _libdir=$(dirname "$_pcap_lib")
                if [ ! -e "${_libdir}/libpcap.so.1" ]; then
                    log_info "Creating libpcap.so.1 symlink for Fedora/RHEL compatibility"
                    ln -sf "$_pcap_lib" "${_libdir}/libpcap.so.1"
                fi
                ldconfig 2>/dev/null || true
            fi
        fi
    fi
}

#═══════════════════════════════════════════════════════════════════════
# Input Validation Functions
#═══════════════════════════════════════════════════════════════════════
#═══════════════════════════════════════════════════════════════════════
# Binary Download & Install
#═══════════════════════════════════════════════════════════════════════

get_latest_version() {
    local response
    response=$(_curl_with_retry "$PAQET_API_URL" 3)
    if [ -z "$response" ]; then
        log_error "Failed to query GitHub API after retries"
        return 1
    fi
    local tag
    tag=$(echo "$response" | grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | grep -o '"[^"]*"$' | tr -d '"')
    if [ -z "$tag" ]; then
        log_error "Could not determine latest paqet version"
        return 1
    fi
    if ! _validate_version_tag "$tag"; then
        log_error "Invalid version tag format: $tag"
        return 1
    fi
    echo "$tag"
}
#═══════════════════════════════════════════════════════════════════════
# Network Auto-Detection
#═══════════════════════════════════════════════════════════════════════

#═══════════════════════════════════════════════════════════════════════
# Configuration Wizard
#═══════════════════════════════════════════════════════════════════════

run_config_wizard() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  PAQCTL CONFIGURATION WIZARD${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""

    # Backend selection
    echo -e "${BOLD}Select backend:${NC}"
    echo "  1. paqet       (Go/KCP, built-in SOCKS5, single binary)"
    echo "  2. gfw-knocker (Python/QUIC, port forwarding + SOCKS5)"
    echo ""
    local backend_choice
    read -p "  Enter choice [1/2]: " backend_choice < /dev/tty || true
    case "$backend_choice" in
        2) BACKEND="gfw-knocker" ;;
        *) BACKEND="paqet" ;;
    esac
    echo ""
    log_info "Selected backend: $BACKEND"
    echo ""

    # Role selection
    echo -e "${BOLD}Select role:${NC}"
    echo "  1. Server  (accept connections from clients)"
    echo "  2. Client  (connect to a server, provides SOCKS5 proxy)"
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
    echo ""
    log_info "Selected role: $ROLE"

    if [ "$BACKEND" = "paqet" ]; then
        _wizard_paqet
    else
        _wizard_gfk
    fi

    echo ""
    read -p "  Enable OS Kernel Turbo Mode (BBR + 32MB Buffers)? [Y/n]: " t_choice < /dev/tty || true
    if [[ ! "${t_choice:-Y}" =~ ^[nN]$ ]]; then
        TURBO_ENABLED="true"
    else
        TURBO_ENABLED="false"
    fi
    read -p "  Enable Self-Healing Watchdog (Auto-Recovery Service)? [Y/n]: " w_choice < /dev/tty || true
    if [[ ! "${w_choice:-Y}" =~ ^[nN]$ ]]; then
        WATCHDOG_ENABLED="true"
    else
        WATCHDOG_ENABLED="false"
    fi

    # Save settings
    save_settings
}

_wizard_paqet() {
    # Auto-detect network
    detect_network
    echo ""

    # Confirm/override interface
    echo -e "${BOLD}Network interface${NC} [${DETECTED_IFACE:-eth0}]:"
    read -p "  Interface: " input < /dev/tty || true
    IFACE="${input:-$DETECTED_IFACE}"
    IFACE="${IFACE:-eth0}"
    if ! _validate_iface "$IFACE"; then
        log_warn "Invalid interface name. Using eth0."
        IFACE="eth0"
    fi

    # Confirm/override local IP
    echo -e "${BOLD}Local IP${NC} [${DETECTED_IP:-auto}]:"
    read -p "  IP: " input < /dev/tty || true
    LOCAL_IP="${input:-$DETECTED_IP}"
    if [ -n "$LOCAL_IP" ] && ! _validate_ip "$LOCAL_IP"; then
        log_warn "Invalid IP format. Using detected IP."
        LOCAL_IP="$DETECTED_IP"
    fi

    # Confirm/override gateway MAC
    echo -e "${BOLD}Gateway MAC address${NC} [${DETECTED_GW_MAC:-auto}]:"
    read -p "  MAC: " input < /dev/tty || true
    GW_MAC="${input:-$DETECTED_GW_MAC}"

    if [ -z "$GW_MAC" ] || ! _validate_mac "$GW_MAC"; then
        if [ -n "$GW_MAC" ]; then
            log_warn "Invalid MAC format detected."
        else
            log_error "Could not detect gateway MAC address."
        fi
        log_error "Please enter it manually (format: aa:bb:cc:dd:ee:ff)"
        read -p "  Gateway MAC: " GW_MAC < /dev/tty || true
        if [ -z "$GW_MAC" ] || ! _validate_mac "$GW_MAC"; then
            log_error "Valid gateway MAC is required for paqet to function."
            exit 1
        fi
    fi
    # Canonical names used by save_settings / config generation (a reinstall
    # has the previous values loaded, which must not win over the wizard)
    INTERFACE="$IFACE"
    GATEWAY_MAC="$GW_MAC"

    if [ "$ROLE" = "server" ]; then
        echo ""
        echo -e "${BOLD}Listen port${NC} [8443]:"
        read -p "  Port: " input < /dev/tty || true
        LISTEN_PORT="${input:-8443}"
        if ! [[ "$LISTEN_PORT" =~ ^[0-9]+$ ]] || [ "$LISTEN_PORT" -lt 1 ] || [ "$LISTEN_PORT" -gt 65535 ]; then
            log_warn "Invalid port. Using default 8443."
            LISTEN_PORT=8443
        fi

        echo ""
        log_info "Generating encryption key..."
        ENCRYPTION_KEY=$("$INSTALL_DIR/bin/paqet" secret 2>/dev/null || true)
        if [ -z "$ENCRYPTION_KEY" ]; then
            log_warn "Could not auto-generate key. Using openssl fallback..."
            ENCRYPTION_KEY=$(openssl rand -base64 32 2>/dev/null | tr -d '=+/' | head -c 32 || true)
        fi
        if [ -z "$ENCRYPTION_KEY" ] || [ "${#ENCRYPTION_KEY}" -lt 16 ]; then
            log_error "Failed to generate a valid encryption key"
            return 1
        fi
        echo ""
        echo -e "${GREEN}${BOLD}  Encryption Key: ${ENCRYPTION_KEY}${NC}"
        echo ""
        echo -e "${YELLOW}  IMPORTANT: Save this key! Clients need it to connect.${NC}"
        echo ""
        SOCKS_PORT=""
    else
        echo ""
        echo -e "${BOLD}Remote server address${NC} (IP:PORT):"
        read -p "  Server: " REMOTE_SERVER < /dev/tty || true
        if [ -z "$REMOTE_SERVER" ]; then
            log_error "Remote server address is required."
            exit 1
        fi

        echo ""
        echo -e "${BOLD}Encryption key${NC} (from server setup):"
        read -p "  Key: " ENCRYPTION_KEY < /dev/tty || true
        if [ -z "$ENCRYPTION_KEY" ]; then
            log_error "Encryption key is required."
            exit 1
        fi

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
            echo -e "${BOLD}SOCKS5 listen port${NC} [1080]:"
            read -p "  SOCKS port: " input < /dev/tty || true
            SOCKS_PORT="${input:-1080}"
            if ! [[ "$SOCKS_PORT" =~ ^[0-9]+$ ]] || [ "$SOCKS_PORT" -lt 1 ] || [ "$SOCKS_PORT" -gt 65535 ]; then
                log_warn "Invalid port. Using default 1080."
                SOCKS_PORT=1080
            fi
        fi
        LISTEN_PORT=""
    fi

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
    case "$p_choice" in
        2)
            KCP_PROFILE="highloss"; KCP_CONN=4; KCP_MTU=1300; KCP_SNDWND=1024; KCP_RCVWND=1024
            KCP_NODELAY=0; KCP_INTERVAL=20; KCP_RESEND=2; KCP_NOCONGESTION=0; KCP_SOCKBUF=4194304; KCP_SMUXBUF=4194304 ;;
        3)
            KCP_PROFILE="cdntunnel"; KCP_CONN=8; KCP_MTU=1400; KCP_SNDWND=2048; KCP_RCVWND=2048
            KCP_NODELAY=0; KCP_INTERVAL=20; KCP_RESEND=2; KCP_NOCONGESTION=0; KCP_SOCKBUF=8388608; KCP_SMUXBUF=8388608 ;;
        4)
            KCP_PROFILE="gaming"; KCP_CONN=2; KCP_MTU=1200; KCP_SNDWND=512; KCP_RCVWND=512
            KCP_NODELAY=1; KCP_INTERVAL=10; KCP_RESEND=2; KCP_NOCONGESTION=1; KCP_SOCKBUF=4194304; KCP_SMUXBUF=4194304 ;;
        *)
            KCP_PROFILE="standard"; KCP_CONN=2; KCP_MTU=1350; KCP_SNDWND=1024; KCP_RCVWND=1024
            KCP_NODELAY=0; KCP_INTERVAL=20; KCP_RESEND=2; KCP_NOCONGESTION=0; KCP_SOCKBUF=4194304; KCP_SMUXBUF=4194304 ;;
    esac

    # Generate YAML config
    generate_config
}

_wizard_gfk() {
    if [ "$ROLE" = "server" ]; then
        # Server IP (this machine's public IP)
        detect_network
        echo ""
        echo -e "${BOLD}This server's public IP${NC} [${DETECTED_IP:-}]:"
        read -p "  IP: " input < /dev/tty || true
        GFK_SERVER_IP="${input:-$DETECTED_IP}"
        if [ -z "$GFK_SERVER_IP" ] || ! _validate_ip "$GFK_SERVER_IP"; then
            log_error "Valid server IP is required."
            exit 1
        fi

        # VIO TCP port (must be closed to OS, raw socket handles it)
        echo ""
        echo -e "${BOLD}VIO TCP port${NC} [45000] (raw socket port, must be blocked by firewall):"
        read -p "  Port: " input < /dev/tty || true
        GFK_VIO_PORT="${input:-45000}"
        if ! _validate_port "$GFK_VIO_PORT"; then
            log_warn "Invalid port. Using default 45000."
            GFK_VIO_PORT=45000
        fi

        # QUIC port
        echo ""
        echo -e "${BOLD}QUIC tunnel port${NC} [25000]:"
        read -p "  Port: " input < /dev/tty || true
        GFK_QUIC_PORT="${input:-25000}"
        if ! _validate_port "$GFK_QUIC_PORT"; then
            log_warn "Invalid port. Using default 25000."
            GFK_QUIC_PORT=25000
        fi

        # Auth code
        echo ""
        local auto_auth
        auto_auth=$(openssl rand -base64 16 2>/dev/null | tr -d '=+/' | head -c 16)
        echo -e "${BOLD}QUIC auth code${NC} [auto-generated]:"
        read -p "  Auth code: " input < /dev/tty || true
        GFK_AUTH_CODE="${input:-$auto_auth}"
        echo ""
        echo -e "${GREEN}${BOLD}  Auth Code: ${GFK_AUTH_CODE}${NC}"
        echo ""
        echo -e "${YELLOW}  IMPORTANT: Save this auth code! Clients need it to connect.${NC}"
        echo ""

        # Port mappings
        echo -e "${BOLD}TCP port mappings${NC} (local:remote, comma-separated) [14000:443]:"
        echo -e "  ${DIM}Example: 14000:443,15000:2096,16000:10809${NC}"
        read -p "  Mappings: " input < /dev/tty || true
        GFK_PORT_MAPPINGS="${input:-14000:443}"
        MICROSOCKS_PORT=""

    else
        # Client: server IP
        echo ""
        echo -e "${BOLD}Remote server IP${NC} (server's public IP):"
        read -p "  Server IP: " GFK_SERVER_IP < /dev/tty || true
        if [ -z "$GFK_SERVER_IP" ] || ! _validate_ip "$GFK_SERVER_IP"; then
            log_error "Valid server IP is required."
            exit 1
        fi

        # Server's VIO TCP port (what port the server is listening on)
        echo ""
        echo -e "${BOLD}Server's VIO TCP port${NC} [45000] (must match server config):"
        read -p "  Port: " input < /dev/tty || true
        GFK_VIO_PORT="${input:-45000}"
        if ! _validate_port "$GFK_VIO_PORT"; then
            log_warn "Invalid port. Using default 45000."
            GFK_VIO_PORT=45000
        fi

        # Local VIO client port (client's local binding)
        echo ""
        echo -e "${BOLD}Local VIO client port${NC} [40000]:"
        read -p "  Port: " input < /dev/tty || true
        GFK_VIO_CLIENT_PORT="${input:-40000}"
        if ! _validate_port "$GFK_VIO_CLIENT_PORT"; then
            log_warn "Invalid port. Using default 40000."
            GFK_VIO_CLIENT_PORT=40000
        fi

        # Server's QUIC port
        echo ""
        echo -e "${BOLD}Server's QUIC port${NC} [25000] (must match server config):"
        read -p "  Port: " input < /dev/tty || true
        GFK_QUIC_PORT="${input:-25000}"
        if ! _validate_port "$GFK_QUIC_PORT"; then
            log_warn "Invalid port. Using default 25000."
            GFK_QUIC_PORT=25000
        fi

        # Local QUIC client port
        echo ""
        echo -e "${BOLD}Local QUIC client port${NC} [20000]:"
        read -p "  Port: " input < /dev/tty || true
        GFK_QUIC_CLIENT_PORT="${input:-20000}"
        if ! _validate_port "$GFK_QUIC_CLIENT_PORT"; then
            log_warn "Invalid port. Using default 20000."
            GFK_QUIC_CLIENT_PORT=20000
        fi

        # Auth code (from server)
        echo ""
        echo -e "${BOLD}QUIC auth code${NC} (from server setup):"
        read -p "  Auth code: " GFK_AUTH_CODE < /dev/tty || true
        if [ -z "$GFK_AUTH_CODE" ]; then
            log_error "Auth code is required."
            exit 1
        fi

        # Port mappings (must match server)
        echo ""
        echo -e "${BOLD}TCP port mappings${NC} (must match server) [14000:443]:"
        read -p "  Mappings: " input < /dev/tty || true
        GFK_PORT_MAPPINGS="${input:-14000:443}"
    fi

    # Generate GFK config
    generate_gfk_config
}

generate_config() {
    log_info "Generating paqet configuration..."

    # Validate required fields
    if [ -z "$IFACE" ] || [ -z "$LOCAL_IP" ] || [ -z "$GW_MAC" ] || [ -z "$ENCRYPTION_KEY" ]; then
        log_error "Missing required configuration fields (interface, ip, gateway_mac, or secret)"
        return 1
    fi
    if [ "$ROLE" = "server" ]; then
        if [ -z "$LISTEN_PORT" ]; then log_error "Missing listen port"; return 1; fi
    else
        if [ -z "$REMOTE_SERVER" ] || [ -z "$SOCKS_PORT" ]; then
            log_error "Missing server address or SOCKS port"
            return 1
        fi
        local _rs_ip="${REMOTE_SERVER%:*}" _rs_port="${REMOTE_SERVER##*:}"
        if ! _validate_ip "$_rs_ip" || ! _validate_port "$_rs_port"; then
            log_error "Server address must be valid IP:PORT (e.g. 1.2.3.4:8443)"
            return 1
        fi
    fi

    # Ensure install directory exists
    mkdir -p "$INSTALL_DIR" || { log_error "Failed to create $INSTALL_DIR"; return 1; }

    local tmp_conf
    tmp_conf=$(mktemp "$INSTALL_DIR/config.yaml.XXXXXXXX") || { log_error "Failed to create temp file"; return 1; }
    # Set permissions on temp file before writing (fixes race condition)
    chmod 600 "$tmp_conf" 2>/dev/null

    (
    umask 077
    generate_paqet_yaml "$tmp_conf"
    )
    if ! mv "$tmp_conf" "$INSTALL_DIR/config.yaml"; then
        log_error "Failed to save configuration file"
        rm -f "$tmp_conf"
        return 1
    fi
    # Ensure final permissions (mv preserves source permissions on most systems)
    chmod 600 "$INSTALL_DIR/config.yaml" 2>/dev/null
    log_success "Configuration saved to $INSTALL_DIR/config.yaml"
}
#═══════════════════════════════════════════════════════════════════════
# Firewall Management
#═══════════════════════════════════════════════════════════════════════

apply_iptables_rules() {
    local port="$1"
    if [ -z "$port" ]; then
        log_error "No port specified for iptables rules"
        return 1
    fi

    log_info "Applying firewall rules for port $port..."

    # firewalld path (Fedora/RHEL)
    if _is_firewalld_active; then
        firewall-cmd --direct --query-rule ipv4 raw PREROUTING 0 -p tcp --dport "$port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || \
        firewall-cmd --direct --add-rule ipv4 raw PREROUTING 0 -p tcp --dport "$port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || \
            { log_error "Failed to add PREROUTING NOTRACK rule via firewalld"; return 1; }
        firewall-cmd --direct --query-rule ipv4 raw OUTPUT 0 -p tcp --sport "$port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || \
        firewall-cmd --direct --add-rule ipv4 raw OUTPUT 0 -p tcp --sport "$port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || \
            { log_error "Failed to add OUTPUT NOTRACK rule via firewalld"; return 1; }
        firewall-cmd --direct --query-rule ipv4 mangle OUTPUT 0 -p tcp --sport "$port" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP 2>/dev/null || \
        firewall-cmd --direct --add-rule ipv4 mangle OUTPUT 0 -p tcp --sport "$port" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP 2>/dev/null || \
            { log_error "Failed to add RST DROP rule via firewalld"; return 1; }
        log_success "IPv4 firewalld rules applied"
        # IPv6
        firewall-cmd --direct --add-rule ipv6 raw PREROUTING 0 -p tcp --dport "$port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || true
        firewall-cmd --direct --add-rule ipv6 raw OUTPUT 0 -p tcp --sport "$port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || true
        firewall-cmd --direct --add-rule ipv6 mangle OUTPUT 0 -p tcp --sport "$port" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP 2>/dev/null || true
        persist_iptables_rules
        return 0
    fi

    # iptables path (Debian/Ubuntu/Arch/etc.)
    modprobe iptable_raw 2>/dev/null || true
    modprobe iptable_mangle 2>/dev/null || true

    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
        log_warn "ufw is active — ensure port $port/tcp is allowed: sudo ufw allow $port/tcp"
    fi

    local TAG="paqctl"

    if iptables -t raw -C PREROUTING -p tcp --dport "$port" -m comment --comment "$TAG" -j NOTRACK 2>/dev/null && \
       iptables -t raw -C OUTPUT -p tcp --sport "$port" -m comment --comment "$TAG" -j NOTRACK 2>/dev/null && \
       iptables -t mangle -C OUTPUT -p tcp --sport "$port" -m comment --comment "$TAG" --tcp-flags RST RST -j DROP 2>/dev/null; then
        log_info "iptables rules already in place"
    else
        iptables -t raw -C PREROUTING -p tcp --dport "$port" -m comment --comment "$TAG" -j NOTRACK 2>/dev/null || \
        iptables -t raw -A PREROUTING -p tcp --dport "$port" -m comment --comment "$TAG" -j NOTRACK 2>/dev/null || {
            log_error "Failed to add PREROUTING NOTRACK rule"
            return 1
        }
        iptables -t raw -C OUTPUT -p tcp --sport "$port" -m comment --comment "$TAG" -j NOTRACK 2>/dev/null || \
        iptables -t raw -A OUTPUT -p tcp --sport "$port" -m comment --comment "$TAG" -j NOTRACK 2>/dev/null || {
            log_error "Failed to add OUTPUT NOTRACK rule"
            return 1
        }
        iptables -t mangle -C OUTPUT -p tcp --sport "$port" -m comment --comment "$TAG" --tcp-flags RST RST -j DROP 2>/dev/null || \
        iptables -t mangle -A OUTPUT -p tcp --sport "$port" -m comment --comment "$TAG" --tcp-flags RST RST -j DROP 2>/dev/null || {
            log_error "Failed to add RST DROP rule"
            return 1
        }
        log_success "IPv4 iptables rules applied"
    fi

    if command -v ip6tables &>/dev/null; then
        local _ipv6_ok=true
        ip6tables -t raw -C PREROUTING -p tcp --dport "$port" -m comment --comment "$TAG" -j NOTRACK 2>/dev/null || \
            ip6tables -t raw -A PREROUTING -p tcp --dport "$port" -m comment --comment "$TAG" -j NOTRACK 2>/dev/null || _ipv6_ok=false
        ip6tables -t raw -C OUTPUT -p tcp --sport "$port" -m comment --comment "$TAG" -j NOTRACK 2>/dev/null || \
            ip6tables -t raw -A OUTPUT -p tcp --sport "$port" -m comment --comment "$TAG" -j NOTRACK 2>/dev/null || _ipv6_ok=false
        ip6tables -t mangle -C OUTPUT -p tcp --sport "$port" -m comment --comment "$TAG" --tcp-flags RST RST -j DROP 2>/dev/null || \
            ip6tables -t mangle -A OUTPUT -p tcp --sport "$port" -m comment --comment "$TAG" --tcp-flags RST RST -j DROP 2>/dev/null || _ipv6_ok=false
        if [ "$_ipv6_ok" = true ]; then
            log_success "IPv6 iptables rules applied"
        else
            log_warn "Some IPv6 iptables rules failed (IPv6 may not be available)"
        fi
    fi

    # Persist rules
    persist_iptables_rules
}

remove_iptables_rules() {
    local port="$1"
    if [ -z "$port" ]; then return 0; fi

    log_info "Removing firewall rules for port $port..."

    # firewalld path
    if _is_firewalld_active; then
        firewall-cmd --direct --remove-rule ipv4 raw PREROUTING 0 -p tcp --dport "$port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || true
        firewall-cmd --direct --remove-rule ipv4 raw OUTPUT 0 -p tcp --sport "$port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || true
        firewall-cmd --direct --remove-rule ipv4 mangle OUTPUT 0 -p tcp --sport "$port" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP 2>/dev/null || true
        firewall-cmd --direct --remove-rule ipv4 filter INPUT 0 -p tcp --dport "$port" -m comment --comment "paqctl" -j DROP 2>/dev/null || true
        firewall-cmd --direct --remove-rule ipv4 filter OUTPUT 0 -p tcp --sport "$port" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP 2>/dev/null || true
        # IPv6
        firewall-cmd --direct --remove-rule ipv6 raw PREROUTING 0 -p tcp --dport "$port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || true
        firewall-cmd --direct --remove-rule ipv6 raw OUTPUT 0 -p tcp --sport "$port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || true
        firewall-cmd --direct --remove-rule ipv6 mangle OUTPUT 0 -p tcp --sport "$port" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP 2>/dev/null || true
        firewall-cmd --direct --remove-rule ipv6 filter INPUT 0 -p tcp --dport "$port" -m comment --comment "paqctl" -j DROP 2>/dev/null || true
        firewall-cmd --direct --remove-rule ipv6 filter OUTPUT 0 -p tcp --sport "$port" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP 2>/dev/null || true
        log_success "firewalld rules removed"
        return 0
    fi

    # iptables path
    local TAG="paqctl"
    iptables -t raw -D PREROUTING -p tcp --dport "$port" -m comment --comment "$TAG" -j NOTRACK 2>/dev/null || true
    iptables -t raw -D OUTPUT -p tcp --sport "$port" -m comment --comment "$TAG" -j NOTRACK 2>/dev/null || true
    iptables -t mangle -D OUTPUT -p tcp --sport "$port" -m comment --comment "$TAG" --tcp-flags RST RST -j DROP 2>/dev/null || true
    iptables -t raw -D PREROUTING -p tcp --dport "$port" -j NOTRACK 2>/dev/null || true
    iptables -t raw -D OUTPUT -p tcp --sport "$port" -j NOTRACK 2>/dev/null || true
    iptables -t mangle -D OUTPUT -p tcp --sport "$port" --tcp-flags RST RST -j DROP 2>/dev/null || true
    if command -v ip6tables &>/dev/null; then
        ip6tables -t raw -D PREROUTING -p tcp --dport "$port" -m comment --comment "$TAG" -j NOTRACK 2>/dev/null || true
        ip6tables -t raw -D OUTPUT -p tcp --sport "$port" -m comment --comment "$TAG" -j NOTRACK 2>/dev/null || true
        ip6tables -t mangle -D OUTPUT -p tcp --sport "$port" -m comment --comment "$TAG" --tcp-flags RST RST -j DROP 2>/dev/null || true
        ip6tables -t raw -D PREROUTING -p tcp --dport "$port" -j NOTRACK 2>/dev/null || true
        ip6tables -t raw -D OUTPUT -p tcp --sport "$port" -j NOTRACK 2>/dev/null || true
        ip6tables -t mangle -D OUTPUT -p tcp --sport "$port" --tcp-flags RST RST -j DROP 2>/dev/null || true
    fi
    log_success "iptables rules removed"
}

check_iptables_rules() {
    local port="$1"
    if [ -z "$port" ]; then return 1; fi

    local ok=true

    if _is_firewalld_active; then
        firewall-cmd --direct --query-rule ipv4 raw PREROUTING 0 -p tcp --dport "$port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || ok=false
        firewall-cmd --direct --query-rule ipv4 raw OUTPUT 0 -p tcp --sport "$port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || ok=false
        firewall-cmd --direct --query-rule ipv4 mangle OUTPUT 0 -p tcp --sport "$port" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP 2>/dev/null || ok=false
    else
        local TAG="paqctl"
        iptables -t raw -C PREROUTING -p tcp --dport "$port" -m comment --comment "$TAG" -j NOTRACK 2>/dev/null || ok=false
        iptables -t raw -C OUTPUT -p tcp --sport "$port" -m comment --comment "$TAG" -j NOTRACK 2>/dev/null || ok=false
        iptables -t mangle -C OUTPUT -p tcp --sport "$port" -m comment --comment "$TAG" --tcp-flags RST RST -j DROP 2>/dev/null || ok=false
    fi

    if [ "$ok" = true ]; then
        return 0
    else
        return 1
    fi
}
#═══════════════════════════════════════════════════════════════════════
# Service Management
#═══════════════════════════════════════════════════════════════════════

setup_service() {
    log_info "Setting up auto-start on boot..."

    # Check which backends are installed
    local paqet_installed=false gfk_installed=false
    [ -f "$INSTALL_DIR/bin/paqet" ] && paqet_installed=true
    if [ "$ROLE" = "server" ]; then
        [ -d "$GFK_DIR" ] && [ -f "$GFK_DIR/quic_server.py" ] && gfk_installed=true
    else
        [ -d "$GFK_DIR" ] && [ -f "$GFK_DIR/quic_client.py" ] && gfk_installed=true
    fi

    # If both backends are installed, create a combined service
    local _both_installed=false
    [ "$paqet_installed" = true ] && [ "$gfk_installed" = true ] && _both_installed=true

    # Compute ExecStart based on backend
    local _exec_start _working_dir _svc_desc _svc_type="simple"
    if [ "$_both_installed" = true ]; then
        _svc_desc="Paqet Combined Proxy Service (Paqet + GFK)"
        _working_dir="${INSTALL_DIR}"
        _svc_type="forking"
        # Create a wrapper script that starts both backends
        cat > "${INSTALL_DIR}/bin/start-both.sh" << BOTH_SCRIPT
#!/bin/bash
INSTALL_DIR="/opt/paqctl"
GFK_DIR="\${INSTALL_DIR}/gfk"
ROLE="${ROLE}"

# Source config for ports
[ -f "\${INSTALL_DIR}/settings.conf" ] && . "\${INSTALL_DIR}/settings.conf"

# Detect firewall backend
_use_firewalld=false
if command -v firewall-cmd &>/dev/null && firewall-cmd --state 2>/dev/null | grep -q running; then
    _use_firewalld=true
fi

# Apply firewall rules (server + client)
if [ "\$ROLE" = "server" ]; then
    port="\${LISTEN_PORT:-8443}"
    vio_port="\${GFK_VIO_PORT:-45000}"
    TAG="paqctl"
    if [ "\$_use_firewalld" = true ]; then
        # Paqet rules via firewalld
        firewall-cmd --direct --add-rule ipv4 raw PREROUTING 0 -p tcp --dport "\$port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || true
        firewall-cmd --direct --add-rule ipv4 raw OUTPUT 0 -p tcp --sport "\$port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || true
        firewall-cmd --direct --add-rule ipv4 mangle OUTPUT 0 -p tcp --sport "\$port" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP 2>/dev/null || true
        # GFK rules via firewalld
        firewall-cmd --direct --add-rule ipv4 raw PREROUTING 0 -p tcp --dport "\$vio_port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || true
        firewall-cmd --direct --add-rule ipv4 raw OUTPUT 0 -p tcp --sport "\$vio_port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || true
        firewall-cmd --direct --add-rule ipv4 filter INPUT 0 -p tcp --dport "\$vio_port" -m comment --comment "paqctl" -j DROP 2>/dev/null || true
        firewall-cmd --direct --add-rule ipv4 filter OUTPUT 0 -p tcp --sport "\$vio_port" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP 2>/dev/null || true
        # IPv6 GFK
        firewall-cmd --direct --add-rule ipv6 filter INPUT 0 -p tcp --dport "\$vio_port" -m comment --comment "paqctl" -j DROP 2>/dev/null || true
        firewall-cmd --direct --add-rule ipv6 filter OUTPUT 0 -p tcp --sport "\$vio_port" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP 2>/dev/null || true
        firewall-cmd --runtime-to-permanent 2>/dev/null || true
    else
        # Paqet rules via iptables
        modprobe iptable_raw 2>/dev/null || true
        modprobe iptable_mangle 2>/dev/null || true
        iptables -t raw -C PREROUTING -p tcp --dport "\$port" -m comment --comment "\$TAG" -j NOTRACK 2>/dev/null || \\
            iptables -t raw -A PREROUTING -p tcp --dport "\$port" -m comment --comment "\$TAG" -j NOTRACK 2>/dev/null
        iptables -t raw -C OUTPUT -p tcp --sport "\$port" -m comment --comment "\$TAG" -j NOTRACK 2>/dev/null || \\
            iptables -t raw -A OUTPUT -p tcp --sport "\$port" -m comment --comment "\$TAG" -j NOTRACK 2>/dev/null
        iptables -t mangle -C OUTPUT -p tcp --sport "\$port" -m comment --comment "\$TAG" --tcp-flags RST RST -j DROP 2>/dev/null || \\
            iptables -t mangle -A OUTPUT -p tcp --sport "\$port" -m comment --comment "\$TAG" --tcp-flags RST RST -j DROP 2>/dev/null
        # GFK rules via iptables
        modprobe iptable_raw 2>/dev/null || true
        iptables -t raw -C PREROUTING -p tcp --dport "\$vio_port" -m comment --comment "\$TAG" -j NOTRACK 2>/dev/null || \\
            iptables -t raw -A PREROUTING -p tcp --dport "\$vio_port" -m comment --comment "\$TAG" -j NOTRACK 2>/dev/null
        iptables -t raw -C OUTPUT -p tcp --sport "\$vio_port" -m comment --comment "\$TAG" -j NOTRACK 2>/dev/null || \\
            iptables -t raw -A OUTPUT -p tcp --sport "\$vio_port" -m comment --comment "\$TAG" -j NOTRACK 2>/dev/null
        iptables -C INPUT -p tcp --dport "\$vio_port" -m comment --comment "\$TAG" -j DROP 2>/dev/null || \\
            iptables -A INPUT -p tcp --dport "\$vio_port" -m comment --comment "\$TAG" -j DROP 2>/dev/null
        iptables -C OUTPUT -p tcp --sport "\$vio_port" --tcp-flags RST RST -m comment --comment "\$TAG" -j DROP 2>/dev/null || \\
            iptables -A OUTPUT -p tcp --sport "\$vio_port" --tcp-flags RST RST -m comment --comment "\$TAG" -j DROP 2>/dev/null
        if command -v ip6tables &>/dev/null; then
            ip6tables -C INPUT -p tcp --dport "\$vio_port" -m comment --comment "\$TAG" -j DROP 2>/dev/null || \\
                ip6tables -A INPUT -p tcp --dport "\$vio_port" -m comment --comment "\$TAG" -j DROP 2>/dev/null || true
            ip6tables -C OUTPUT -p tcp --sport "\$vio_port" --tcp-flags RST RST -m comment --comment "\$TAG" -j DROP 2>/dev/null || \\
                ip6tables -A OUTPUT -p tcp --sport "\$vio_port" --tcp-flags RST RST -m comment --comment "\$TAG" -j DROP 2>/dev/null || true
        fi
    fi
else
    # GFK client firewall rules
    vio_client_port="\${GFK_VIO_CLIENT_PORT:-40000}"
    TAG="paqctl"
    if [ "\$_use_firewalld" = true ]; then
        firewall-cmd --direct --add-rule ipv4 raw PREROUTING 0 -p tcp --dport "\$vio_client_port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || true
        firewall-cmd --direct --add-rule ipv4 raw OUTPUT 0 -p tcp --sport "\$vio_client_port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || true
        firewall-cmd --direct --add-rule ipv4 filter INPUT 0 -p tcp --dport "\$vio_client_port" -m comment --comment "paqctl" -j DROP 2>/dev/null || true
        firewall-cmd --direct --add-rule ipv4 filter OUTPUT 0 -p tcp --sport "\$vio_client_port" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP 2>/dev/null || true
        firewall-cmd --direct --add-rule ipv6 filter INPUT 0 -p tcp --dport "\$vio_client_port" -m comment --comment "paqctl" -j DROP 2>/dev/null || true
        firewall-cmd --direct --add-rule ipv6 filter OUTPUT 0 -p tcp --sport "\$vio_client_port" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP 2>/dev/null || true
        firewall-cmd --runtime-to-permanent 2>/dev/null || true
    else
        modprobe iptable_raw 2>/dev/null || true
        iptables -t raw -C PREROUTING -p tcp --dport "\$vio_client_port" -m comment --comment "\$TAG" -j NOTRACK 2>/dev/null || \\
            iptables -t raw -A PREROUTING -p tcp --dport "\$vio_client_port" -m comment --comment "\$TAG" -j NOTRACK 2>/dev/null
        iptables -t raw -C OUTPUT -p tcp --sport "\$vio_client_port" -m comment --comment "\$TAG" -j NOTRACK 2>/dev/null || \\
            iptables -t raw -A OUTPUT -p tcp --sport "\$vio_client_port" -m comment --comment "\$TAG" -j NOTRACK 2>/dev/null
        iptables -C INPUT -p tcp --dport "\$vio_client_port" -m comment --comment "\$TAG" -j DROP 2>/dev/null || \\
            iptables -A INPUT -p tcp --dport "\$vio_client_port" -m comment --comment "\$TAG" -j DROP 2>/dev/null
        iptables -C OUTPUT -p tcp --sport "\$vio_client_port" --tcp-flags RST RST -m comment --comment "\$TAG" -j DROP 2>/dev/null || \\
            iptables -A OUTPUT -p tcp --sport "\$vio_client_port" --tcp-flags RST RST -m comment --comment "\$TAG" -j DROP 2>/dev/null
        if command -v ip6tables &>/dev/null; then
            ip6tables -C INPUT -p tcp --dport "\$vio_client_port" -m comment --comment "\$TAG" -j DROP 2>/dev/null || \\
                ip6tables -A INPUT -p tcp --dport "\$vio_client_port" -m comment --comment "\$TAG" -j DROP 2>/dev/null || true
            ip6tables -C OUTPUT -p tcp --sport "\$vio_client_port" --tcp-flags RST RST -m comment --comment "\$TAG" -j DROP 2>/dev/null || \\
                ip6tables -A OUTPUT -p tcp --sport "\$vio_client_port" --tcp-flags RST RST -m comment --comment "\$TAG" -j DROP 2>/dev/null || true
        fi
    fi
fi

# Start paqet backend
(umask 077; touch /var/log/paqet-backend.log)
nohup "\${INSTALL_DIR}/bin/paqet" run -c "\${INSTALL_DIR}/config.yaml" > /var/log/paqet-backend.log 2>&1 &
echo \$! > /run/paqet-backend.pid

# Start GFK backend
(umask 077; touch /var/log/gfk-backend.log)
if [ "\$ROLE" = "server" ]; then
    # Start Xray if available
    if command -v xray &>/dev/null || [ -x /usr/local/bin/xray ] || [ -x /usr/local/x-ui/bin/xray-linux-amd64 ]; then
        if ! pgrep -f "xray run" &>/dev/null; then
            systemctl start xray 2>/dev/null || xray run -c /usr/local/etc/xray/config.json &>/dev/null &
            sleep 2
        fi
    fi
    cd "\$GFK_DIR"
    nohup "\${INSTALL_DIR}/venv/bin/python" "\${GFK_DIR}/mainserver.py" > /var/log/gfk-backend.log 2>&1 &
else
    if [ -x "\${INSTALL_DIR}/bin/gfk-client.sh" ]; then
        nohup "\${INSTALL_DIR}/bin/gfk-client.sh" > /var/log/gfk-backend.log 2>&1 &
    else
        cd "\$GFK_DIR"
        nohup "\${INSTALL_DIR}/venv/bin/python" "\${GFK_DIR}/mainclient.py" > /var/log/gfk-backend.log 2>&1 &
    fi
fi
echo \$! > /run/gfk-backend.pid

sleep 1
exit 0
BOTH_SCRIPT
        chmod +x "${INSTALL_DIR}/bin/start-both.sh"
        _exec_start="${INSTALL_DIR}/bin/start-both.sh"
    elif [ "$BACKEND" = "gfw-knocker" ]; then
        _svc_desc="GFW-knocker Proxy Service"
        _working_dir="${GFK_DIR}"
        if [ "$ROLE" = "server" ]; then
            _exec_start="${INSTALL_DIR}/venv/bin/python ${GFK_DIR}/mainserver.py"
        else
            _exec_start="${INSTALL_DIR}/bin/gfk-client.sh"
        fi
    else
        _svc_desc="Paqet Proxy Service"
        _working_dir="${INSTALL_DIR}"
        _exec_start="${INSTALL_DIR}/bin/paqet run -c ${INSTALL_DIR}/config.yaml"
    fi

    if [ "$HAS_SYSTEMD" = "true" ]; then
        if [ "$_both_installed" = true ]; then
            # Combined service for both backends
            cat > /etc/systemd/system/paqctl.service << EOF
[Unit]
Description=${_svc_desc}
After=network-online.target
Wants=network-online.target

[Service]
Type=${_svc_type}
WorkingDirectory=${_working_dir}
ExecStart=${_exec_start}
ExecStop=/usr/local/bin/paqctl stop
ExecStopPost=/usr/local/bin/paqctl _remove-firewall
RemainAfterExit=yes
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=30
LimitNOFILE=65535
StandardOutput=journal
StandardError=journal
SyslogIdentifier=paqctl

[Install]
WantedBy=multi-user.target
EOF
        else
            # Single backend service
            cat > /etc/systemd/system/paqctl.service << EOF
[Unit]
Description=${_svc_desc}
After=network-online.target
Wants=network-online.target

[Service]
Type=${_svc_type}
WorkingDirectory=${_working_dir}
ExecStartPre=/usr/local/bin/paqctl _apply-firewall
ExecStart=${_exec_start}
ExecStopPost=/usr/local/bin/paqctl _remove-firewall
Restart=on-failure
RestartSec=5
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=30
LimitNOFILE=65535
StandardOutput=journal
StandardError=journal
SyslogIdentifier=paqctl

[Install]
WantedBy=multi-user.target
EOF
        fi

        systemctl daemon-reload 2>/dev/null || true
        systemctl enable paqctl.service 2>/dev/null || true
        log_success "Systemd service created and enabled"

    elif command -v rc-update &>/dev/null; then
        local _openrc_run
        _openrc_run=$(command -v openrc-run 2>/dev/null || echo "/sbin/openrc-run")
        cat > /etc/init.d/paqctl << EOF
#!${_openrc_run}

name="paqctl"
description="${_svc_desc}"
command="$(echo "${_exec_start}" | awk '{print $1}')"
command_args="$(echo "${_exec_start}" | cut -d' ' -f2-)"
if [ "\$command_args" = "\$command" ]; then command_args=""; fi
command_background=true
pidfile="/run/\${RC_SVCNAME}.pid"

depend() {
    need net
    after firewall
}

start_pre() {
    /usr/local/bin/paqctl _apply-firewall
}

stop_post() {
    /usr/local/bin/paqctl _remove-firewall
}
EOF
        if ! chmod +x /etc/init.d/paqctl; then
            log_error "Failed to make init script executable"
            return 1
        fi
        rc-update add paqctl default 2>/dev/null || true
        log_success "OpenRC service created and enabled"

    elif [ -d /etc/init.d ]; then
        cat > /etc/init.d/paqctl << SYSV
#!/bin/bash
### BEGIN INIT INFO
# Provides:          paqctl
# Required-Start:    \$remote_fs \$network \$syslog
# Required-Stop:     \$remote_fs \$network \$syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: ${_svc_desc}
### END INIT INFO

case "\$1" in
    start)
        /usr/local/bin/paqctl _apply-firewall
        ${_exec_start} &
        _pid=\$!
        sleep 1
        if kill -0 "\$_pid" 2>/dev/null; then
            echo \$_pid > /run/paqctl.pid
        else
            echo "Failed to start paqet"
            /usr/local/bin/paqctl _remove-firewall
            exit 1
        fi
        ;;
    stop)
        if [ -f /run/paqctl.pid ]; then
            _pid=\$(cat /run/paqctl.pid)
            kill "\$_pid" 2>/dev/null
            _count=0
            while kill -0 "\$_pid" 2>/dev/null && [ \$_count -lt 10 ]; do
                sleep 1
                _count=\$((_count + 1))
            done
            kill -0 "\$_pid" 2>/dev/null && kill -9 "\$_pid" 2>/dev/null
            rm -f /run/paqctl.pid
        fi
        /usr/local/bin/paqctl _remove-firewall
        ;;
    restart)
        \$0 stop
        sleep 1
        \$0 start
        ;;
    status)
        [ -f /run/paqctl.pid ] && kill -0 "\$(cat /run/paqctl.pid)" 2>/dev/null && echo "Running" || echo "Stopped"
        ;;
    *)
        echo "Usage: \$0 {start|stop|restart|status}"
        exit 1
        ;;
esac
SYSV
        if ! chmod +x /etc/init.d/paqctl; then
            log_error "Failed to make init script executable"
            return 1
        fi
        if command -v update-rc.d &>/dev/null; then
            update-rc.d paqctl defaults 2>/dev/null || true
        elif command -v chkconfig &>/dev/null; then
            chkconfig paqctl on 2>/dev/null || true
        fi
        log_success "SysVinit service created and enabled"

    else
        log_warn "Could not set up auto-start. You can start paqet manually with: sudo paqctl start"
    fi
}

setup_logrotate() {
    # Only set up if logrotate is available
    command -v logrotate &>/dev/null || return 0

    log_info "Setting up log rotation..."

    cat > /etc/logrotate.d/paqctl << 'LOGROTATE'
/var/log/paqctl.log
/var/log/paqet-backend.log
/var/log/gfk-backend.log
/var/log/xray.log
{
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
    sharedscripts
    postrotate
        # Signal processes to reopen logs if needed
        systemctl reload paqctl.service 2>/dev/null || true
    endscript
}
LOGROTATE

    log_success "Log rotation configured (7 days, compressed)"
}
#═══════════════════════════════════════════════════════════════════════
# Management Script (Embedded)
#═══════════════════════════════════════════════════════════════════════

create_management_script() {
    local tmp_script
    tmp_script=$(mktemp "$INSTALL_DIR/paqctl.XXXXXXXX") || { log_error "Failed to create temp file"; return 1; }
    cat > "$tmp_script" << 'MANAGEMENT'
#!/bin/bash
#
# paqctl - Paqet Manager
# https://github.com/SamNet-dev/paqctl
#

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

INSTALL_DIR="REPLACE_ME_INSTALL_DIR"
# shellcheck shell=bash
# Versions, repositories and colours shared by the installer and the management script.
# INSTALL_DIR must be set before this file is included.

VERSION="1.3.0"

# Pinned versions for stability (update these after testing new releases)
PAQET_VERSION_PINNED="v1.0.0-alpha.21-a1"
XRAY_VERSION_PINNED="v26.2.4"
GFK_VERSION_PINNED="v1.0.0"

PAQET_REPO="4H1R/paqet"
PAQET_API_URL="https://api.github.com/repos/${PAQET_REPO}/releases/latest"
GFK_REPO="4H1R/paqctl"
GFK_BRANCH="main"
GFK_RAW_URL="https://raw.githubusercontent.com/${GFK_REPO}/${GFK_BRANCH}/gfk"
MICROSOCKS_REPO="rofl0r/microsocks"

BACKUP_DIR="$INSTALL_DIR/backups"
GFK_DIR="$INSTALL_DIR/gfk"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# Global flags (accepted anywhere on the command line, before an optional "--")
#   -y, --yes    answer yes to confirmation prompts
#   --json       machine-readable output where supported
#   --no-color   disable colours (also honours NO_COLOR and non-terminal output)
ASSUME_YES=false
JSON_OUTPUT=false
MENU_MODE=false
_paqctl_args=()
_paqctl_flags_done=false
for _paqctl_a in "$@"; do
    if [ "$_paqctl_flags_done" = true ]; then
        _paqctl_args+=("$_paqctl_a")
        continue
    fi
    case "$_paqctl_a" in
        -y|--yes)   ASSUME_YES=true ;;
        --json)     JSON_OUTPUT=true ;;
        --no-color|--no-colour) NO_COLOR=1 ;;
        --)         _paqctl_flags_done=true ;;
        *)          _paqctl_args+=("$_paqctl_a") ;;
    esac
done
set -- "${_paqctl_args[@]}"
unset _paqctl_a _paqctl_flags_done

if [ -n "${NO_COLOR:-}" ] || [ ! -t 1 ] || [ "$JSON_OUTPUT" = true ]; then
    RED='' GREEN='' YELLOW='' BLUE='' CYAN='' MAGENTA='' BOLD='' DIM='' NC=''
fi

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
# paqet config.yaml
#═══════════════════════════════════════════════════════════════════════

# Escape a value for use inside a double-quoted YAML string. Callers always
# write the quotes themselves, so this never adds any.
_escape_yaml() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/}"
    s="${s//$'\r'/}"
    printf '%s' "$s"
}

# KCP mode in the current config.yaml (transport.kcp.mode), if any
_current_kcp_mode() {
    [ -f "$INSTALL_DIR/config.yaml" ] || return 0
    awk '/^  kcp:/{k=1; next} k && /^[^ ]|^  [^ ]/{k=0} k && /^    mode:/{gsub(/["\047]/, "", $2); print $2; exit}' "$INSTALL_DIR/config.yaml" 2>/dev/null || true
}

generate_paqet_yaml() {
    local target_file="$1"
    local _y_iface _y_ip _y_mac _y_key _y_server _tcp_local_flags _tcp_remote_flags
    _y_iface=$(_escape_yaml "${INTERFACE:-${IFACE:-eth0}}")
    _y_ip=$(_escape_yaml "${LOCAL_IP:-}")
    _y_mac=$(_escape_yaml "${GATEWAY_MAC:-${GW_MAC:-}}")
    _y_key=$(_escape_yaml "${ENCRYPTION_KEY:-${KEY:-}}")
    _tcp_local_flags=$(echo "${PAQET_TCP_LOCAL_FLAG:-PA}" | sed 's/,/", "/g; s/.*/["&"]/')
    _tcp_remote_flags=$(echo "${PAQET_TCP_REMOTE_FLAG:-PA}" | sed 's/,/", "/g; s/.*/["&"]/')

    # KCP mode: setting > mode already in config.yaml > "fast". Keeping the
    # current mode means regenerating (config set, rotate-key, import...) never
    # silently changes how an existing server behaves.
    local _mode="${KCP_MODE:-}"
    [ -n "$_mode" ] || _mode=$(_current_kcp_mode)
    case "$_mode" in normal|fast|fast2|fast3|manual) ;; *) _mode="fast" ;; esac
    # nodelay/interval/resend/nocongestion only take effect in manual mode
    local _manual=""
    if [ "$_mode" = "manual" ]; then
        _manual="
    nodelay: ${KCP_NODELAY:-0}
    interval: ${KCP_INTERVAL:-20}
    resend: ${KCP_RESEND:-2}
    nocongestion: ${KCP_NOCONGESTION:-0}"
    fi

    local _conn="${KCP_CONN:-2}"
    local _mtu="${KCP_MTU:-1350}"
    local _sndwnd="${KCP_SNDWND:-1024}"
    local _rcvwnd="${KCP_RCVWND:-1024}"
    local _nodelay="${KCP_NODELAY:-0}"
    local _interval="${KCP_INTERVAL:-20}"
    local _resend="${KCP_RESEND:-2}"
    local _nocongestion="${KCP_NOCONGESTION:-0}"
    local _sockbuf="${KCP_SOCKBUF:-4194304}"
    local _smuxbuf="${KCP_SMUXBUF:-4194304}"

    if [ "$ROLE" = "server" ]; then
        cat > "$target_file" << EOF
role: "server"

log:
  level: "info"

listen:
  addr: ":${LISTEN_PORT:-8443}"

network:
  interface: "${_y_iface}"
  ipv4:
    addr: "${_y_ip}:${LISTEN_PORT:-8443}"
    router_mac: "${_y_mac}"
  tcp:
    local_flag: ${_tcp_local_flags}
    remote_flag: ${_tcp_remote_flags}
  pcap:
    sockbuf: $(( _sockbuf > 8388608 ? _sockbuf : 8388608 ))

transport:
  protocol: "kcp"
  kcp:
    mode: "${_mode}"${_manual}
    key: "${_y_key}"
    mtu: ${_mtu}
    sndwnd: ${_sndwnd}
    rcvwnd: ${_rcvwnd}
    smuxbuf: ${_smuxbuf}
EOF
    else
        _y_server=$(_escape_yaml "${REMOTE_SERVER:-}")
        local _routing_section=""
        if [ "${ROUTING_MODE:-socks5}" = "forward" ]; then
            _routing_section="forward:
  - listen: \"0.0.0.0:${FORWARD_PORT:-14000}\"
    target: \"${FORWARD_TARGET:-127.0.0.1:80}\""
        else
            _routing_section="socks5:
  - listen: \"127.0.0.1:${SOCKS_PORT:-1080}\""
        fi

        cat > "$target_file" << EOF
role: "client"

log:
  level: "info"

${_routing_section}

network:
  interface: "${_y_iface}"
  ipv4:
    addr: "${_y_ip}:0"
    router_mac: "${_y_mac}"
  tcp:
    local_flag: ${_tcp_local_flags}
    remote_flag: ${_tcp_remote_flags}
  pcap:
    sockbuf: ${_sockbuf}

server:
  addr: "${_y_server}"

transport:
  protocol: "kcp"
  conn: ${_conn}
  kcp:
    mode: "${_mode}"${_manual}
    key: "${_y_key}"
    mtu: ${_mtu}
    sndwnd: ${_sndwnd}
    rcvwnd: ${_rcvwnd}
    smuxbuf: ${_smuxbuf}
EOF
    fi
}

#═══════════════════════════════════════════════════════════════════════
# Firewall persistence
#═══════════════════════════════════════════════════════════════════════

_is_firewalld_active() {
    command -v firewall-cmd &>/dev/null && firewall-cmd --state 2>/dev/null | grep -q running
}

persist_iptables_rules() {
    # The egress guard binds to paqet's running cgroup and cannot be restored
    # at boot (the restore would fail as a whole): keep it out of saved rules.
    # It is rebuilt on every service start.
    if declare -F _egress_guard_active >/dev/null && _egress_guard_active; then
        _egress_guard_remove
        _persist_iptables_rules_now
        _egress_guard_apply >/dev/null 2>&1 || true
        return 0
    fi
    _persist_iptables_rules_now
}

_persist_iptables_rules_now() {
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
            KCP_MODE) [[ "$value" =~ ^(normal|fast|fast2|fast3|manual)?$ ]] && KCP_MODE="$value" ;;
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
            EGRESS_GUARD) [[ "$value" =~ ^(true|false)$ ]] && EGRESS_GUARD="$value" ;;
            EGRESS_ALLOW) _egress_valid_allow "$value" && EGRESS_ALLOW="$value" ;;
        esac
    done < <(grep '^[A-Z_][A-Z_0-9]*=' "$INSTALL_DIR/settings.conf")
    # An invalid value on the last line must not make loading "fail"
    return 0
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
KCP_MODE="${KCP_MODE:-}"
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
EGRESS_GUARD="${EGRESS_GUARD:-true}"
EGRESS_ALLOW="${EGRESS_ALLOW:-}"
SEOF
    )
    if ! mv "$_tmp" "$INSTALL_DIR/settings.conf"; then
        log_error "Failed to save settings"
        rm -f "$_tmp"
        return 1
    fi
    chmod 600 "$INSTALL_DIR/settings.conf" 2>/dev/null
}
#═══════════════════════════════════════════════════════════════════════
# Egress guard (paqet server)
#
# A paqet server dials whatever address a client asks for. Without this
# guard anyone holding the key can reach this host's loopback services, its
# Docker/private networks and the cloud metadata service (169.254.169.254).
#
# The guard rejects such connections for processes in paqctl.service only
# (iptables cgroup match). paqet's tunnel packets are injected below iptables
# and are not affected; neither is anything else on the host.
#
# The cgroup match binds to the cgroup that exists when the rule is added,
# so the rules are rebuilt on every start (ExecStartPre -> _apply_firewall)
# and kept out of saved rulesets, where they would fail to restore at boot.
#
# Settings: EGRESS_GUARD=true|false (default true)
#           EGRESS_ALLOW="127.0.0.1:80, 10.0.0.0/8, [fd00::1]:443"
#═══════════════════════════════════════════════════════════════════════

_EGRESS_CHAIN="PAQCTL_EGRESS"
_EGRESS_DENY="PAQCTL_EGRESS_DENY"
_EGRESS_TAG="paqctl-egress"
_EGRESS_LOG_PREFIX="paqctl-egress: "
_EGRESS_CGROUP="system.slice/paqctl.service"
_EGRESS_RESOLV_CONF="/etc/resolv.conf"
# Loopback, "this host", RFC1918, CGNAT, link-local (cloud metadata),
# IETF/benchmark ranges, multicast and reserved
_EGRESS_BLOCK4="0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.168.0.0/16 198.18.0.0/15 224.0.0.0/4 240.0.0.0/4"
# Unspecified, loopback, link-local, site-local, unique-local, multicast
_EGRESS_BLOCK6="::/128 ::1/128 fe80::/10 fec0::/10 fc00::/7 ff00::/8"

# Is the guard wanted for this install? (paqet server, not switched off)
_egress_guard_wanted() {
    [ "${BACKEND:-paqet}" = "paqet" ] && [ "${ROLE:-}" = "server" ] && [ "${EGRESS_GUARD:-true}" = "true" ]
}

_egress_valid_ip6() {
    [[ "$1" == *:* ]] && [[ "$1" =~ ^[0-9A-Fa-f:.]+$ ]] && [ ${#1} -le 45 ] || return 1
    local rest="${1#*::}"
    [[ "$rest" != *::* ]]   # at most one "::"
}

# _egress_parse_allow ENTRY -> "FAMILY|CIDR|PORT" (PORT may be empty); 1 if invalid
# Accepts: 1.2.3.4  1.2.3.0/24  1.2.3.4:80  1.2.3.0/24:80  fd00::1  fd00::/8  [fd00::1]:80  [fd00::/8]:80
_egress_parse_allow() {
    local e="$1" addr port="" ip pfx="" fam
    if [[ "$e" =~ ^\[([^]]+)\]:([0-9]+)$ ]]; then
        addr="${BASH_REMATCH[1]}"; port="${BASH_REMATCH[2]}"
    elif [[ "$e" =~ ^([0-9./]+):([0-9]+)$ ]]; then
        addr="${BASH_REMATCH[1]}"; port="${BASH_REMATCH[2]}"
    else
        addr="$e"
    fi
    ip="${addr%%/*}"
    [[ "$addr" == */* ]] && pfx="${addr#*/}"
    if _validate_ip "$ip"; then
        fam=4
        [ -z "$pfx" ] || { [[ "$pfx" =~ ^[0-9]{1,2}$ ]] && [ "$pfx" -le 32 ]; } || return 1
    elif _egress_valid_ip6 "$ip"; then
        fam=6
        [ -z "$pfx" ] || { [[ "$pfx" =~ ^[0-9]{1,3}$ ]] && [ "$pfx" -le 128 ]; } || return 1
    else
        return 1
    fi
    [ -z "$port" ] || _validate_port "$port" || return 1
    printf '%s|%s|%s\n' "$fam" "$addr" "$port"
}

# EGRESS_ALLOW split on commas and whitespace
_egress_allow_list() {
    local list="${EGRESS_ALLOW:-}"
    list="${list//,/ }"
    local e
    for e in $list; do printf '%s\n' "$e"; done
}

# Every EGRESS_ALLOW entry valid? (empty is valid)
_egress_valid_allow() {
    local e
    for e in $(EGRESS_ALLOW="$1" _egress_allow_list); do
        _egress_parse_allow "$e" >/dev/null || return 1
    done
    return 0
}

# DNS resolvers paqet needs to reach (they are often on loopback, e.g. 127.0.0.53)
_egress_resolvers() {
    local fam="$1" ns any=false
    while read -r _ ns _; do
        any=true
        ns="${ns%%\%*}"
        if [ "$fam" = 4 ] && _validate_ip "$ns"; then
            echo "$ns"
        elif [ "$fam" = 6 ] && _egress_valid_ip6 "$ns"; then
            echo "$ns"
        fi
    done < <(grep -E '^[[:space:]]*nameserver[[:space:]]' "$_EGRESS_RESOLV_CONF" 2>/dev/null)
    # No nameserver line: resolvers fall back to localhost
    if [ "$any" = false ]; then
        if [ "$fam" = 4 ]; then echo "127.0.0.1"; else echo "::1"; fi
    fi
}

# Root of the cgroup v2 hierarchy (unified or hybrid mode)
_egress_cgroup_root() {
    if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
        echo /sys/fs/cgroup
    elif [ -f /sys/fs/cgroup/unified/cgroup.controllers ]; then
        echo /sys/fs/cgroup/unified
    else
        return 1
    fi
}

# _egress_build_family iptables|ip6tables  - (re)create the guard chains
_egress_build_family() {
    local ipt="$1" fam=4 rej="icmp-admin-prohibited" block="$_EGRESS_BLOCK4"
    if [ "$ipt" = "ip6tables" ]; then
        fam=6; rej="icmp6-adm-prohibited"; block="$_EGRESS_BLOCK6"
    fi
    local c
    for c in "$_EGRESS_DENY" "$_EGRESS_CHAIN"; do
        "$ipt" -w -N "$c" 2>/dev/null || "$ipt" -w -F "$c" 2>/dev/null || return 1
    done

    # Deny: log (rate-limited, for 'paqctl doctor') and fail fast
    "$ipt" -w -A "$_EGRESS_DENY" -m limit --limit 10/min --limit-burst 20 \
        -j LOG --log-prefix "$_EGRESS_LOG_PREFIX" --log-level info 2>/dev/null || true
    "$ipt" -w -A "$_EGRESS_DENY" -p tcp -j REJECT --reject-with tcp-reset || return 1
    "$ipt" -w -A "$_EGRESS_DENY" -j REJECT --reject-with "$rej" || return 1

    # Published ports (e.g. Docker): the client asked for a public or local
    # address that was DNATed to a private one - allowed, as from anywhere else
    "$ipt" -w -A "$_EGRESS_CHAIN" -m conntrack --ctstate DNAT -j RETURN || return 1

    local r proto
    while IFS= read -r r; do
        [ -n "$r" ] || continue
        for proto in udp tcp; do
            "$ipt" -w -A "$_EGRESS_CHAIN" -d "$r" -p "$proto" --dport 53 -j RETURN || return 1
        done
    done < <(_egress_resolvers "$fam")

    local e parsed f cidr port
    while IFS= read -r e; do
        parsed=$(_egress_parse_allow "$e") || continue
        IFS='|' read -r f cidr port <<< "$parsed"
        [ "$f" = "$fam" ] || continue
        if [ -n "$port" ]; then
            for proto in tcp udp; do
                "$ipt" -w -A "$_EGRESS_CHAIN" -d "$cidr" -p "$proto" --dport "$port" -j RETURN || return 1
            done
        else
            "$ipt" -w -A "$_EGRESS_CHAIN" -d "$cidr" -j RETURN || return 1
        fi
    done < <(_egress_allow_list)

    for cidr in $block; do
        "$ipt" -w -A "$_EGRESS_CHAIN" -d "$cidr" -j "$_EGRESS_DENY" || return 1
    done
}

# Delete every OUTPUT jump to the guard (by number: the cgroup a stale rule
# points to may no longer exist), then the chains
_egress_remove_family() {
    local ipt="$1" n
    command -v "$ipt" &>/dev/null || return 0
    for _ in $(seq 1 20); do
        n=$("$ipt" -w -L OUTPUT -n --line-numbers 2>/dev/null | awk -v c="$_EGRESS_CHAIN" '$2 == c {print $1; exit}')
        [ -n "$n" ] || break
        "$ipt" -w -D OUTPUT "$n" 2>/dev/null || break
    done
    local c
    for c in "$_EGRESS_CHAIN" "$_EGRESS_DENY"; do
        "$ipt" -w -F "$c" 2>/dev/null || true
        "$ipt" -w -X "$c" 2>/dev/null || true
    done
}

_egress_guard_remove() {
    _egress_remove_family iptables
    _egress_remove_family ip6tables
}

# Is the guard jump in place (IPv4)?
_egress_guard_active() {
    command -v iptables &>/dev/null || return 1
    iptables -w -L OUTPUT -n 2>/dev/null | awk -v c="$_EGRESS_CHAIN" '$1 == c {f = 1} END {exit !f}'
}

# Rebuild the guard, or remove it when it is not wanted.
# Returns 0 when done (or not wanted), 2 when paqet is not running (the guard
# is installed at the next start), 1 on failure.
_egress_guard_apply() {
    _egress_guard_remove
    _egress_guard_wanted || return 0

    if _is_firewalld_active; then
        echo -e "${YELLOW}[!]${NC} Egress guard is not available with firewalld: paqet clients can reach this host's private networks." >&2
        return 1
    fi
    if ! command -v iptables &>/dev/null; then
        echo -e "${YELLOW}[!]${NC} Egress guard needs iptables." >&2
        return 1
    fi
    if [ ! -d /run/systemd/system ]; then
        echo -e "${YELLOW}[!]${NC} Egress guard needs systemd: paqet clients can reach this host's private networks." >&2
        return 1
    fi
    local root
    if ! root=$(_egress_cgroup_root); then
        echo -e "${YELLOW}[!]${NC} Egress guard needs cgroup v2 (not available on this system)." >&2
        return 1
    fi
    # The service cgroup only exists while it runs (ExecStartPre included)
    [ -d "$root/$_EGRESS_CGROUP" ] || return 2
    modprobe xt_cgroup 2>/dev/null || true

    local ok=true
    if _egress_build_family iptables; then
        iptables -w -I OUTPUT 1 -m cgroup --path "$_EGRESS_CGROUP" -m comment --comment "$_EGRESS_TAG" \
            -j "$_EGRESS_CHAIN" 2>/dev/null || ok=false
    else
        ok=false
    fi
    if command -v ip6tables &>/dev/null && [ -d /proc/sys/net/ipv6 ]; then
        if _egress_build_family ip6tables; then
            ip6tables -w -I OUTPUT 1 -m cgroup --path "$_EGRESS_CGROUP" -m comment --comment "$_EGRESS_TAG" \
                -j "$_EGRESS_CHAIN" 2>/dev/null || ok=false
        else
            ok=false
        fi
    fi
    if [ "$ok" != true ]; then
        echo -e "${YELLOW}[!]${NC} Could not install the egress guard (iptables cgroup match unavailable?)." >&2
        return 1
    fi
    return 0
}

# Prove the guard works: from inside paqet's cgroup, connect to a TCP port
# that is reachable from outside it. Prints "blocked", "open" or "skipped".
_egress_selftest() {
    local root dir port
    root=$(_egress_cgroup_root) || { echo skipped; return 0; }
    dir="$root/$_EGRESS_CGROUP"
    [ -w "$dir/cgroup.procs" ] || { echo skipped; return 0; }
    # A loopback-reachable TCP listener, not DNS and not allow-listed
    port=$(ss -Hltn 2>/dev/null | awk '{print $4}' | grep -E '^(127\.0\.0\.1|0\.0\.0\.0|\*):[0-9]+$' \
        | sed 's/.*://' | grep -vx 53 | sort -un | head -1)
    [ -n "$port" ] || { echo skipped; return 0; }
    local e
    for e in $(_egress_allow_list); do
        case "$e" in 127.*|0.*) echo skipped; return 0 ;; esac
    done
    timeout 3 bash -c "exec 3<>/dev/tcp/127.0.0.1/$port" 2>/dev/null || { echo skipped; return 0; }
    # shellcheck disable=SC2016  # expanded by the inner shell
    if timeout 3 bash -c 'echo "$BASHPID" > "$1/cgroup.procs" && exec 3<>"/dev/tcp/127.0.0.1/$2"' _ "$dir" "$port" 2>/dev/null; then
        echo open
    else
        echo blocked
    fi
}

# Client side: a forward-mode target on the server's private side (e.g. a
# panel on its 127.0.0.1) has to be allowed on the server
_egress_forward_hint() {
    local target="$1" host
    host="${target%:*}"; host="${host#[}"; host="${host%]}"
    case "$host" in
        localhost|127.*|0.*|10.*|192.168.*|169.254.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|\
        100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*|::1|[fF][cCdD]*|[fF][eE]80*) ;;
        *) return 0 ;;
    esac
    echo -e "  ${YELLOW}Note:${NC} paqet servers block private/loopback targets by default. Allow this one on the server:"
    echo -e "    ${BOLD}sudo paqctl config set EGRESS_ALLOW=\"${target/localhost/127.0.0.1}\"${NC}"
}

# Connections the guard rejected recently (kernel log, rate-limited): "COUNT DST:PORT" lines
_egress_recent_blocks() {
    local since="${1:-24 hours ago}"
    command -v journalctl &>/dev/null || return 0
    journalctl -k --since "$since" --no-pager -o cat 2>/dev/null | grep -F "$_EGRESS_LOG_PREFIX" \
        | sed -nE 's/.* DST=([^ ]+) .*PROTO=([A-Z0-9]+)( .* DPT=([0-9]+))?.*/\1:\4 (\2)/p' \
        | sed 's/: (/ (/' | sort | uniq -c | sort -rn
}
# shellcheck shell=bash
# Backend install/config helpers (paqet binary, GFW-knocker scripts).
# Included into both the installer and the management script by build.sh.

#═══════════════════════════════════════════════════════════════════════
# paqet binary
#═══════════════════════════════════════════════════════════════════════

download_paqet() {
    local version="$1"
    local arch
    arch=$(detect_arch) || return 1
    local os_name="linux"
    local ext="tar.gz"
    local filename="paqet-${os_name}-${arch}-${version}.${ext}"
    local url="https://github.com/${PAQET_REPO}/releases/download/${version}/${filename}"

    log_info "Downloading paqet ${version} for ${os_name}/${arch}..."

    if ! mkdir -p "$INSTALL_DIR/bin"; then
        log_error "Failed to create directory $INSTALL_DIR/bin"
        return 1
    fi
    local tmp_file
    tmp_file=$(mktemp "/tmp/paqet-download-XXXXXXXX.${ext}") || { log_error "Failed to create temp file"; return 1; }

    # Try curl first, fallback to wget
    local download_ok=false
    if curl -sL --max-time 180 --retry 3 --retry-delay 5 --fail -o "$tmp_file" "$url" 2>/dev/null; then
        download_ok=true
    elif command -v wget &>/dev/null; then
        log_info "curl failed, trying wget..."
        rm -f "$tmp_file"
        if wget -q --timeout=180 --tries=3 -O "$tmp_file" "$url" 2>/dev/null; then
            download_ok=true
        fi
    fi

    if [ "$download_ok" != "true" ]; then
        log_error "Failed to download: $url"
        log_error "Try manual download: wget '$url' and place binary in $INSTALL_DIR/bin/"
        rm -f "$tmp_file"
        return 1
    fi

    # Validate download
    local fsize
    fsize=$(stat -c%s "$tmp_file" 2>/dev/null || stat -f%z "$tmp_file" 2>/dev/null || wc -c < "$tmp_file" 2>/dev/null || echo 0)
    if [ "$fsize" -lt 1000 ]; then
        log_error "Downloaded file is too small ($fsize bytes). Download may have failed."
        rm -f "$tmp_file"
        return 1
    fi

    # Extract
    log_info "Extracting..."
    local tmp_extract
    tmp_extract=$(mktemp -d "/tmp/paqet-extract-XXXXXXXX") || { log_error "Failed to create temp file"; return 1; }
    if ! tar -xzf "$tmp_file" -C "$tmp_extract" 2>/dev/null; then
        log_error "Failed to extract archive"
        rm -f "$tmp_file"
        rm -rf "$tmp_extract"
        return 1
    fi

    # Find the binary in extracted files
    local binary_name="paqet_${os_name}_${arch}"
    local found_binary=""
    found_binary=$(find "$tmp_extract" -name "$binary_name" -type f 2>/dev/null | head -1)
    if [ -z "$found_binary" ]; then
        # Try alternate name patterns
        found_binary=$(find "$tmp_extract" -name "paqet*" -type f -executable 2>/dev/null | head -1)
    fi
    if [ -z "$found_binary" ]; then
        found_binary=$(find "$tmp_extract" -name "paqet*" -type f 2>/dev/null | head -1)
    fi

    if [ -z "$found_binary" ]; then
        log_error "Could not find paqet binary in archive"
        rm -f "$tmp_file"
        rm -rf "$tmp_extract"
        return 1
    fi

    # Stop paqet if running to avoid "Text file busy" error
    if pgrep -f "$INSTALL_DIR/bin/paqet" &>/dev/null; then
        log_info "Stopping paqet to update binary..."
        pkill -f "$INSTALL_DIR/bin/paqet" 2>/dev/null || true
        sleep 1
    fi

    if ! cp "$found_binary" "$INSTALL_DIR/bin/paqet"; then
        log_error "Failed to copy paqet binary to $INSTALL_DIR/bin/"
        rm -f "$tmp_file"
        rm -rf "$tmp_extract"
        return 1
    fi
    if ! chmod +x "$INSTALL_DIR/bin/paqet"; then
        log_error "Failed to make paqet binary executable"
        return 1
    fi

    # Copy example configs if they exist
    find "$tmp_extract" -name "*.yaml.example" -exec cp {} "$INSTALL_DIR/" \; 2>/dev/null || true

    rm -f "$tmp_file"
    rm -rf "$tmp_extract"

    # Verify binary runs
    if "$INSTALL_DIR/bin/paqet" version &>/dev/null; then
        log_success "paqet ${version} installed successfully"
    else
        log_warn "paqet binary installed but version check failed (may need libpcap)"
    fi
}

#═══════════════════════════════════════════════════════════════════════
# GFW-knocker
#═══════════════════════════════════════════════════════════════════════

install_python_deps() {
    log_info "Installing Python dependencies for GFW-knocker..."
    _ensure_pkg_manager
    if ! command -v python3 &>/dev/null; then
        install_package python3
    fi
    # Ensure python3 version >= 3.10
    local pyver
    pyver=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "0.0")
    local pymajor pyminor
    pymajor=$(echo "$pyver" | cut -d. -f1)
    pyminor=$(echo "$pyver" | cut -d. -f2)
    if [ "$pymajor" -lt 3 ] || { [ "$pymajor" -eq 3 ] && [ "$pyminor" -lt 10 ]; }; then
        log_error "Python 3.10+ required, found $pyver"
        return 1
    fi

    # Install venv support (varies by distro)
    # - Debian/Ubuntu: needs python3-venv or python3.X-venv package
    # - Fedora/RHEL/Arch/openSUSE: venv included with python3, just need pip
    # - Alpine: needs py3-pip
    case "$PKG_MANAGER" in
        apt)
            # Debian/Ubuntu needs python3-venv package (version-specific)
            local pyver_full
            pyver_full=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null)
            if [ -n "$pyver_full" ]; then
                install_package "python${pyver_full}-venv" || install_package "python3-venv"
            else
                install_package "python3-venv"
            fi
            ;;
        dnf)
            # Fedora/RHEL 8+: venv is included with python3, just ensure pip
            install_package "python3-pip" || true
            ;;
        yum)
            # Older RHEL/CentOS 7
            install_package "python3-pip" || true
            ;;
        pacman)
            # Arch Linux: venv included with python, pip is separate
            install_package "python-pip" || true
            ;;
        zypper)
            # openSUSE: venv included with python3
            install_package "python3-pip" || true
            ;;
        apk)
            # Alpine
            install_package "py3-pip" || true
            ;;
        *)
            # Try generic python3-venv, ignore if fails (venv may be built-in)
            install_package "python3-venv" 2>/dev/null || true
            ;;
    esac

    # Create virtual environment
    local VENV_DIR="$INSTALL_DIR/venv"
    # Check if venv exists AND is complete (has pip)
    if [ ! -x "$VENV_DIR/bin/pip" ]; then
        # Remove broken/incomplete venv if exists
        [ -d "$VENV_DIR" ] && rm -rf "$VENV_DIR"
        log_info "Creating Python virtual environment..."
        python3 -m venv "$VENV_DIR" || {
            log_error "Failed to create virtual environment (is python3-venv installed?)"
            return 1
        }
    fi

    # Verify pip exists after venv creation
    if [ ! -x "$VENV_DIR/bin/pip" ]; then
        log_error "venv created but pip missing (install python3-venv package)"
        return 1
    fi

    # Install packages in venv
    log_info "Installing scapy and aioquic in venv..."
    "$VENV_DIR/bin/pip" install --quiet --upgrade pip 2>/dev/null || true
    "$VENV_DIR/bin/pip" install --quiet scapy aioquic 2>/dev/null || {
        # Try with --break-system-packages as fallback (shouldn't be needed in venv)
        "$VENV_DIR/bin/pip" install scapy aioquic || {
            log_error "Failed to install Python packages (scapy, aioquic)"
            return 1
        }
    }

    # Verify
    if "$VENV_DIR/bin/python" -c "import scapy; import aioquic" 2>/dev/null; then
        log_success "Python dependencies installed (scapy, aioquic)"
    else
        log_error "Python package verification failed"
        return 1
    fi
}

install_microsocks() {
    log_info "Installing microsocks for SOCKS5 proxy..."
    if [ -x "$INSTALL_DIR/bin/microsocks" ]; then
        log_success "microsocks already installed"
        return 0
    fi
    # Build dependencies
    command -v gcc &>/dev/null || install_package gcc
    command -v make &>/dev/null || install_package make
    _ensure_pkg_manager
    # Alpine needs the libc headers to compile
    [ "$PKG_MANAGER" = "apk" ] && { [ -f /usr/include/stdio.h ] || install_package musl-dev || true; }
    local tmp_dir
    tmp_dir=$(mktemp -d)
    if ! curl -sL "https://github.com/${MICROSOCKS_REPO}/archive/refs/heads/master.tar.gz" -o "$tmp_dir/microsocks.tar.gz"; then
        log_error "Failed to download microsocks"
        rm -rf "$tmp_dir"
        return 1
    fi
    tar -xzf "$tmp_dir/microsocks.tar.gz" -C "$tmp_dir" 2>/dev/null || {
        log_error "Failed to extract microsocks"
        rm -rf "$tmp_dir"
        return 1
    }
    local src_dir
    src_dir=$(find "$tmp_dir" -maxdepth 1 -type d -name "microsocks*" | head -1)
    if [ -z "$src_dir" ]; then
        log_error "microsocks source directory not found"
        rm -rf "$tmp_dir"
        return 1
    fi
    if ! make -C "$src_dir" -j"$(nproc 2>/dev/null || echo 1)" 2>/dev/null; then
        log_error "Failed to compile microsocks"
        rm -rf "$tmp_dir"
        return 1
    fi
    mkdir -p "$INSTALL_DIR/bin"
    cp "$src_dir/microsocks" "$INSTALL_DIR/bin/microsocks"
    chmod 755 "$INSTALL_DIR/bin/microsocks"
    rm -rf "$tmp_dir"
    log_success "microsocks installed"
}

download_gfk() {
    log_info "Downloading GFW-knocker scripts..."
    if ! mkdir -p "$GFK_DIR"; then
        log_error "Failed to create $GFK_DIR"
        return 1
    fi
    # Note: parameters.py is generated by generate_gfk_config(), don't download it
    # Download server scripts from gfk/server/
    local server_files="mainserver.py quic_server.py vio_server.py"
    local f
    for f in $server_files; do
        if ! curl -sL "$GFK_RAW_URL/server/$f" -o "$GFK_DIR/$f"; then
            log_error "Failed to download $f"
            return 1
        fi
    done
    # Download client scripts from gfk/client/
    local client_files="mainclient.py quic_client.py vio_client.py"
    for f in $client_files; do
        if ! curl -sL "$GFK_RAW_URL/client/$f" -o "$GFK_DIR/$f"; then
            log_error "Failed to download $f"
            return 1
        fi
    done
    chmod 600 "$GFK_DIR"/*.py
    # Patch mainserver.py to use venv python for subprocesses
    if [ -f "$GFK_DIR/mainserver.py" ]; then
        sed -i "s|'python3'|'$INSTALL_DIR/venv/bin/python'|g" "$GFK_DIR/mainserver.py"
    fi
    log_success "GFW-knocker scripts downloaded to $GFK_DIR"
}

generate_gfk_certs() {
    if [ -f "$GFK_DIR/cert.pem" ] && [ -f "$GFK_DIR/key.pem" ]; then
        log_info "GFW-knocker certificates already exist"
        return 0
    fi
    if ! command -v openssl &>/dev/null; then
        log_info "Installing openssl..."
        install_package openssl || { log_error "Failed to install openssl"; return 1; }
    fi
    log_info "Generating QUIC TLS certificates..."
    if ! openssl req -x509 -newkey rsa:2048 -keyout "$GFK_DIR/key.pem" \
        -out "$GFK_DIR/cert.pem" -days 3650 -nodes -subj "/CN=gfk" 2>/dev/null; then
        log_error "Failed to generate certificates"
        return 1
    fi
    chmod 600 "$GFK_DIR/key.pem" "$GFK_DIR/cert.pem"
    log_success "QUIC certificates generated"
}

generate_gfk_config() {
    log_info "Generating GFW-knocker configuration..."
    # Ensure GFK directory exists
    mkdir -p "$GFK_DIR" || { log_error "Failed to create $GFK_DIR"; return 1; }
    local _tmp
    _tmp=$(mktemp "$GFK_DIR/parameters.py.XXXXXXXX") || { log_error "Failed to create temp file"; return 1; }

    # Determine port values based on role - validate they are numeric
    local vio_tcp_server_port="${GFK_VIO_PORT:-45000}"
    local vio_tcp_client_port="${GFK_VIO_CLIENT_PORT:-40000}"
    local vio_udp_server_port="${GFK_VIO_UDP_SERVER:-35000}"
    local vio_udp_client_port="${GFK_VIO_UDP_CLIENT:-30000}"
    local quic_server_port="${GFK_QUIC_PORT:-25000}"
    local quic_client_port="${GFK_QUIC_CLIENT_PORT:-20000}"

    # Validate all ports are numeric
    for _p in "$vio_tcp_server_port" "$vio_tcp_client_port" "$vio_udp_server_port" \
              "$vio_udp_client_port" "$quic_server_port" "$quic_client_port"; do
        if ! [[ "$_p" =~ ^[0-9]+$ ]]; then
            log_error "Invalid port number: $_p"
            rm -f "$_tmp"
            return 1
        fi
    done

    # Escape Python string - prevents code injection
    _escape_py_string() {
        local s="$1"
        s="${s//\\/\\\\}"   # Escape backslashes first
        s="${s//\"/\\\"}"   # Escape double quotes
        s="${s//\'/\\\'}"   # Escape single quotes
        s="${s//$'\n'/\\n}" # Escape newlines
        s="${s//$'\r'/\\r}" # Escape carriage returns
        printf '%s' "$s"
    }

    # Validate and escape server IP
    local safe_server_ip
    safe_server_ip=$(_escape_py_string "${GFK_SERVER_IP:-}")
    if ! _validate_ip "${GFK_SERVER_IP:-}"; then
        log_error "Invalid server IP: ${GFK_SERVER_IP:-}"
        rm -f "$_tmp"
        return 1
    fi

    # Validate and escape auth code
    local safe_auth_code
    safe_auth_code=$(_escape_py_string "${GFK_AUTH_CODE:-}")

    # Build port mapping dict string with validation
    local tcp_mapping="${GFK_PORT_MAPPINGS:-14000:443}"
    local mapping_str="{"
    local first=true
    local pair
    for pair in $(echo "$tcp_mapping" | tr ',' ' '); do
        local lport rport
        lport=$(echo "$pair" | cut -d: -f1)
        rport=$(echo "$pair" | cut -d: -f2)
        # Validate both ports are numeric
        if ! [[ "$lport" =~ ^[0-9]+$ ]] || ! [[ "$rport" =~ ^[0-9]+$ ]]; then
            log_error "Invalid port mapping: $pair (must be numeric:numeric)"
            rm -f "$_tmp"
            return 1
        fi
        if [ "$first" = true ]; then
            mapping_str="${mapping_str}${lport}: ${rport}"
            first=false
        else
            mapping_str="${mapping_str}, ${lport}: ${rport}"
        fi
    done
    mapping_str="${mapping_str}}"

    # Escape GFK_DIR for Python string
    local safe_gfk_dir
    safe_gfk_dir=$(_escape_py_string "${GFK_DIR}")

    (
    umask 077
    cat > "$_tmp" << PYEOF
# GFW-knocker parameters - auto-generated by paqctl
# Do not edit manually

vps_ip = "${safe_server_ip}"
xray_server_ip_address = "127.0.0.1"

tcp_port_mapping = ${mapping_str}
udp_port_mapping = {}

vio_tcp_server_port = ${vio_tcp_server_port}
vio_tcp_client_port = ${vio_tcp_client_port}
vio_udp_server_port = ${vio_udp_server_port}
vio_udp_client_port = ${vio_udp_client_port}

quic_server_port = ${quic_server_port}
quic_client_port = ${quic_client_port}
quic_local_ip = "127.0.0.1"

quic_idle_timeout = 86400
udp_timeout = 300
quic_mtu = ${KCP_MTU:-1350}
quic_verify_cert = False
quic_max_data = 1073741824
quic_max_stream_data = 1073741824

quic_auth_code = "${safe_auth_code}"

quic_cert_filepath = ("${safe_gfk_dir}/cert.pem", "${safe_gfk_dir}/key.pem")

tcp_flags = "${GFK_TCP_FLAGS:-AP}"
PYEOF
    )
    if ! mv "$_tmp" "$GFK_DIR/parameters.py"; then
        log_error "Failed to save GFW-knocker configuration"
        rm -f "$_tmp"
        return 1
    fi
    chmod 600 "$GFK_DIR/parameters.py"
    log_success "GFW-knocker configuration saved"
}

create_gfk_client_wrapper() {
    log_info "Creating GFW-knocker client wrapper..."
    local wrapper="$INSTALL_DIR/bin/gfk-client.sh"
    mkdir -p "$INSTALL_DIR/bin"
    cat > "$wrapper" << 'WRAPEOF'
#!/bin/bash
set -e
GFK_DIR="REPLACE_ME_GFK_DIR"
INSTALL_DIR="REPLACE_ME_INSTALL_DIR"

cd "$GFK_DIR"
"$INSTALL_DIR/venv/bin/python" mainclient.py &
PID1=$!
trap "kill $PID1 2>/dev/null; wait" EXIT INT TERM
wait
WRAPEOF
    sed "s#REPLACE_ME_GFK_DIR#${GFK_DIR}#g; s#REPLACE_ME_INSTALL_DIR#${INSTALL_DIR}#g" "$wrapper" > "$wrapper.sed" && mv "$wrapper.sed" "$wrapper"
    chmod 755 "$wrapper"
    log_success "Client wrapper created at $wrapper"
}
# shellcheck shell=bash
# Xray (SOCKS5 for the GFK server).
# Included into both the installer and the management script by build.sh.

#═══════════════════════════════════════════════════════════════════════
# Xray
#═══════════════════════════════════════════════════════════════════════

XRAY_CONFIG_DIR="/usr/local/etc/xray"
XRAY_CONFIG_FILE="$XRAY_CONFIG_DIR/config.json"

check_xray_installed() {
    command -v xray &>/dev/null && return 0
    [ -x /usr/local/bin/xray ] && return 0
    [ -x /usr/local/x-ui/bin/xray-linux-amd64 ] && return 0
    return 1
}

install_xray() {
    if check_xray_installed; then
        log_info "Xray is already installed"
        return 0
    fi

    log_info "Installing Xray ${XRAY_VERSION_PINNED}..."

    # Use official Xray install script with pinned version for stability
    local tmp_script
    tmp_script=$(mktemp)
    if ! curl -sL https://github.com/XTLS/Xray-install/raw/main/install-release.sh -o "$tmp_script"; then
        log_error "Failed to download Xray installer"
        rm -f "$tmp_script"
        return 1
    fi

    # Install specific version (not latest) for stability
    if ! bash "$tmp_script" install --version "$XRAY_VERSION_PINNED" 2>/dev/null; then
        log_error "Failed to install Xray"
        rm -f "$tmp_script"
        return 1
    fi
    rm -f "$tmp_script"

    log_success "Xray ${XRAY_VERSION_PINNED} installed"
}

configure_xray_socks() {
    local listen_port="${1:-443}"

    log_info "Configuring Xray SOCKS5 proxy on port $listen_port..."

    mkdir -p "$XRAY_CONFIG_DIR"

    # Create simple SOCKS5 inbound config
    cat > "$XRAY_CONFIG_FILE" << EOF
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "tag": "socks-in",
      "port": ${listen_port},
      "listen": "127.0.0.1",
      "protocol": "socks",
      "settings": {
        "auth": "noauth",
        "udp": true
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    }
  ],
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom",
      "settings": {}
    }
  ]
}
EOF
    chmod 644 "$XRAY_CONFIG_FILE"  # Xray service runs as 'nobody', needs read access
    log_success "Xray configured (SOCKS5 on 127.0.0.1:$listen_port)"
}

# Check if running xray is paqctl's own standalone install (not a real panel)
# Returns 0 if standalone (all inbounds are socks on 127.0.0.1), 1 if panel
_is_paqctl_standalone_xray() {
    [ -f "$XRAY_CONFIG_FILE" ] || return 1
    command -v python3 &>/dev/null || return 1
    python3 -c "
import json, sys
try:
    with open(sys.argv[1]) as f:
        cfg = json.load(f)
    inbounds = cfg.get('inbounds', [])
    if not inbounds:
        sys.exit(1)
    for i in inbounds:
        if i.get('protocol') != 'socks' or i.get('listen', '0.0.0.0') != '127.0.0.1':
            sys.exit(1)
    sys.exit(0)
except:
    sys.exit(1)
" "$XRAY_CONFIG_FILE" 2>/dev/null
}

# Add a SOCKS5 inbound to an existing xray config (panel) without touching other inbounds
_add_xray_gfk_socks() {
    local port="$1"
    python3 -c "
import json, sys
port = int(sys.argv[1])
config_path = sys.argv[2]
try:
    with open(config_path, 'r') as f:
        cfg = json.load(f)
except:
    cfg = {'inbounds': [], 'outbounds': [{'tag': 'direct', 'protocol': 'freedom', 'settings': {}}]}
cfg.setdefault('inbounds', [])
cfg['inbounds'] = [i for i in cfg['inbounds'] if i.get('tag') != 'gfk-socks']
cfg['inbounds'].append({
    'tag': 'gfk-socks',
    'port': port,
    'listen': '127.0.0.1',
    'protocol': 'socks',
    'settings': {'auth': 'noauth', 'udp': True},
    'sniffing': {'enabled': True, 'destOverride': ['http', 'tls']}
})
if not any(o.get('protocol') == 'freedom' for o in cfg.get('outbounds', [])):
    cfg.setdefault('outbounds', []).append({'tag': 'direct', 'protocol': 'freedom', 'settings': {}})
with open(config_path, 'w') as f:
    json.dump(cfg, f, indent=2)
" "$port" "$XRAY_CONFIG_FILE" 2>/dev/null
    if [ $? -ne 0 ]; then
        log_error "Failed to add SOCKS5 inbound to existing Xray config"
        return 1
    fi
    log_success "Added GFK SOCKS5 inbound on 127.0.0.1:$port"
}

start_xray() {
    log_info "Starting Xray service..."

    if command -v systemctl &>/dev/null && [ -d /run/systemd/system ]; then
        # Stop first, reload daemon, then start - with retry
        systemctl stop xray 2>/dev/null || true
        sleep 1
        systemctl daemon-reload 2>/dev/null || true
        systemctl enable xray 2>/dev/null || true

        # Try up to 3 times
        local attempt
        for attempt in 1 2 3; do
            systemctl start xray 2>/dev/null
            sleep 2
            if systemctl is-active --quiet xray; then
                log_success "Xray started"
                return 0
            fi
            [ "$attempt" -lt 3 ] && sleep 1
        done
        log_error "Failed to start Xray after 3 attempts"
        return 1
    else
        # Direct start for non-systemd
        local _xray_bin=""
        [ -x /usr/local/bin/xray ] && _xray_bin="/usr/local/bin/xray"
        [ -z "$_xray_bin" ] && [ -x /usr/local/x-ui/bin/xray-linux-amd64 ] && _xray_bin="/usr/local/x-ui/bin/xray-linux-amd64"
        if [ -n "$_xray_bin" ]; then
            pkill -x xray 2>/dev/null || true
            sleep 1
            nohup "$_xray_bin" run -c "$XRAY_CONFIG_FILE" > /var/log/xray.log 2>&1 &
            sleep 2
            if pgrep -f "xray" &>/dev/null; then
                log_success "Xray started"
                return 0
            fi
        fi
        log_error "Failed to start Xray"
        return 1
    fi
}

stop_xray() {
    if command -v systemctl &>/dev/null && [ -d /run/systemd/system ]; then
        systemctl stop xray 2>/dev/null || true
    else
        pkill -x xray 2>/dev/null || true
    fi
}

setup_xray_for_gfk() {
    local target_port
    target_port=$(echo "${GFK_PORT_MAPPINGS:-14000:443}" | cut -d: -f2 | cut -d, -f1)

    if pgrep -x xray &>/dev/null || pgrep -f "xray-linux" &>/dev/null; then
        # Check if this is paqctl's own standalone Xray (not a real panel)
        if _is_paqctl_standalone_xray; then
            log_info "Existing Xray is paqctl's standalone install — reconfiguring..."
            stop_xray
            sleep 1
            # Fall through to standalone install path below
        else
            XRAY_PANEL_DETECTED=true
            log_info "Existing Xray detected — adding SOCKS5 alongside panel..."

            # Clean up any leftover standalone GFK xray from prior installs
            pkill -f "xray run -c.*gfk-socks.json" 2>/dev/null || true
            rm -f "${XRAY_CONFIG_DIR}/gfk-socks.json" 2>/dev/null

            # Check all existing target ports from mappings
            local mapping pairs
            IFS=',' read -ra pairs <<< "${GFK_PORT_MAPPINGS:-14000:443}"
            for mapping in "${pairs[@]}"; do
                local vio_port="${mapping%%:*}"
                local tp="${mapping##*:}"
                if ss -tln 2>/dev/null | grep -q ":${tp} "; then
                    log_success "Port $tp is listening — GFK will forward VIO port $vio_port to this port"
                else
                    log_warn "Port $tp is NOT listening — make sure your panel inbound is on port $tp"
                fi
            done

            # Find free port for SOCKS5 (starting at 10443)
            local socks_port=10443
            while ss -tln 2>/dev/null | grep -q ":${socks_port} "; do
                socks_port=$((socks_port + 1))
                if [ "$socks_port" -gt 65000 ]; then
                    log_warn "Could not find free port for SOCKS5 — panel-only mode"
                    echo ""
                    local first_vio
                    first_vio=$(echo "${GFK_PORT_MAPPINGS:-14000:443}" | cut -d: -f1 | cut -d, -f1)
                    log_warn "For panel-to-panel: configure Iran panel outbound to 127.0.0.1:${first_vio}"
                    return 0
                fi
            done

            # Add SOCKS5 inbound to existing xray config
            _add_xray_gfk_socks "$socks_port" || {
                log_warn "Could not add SOCKS5 to panel config — panel-only mode"
                return 0
            }

            # Restart xray to load new config
            systemctl restart xray 2>/dev/null || pkill -SIGHUP xray 2>/dev/null || true
            sleep 2

            # Find next VIO port (highest existing + 1) and append SOCKS5 mapping
            local max_vio=0
            for mapping in "${pairs[@]}"; do
                local v="${mapping%%:*}"
                [ "$v" -gt "$max_vio" ] && max_vio="$v"
            done
            local socks_vio=$((max_vio + 1))
            GFK_PORT_MAPPINGS="${GFK_PORT_MAPPINGS},${socks_vio}:${socks_port}"
            GFK_SOCKS_PORT="$socks_port"
            GFK_SOCKS_VIO_PORT="$socks_vio"

            log_success "SOCKS5 proxy added on port $socks_port (VIO port $socks_vio)"
            echo ""
            log_info "Port mappings updated: ${GFK_PORT_MAPPINGS}"
            log_warn "Use these SAME mappings on the client side"
            echo ""
            local first_vio
            first_vio=$(echo "${GFK_PORT_MAPPINGS:-14000:443}" | cut -d: -f1 | cut -d, -f1)
            log_warn "For panel-to-panel: configure Iran panel outbound to 127.0.0.1:${first_vio}"
            log_warn "For direct SOCKS5: use 127.0.0.1:${socks_vio} as your proxy on client"
            return 0
        fi
    fi

    install_xray || return 1
    configure_xray_socks "$target_port" || return 1
    start_xray || return 1
}

# Safe string length check - prevents DoS via extremely long inputs
_check_length() { [ ${#1} -le "${2:-256}" ]; }

# Load settings
_load_settings
ROLE=${ROLE:-server}
PAQET_VERSION=${PAQET_VERSION:-unknown}
LISTEN_PORT=${LISTEN_PORT:-8443}
SOCKS_PORT=${SOCKS_PORT:-1080}
INTERFACE=${INTERFACE:-eth0}
LOCAL_IP=${LOCAL_IP:-}
GATEWAY_MAC=${GATEWAY_MAC:-}
ENCRYPTION_KEY=${ENCRYPTION_KEY:-}
REMOTE_SERVER=${REMOTE_SERVER:-}
TELEGRAM_BOT_TOKEN=${TELEGRAM_BOT_TOKEN:-}
TELEGRAM_CHAT_ID=${TELEGRAM_CHAT_ID:-}
TELEGRAM_INTERVAL=${TELEGRAM_INTERVAL:-6}
TELEGRAM_ENABLED=${TELEGRAM_ENABLED:-false}
TELEGRAM_ALERTS_ENABLED=${TELEGRAM_ALERTS_ENABLED:-true}
TELEGRAM_DAILY_SUMMARY=${TELEGRAM_DAILY_SUMMARY:-true}
TELEGRAM_WEEKLY_SUMMARY=${TELEGRAM_WEEKLY_SUMMARY:-true}
TELEGRAM_SERVER_LABEL=${TELEGRAM_SERVER_LABEL:-}
TELEGRAM_START_HOUR=${TELEGRAM_START_HOUR:-0}
BACKEND=${BACKEND:-paqet}
GFK_VIO_PORT=${GFK_VIO_PORT:-}
GFK_QUIC_PORT=${GFK_QUIC_PORT:-}
GFK_AUTH_CODE=${GFK_AUTH_CODE:-}
GFK_PORT_MAPPINGS=${GFK_PORT_MAPPINGS:-}
GFK_SOCKS_PORT=${GFK_SOCKS_PORT:-}
GFK_SOCKS_VIO_PORT=${GFK_SOCKS_VIO_PORT:-}
XRAY_PANEL_DETECTED=${XRAY_PANEL_DETECTED:-false}
MICROSOCKS_PORT=${MICROSOCKS_PORT:-}
GFK_SERVER_IP=${GFK_SERVER_IP:-}
GFK_TCP_FLAGS=${GFK_TCP_FLAGS:-AP}

# Root is checked per command in _main (help/version/completion work without it)
_require_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}Error: This command must be run as root (use sudo paqctl)${NC}" >&2
        return 1
    fi
}
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
#═══════════════════════════════════════════════════════════════════════
# Firewall (internal commands)
#═══════════════════════════════════════════════════════════════════════


_apply_firewall() {
    if ! _is_firewalld_active && ! command -v iptables &>/dev/null; then
        echo -e "${YELLOW}[!]${NC} No firewall backend found (iptables or firewalld)." >&2
        return 1
    fi

    # IP bans are independent of backend/role; re-apply them on every start
    _reapply_bans

    # Egress guard (paqet server): rebuilt on every start because it binds to
    # the service's current cgroup; removed when not wanted (other role/backend).
    # Never fails the start: 'paqctl health' reports a missing guard.
    local _eg_rc=0
    _egress_guard_apply || _eg_rc=$?
    if [ "$_eg_rc" -eq 2 ] && [ -t 1 ]; then
        echo -e "${DIM}  Egress guard will be installed when paqet starts.${NC}"
    fi

    if [ "$BACKEND" = "gfw-knocker" ]; then
        local vio_port
        if [ "$ROLE" = "server" ]; then
            vio_port="${GFK_VIO_PORT:-45000}"
        else
            vio_port="${GFK_VIO_CLIENT_PORT:-40000}"
        fi

        if _is_firewalld_active; then
            firewall-cmd --direct --query-rule ipv4 raw PREROUTING 0 -p tcp --dport "$vio_port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || \
                firewall-cmd --direct --add-rule ipv4 raw PREROUTING 0 -p tcp --dport "$vio_port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || true
            firewall-cmd --direct --query-rule ipv4 raw OUTPUT 0 -p tcp --sport "$vio_port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || \
                firewall-cmd --direct --add-rule ipv4 raw OUTPUT 0 -p tcp --sport "$vio_port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || true
            firewall-cmd --direct --query-rule ipv4 filter INPUT 0 -p tcp --dport "$vio_port" -m comment --comment "paqctl" -j DROP 2>/dev/null || \
                firewall-cmd --direct --add-rule ipv4 filter INPUT 0 -p tcp --dport "$vio_port" -m comment --comment "paqctl" -j DROP 2>/dev/null || \
                echo -e "${YELLOW}[!]${NC} Failed to add VIO port DROP rule via firewalld" >&2
            firewall-cmd --direct --query-rule ipv4 filter OUTPUT 0 -p tcp --sport "$vio_port" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP 2>/dev/null || \
                firewall-cmd --direct --add-rule ipv4 filter OUTPUT 0 -p tcp --sport "$vio_port" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP 2>/dev/null || \
                echo -e "${YELLOW}[!]${NC} Failed to add RST DROP rule via firewalld" >&2
            firewall-cmd --direct --query-rule ipv6 filter INPUT 0 -p tcp --dport "$vio_port" -m comment --comment "paqctl" -j DROP 2>/dev/null || \
                firewall-cmd --direct --add-rule ipv6 filter INPUT 0 -p tcp --dport "$vio_port" -m comment --comment "paqctl" -j DROP 2>/dev/null || true
            firewall-cmd --direct --query-rule ipv6 filter OUTPUT 0 -p tcp --sport "$vio_port" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP 2>/dev/null || \
                firewall-cmd --direct --add-rule ipv6 filter OUTPUT 0 -p tcp --sport "$vio_port" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP 2>/dev/null || true
        else
            local TAG="paqctl"
            modprobe iptable_raw 2>/dev/null || true
            iptables -t raw -C PREROUTING -p tcp --dport "$vio_port" -m comment --comment "$TAG" -j NOTRACK 2>/dev/null || \
                iptables -t raw -I PREROUTING 1 -p tcp --dport "$vio_port" -m comment --comment "$TAG" -j NOTRACK 2>/dev/null || true
            iptables -t raw -C OUTPUT -p tcp --sport "$vio_port" -m comment --comment "$TAG" -j NOTRACK 2>/dev/null || \
                iptables -t raw -I OUTPUT 1 -p tcp --sport "$vio_port" -m comment --comment "$TAG" -j NOTRACK 2>/dev/null || true
            iptables -C INPUT -p tcp --dport "$vio_port" -m comment --comment "$TAG" -j DROP 2>/dev/null || \
                iptables -I INPUT 1 -p tcp --dport "$vio_port" -m comment --comment "$TAG" -j DROP 2>/dev/null || \
                echo -e "${YELLOW}[!]${NC} Failed to add VIO port DROP rule" >&2
            iptables -C OUTPUT -p tcp --sport "$vio_port" --tcp-flags RST RST -m comment --comment "$TAG" -j DROP 2>/dev/null || \
                iptables -I OUTPUT 1 -p tcp --sport "$vio_port" --tcp-flags RST RST -m comment --comment "$TAG" -j DROP 2>/dev/null || \
                echo -e "${YELLOW}[!]${NC} Failed to add RST DROP rule" >&2
            if command -v ip6tables &>/dev/null; then
                ip6tables -C INPUT -p tcp --dport "$vio_port" -m comment --comment "$TAG" -j DROP 2>/dev/null || \
                    ip6tables -I INPUT 1 -p tcp --dport "$vio_port" -m comment --comment "$TAG" -j DROP 2>/dev/null || true
                ip6tables -C OUTPUT -p tcp --sport "$vio_port" --tcp-flags RST RST -m comment --comment "$TAG" -j DROP 2>/dev/null || \
                    ip6tables -I OUTPUT 1 -p tcp --sport "$vio_port" --tcp-flags RST RST -m comment --comment "$TAG" -j DROP 2>/dev/null || true
            fi
        fi
        return 0
    fi

    [ "$ROLE" != "server" ] && return 0
    local port="${LISTEN_PORT:-8443}"

    if _is_firewalld_active; then
        firewall-cmd --direct --query-rule ipv4 raw PREROUTING 0 -p tcp --dport "$port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || \
            firewall-cmd --direct --add-rule ipv4 raw PREROUTING 0 -p tcp --dport "$port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || \
            echo -e "${YELLOW}[!]${NC} Failed to add PREROUTING NOTRACK rule via firewalld" >&2
        firewall-cmd --direct --query-rule ipv4 raw OUTPUT 0 -p tcp --sport "$port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || \
            firewall-cmd --direct --add-rule ipv4 raw OUTPUT 0 -p tcp --sport "$port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || \
            echo -e "${YELLOW}[!]${NC} Failed to add OUTPUT NOTRACK rule via firewalld" >&2
        firewall-cmd --direct --query-rule ipv4 mangle OUTPUT 0 -p tcp --sport "$port" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP 2>/dev/null || \
            firewall-cmd --direct --add-rule ipv4 mangle OUTPUT 0 -p tcp --sport "$port" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP 2>/dev/null || \
            echo -e "${YELLOW}[!]${NC} Failed to add RST DROP rule via firewalld" >&2
        firewall-cmd --direct --query-rule ipv6 raw PREROUTING 0 -p tcp --dport "$port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || \
            firewall-cmd --direct --add-rule ipv6 raw PREROUTING 0 -p tcp --dport "$port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || true
        firewall-cmd --direct --query-rule ipv6 raw OUTPUT 0 -p tcp --sport "$port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || \
            firewall-cmd --direct --add-rule ipv6 raw OUTPUT 0 -p tcp --sport "$port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || true
        firewall-cmd --direct --query-rule ipv6 mangle OUTPUT 0 -p tcp --sport "$port" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP 2>/dev/null || \
            firewall-cmd --direct --add-rule ipv6 mangle OUTPUT 0 -p tcp --sport "$port" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP 2>/dev/null || true
    else
        local TAG="paqctl"
        modprobe iptable_raw 2>/dev/null || true
        modprobe iptable_mangle 2>/dev/null || true
        iptables -t raw -C PREROUTING -p tcp --dport "$port" -m comment --comment "$TAG" -j NOTRACK 2>/dev/null || \
            iptables -t raw -I PREROUTING 1 -p tcp --dport "$port" -m comment --comment "$TAG" -j NOTRACK 2>/dev/null || \
            echo -e "${YELLOW}[!]${NC} Failed to add PREROUTING NOTRACK rule" >&2
        iptables -t raw -C OUTPUT -p tcp --sport "$port" -m comment --comment "$TAG" -j NOTRACK 2>/dev/null || \
            iptables -t raw -I OUTPUT 1 -p tcp --sport "$port" -m comment --comment "$TAG" -j NOTRACK 2>/dev/null || \
            echo -e "${YELLOW}[!]${NC} Failed to add OUTPUT NOTRACK rule" >&2
        iptables -t mangle -C OUTPUT -p tcp --sport "$port" -m comment --comment "$TAG" --tcp-flags RST RST -j DROP 2>/dev/null || \
            iptables -t mangle -I OUTPUT 1 -p tcp --sport "$port" -m comment --comment "$TAG" --tcp-flags RST RST -j DROP 2>/dev/null || \
            echo -e "${YELLOW}[!]${NC} Failed to add RST DROP rule" >&2
        if command -v ip6tables &>/dev/null; then
            ip6tables -t raw -C PREROUTING -p tcp --dport "$port" -m comment --comment "$TAG" -j NOTRACK 2>/dev/null || \
                ip6tables -t raw -I PREROUTING 1 -p tcp --dport "$port" -m comment --comment "$TAG" -j NOTRACK 2>/dev/null || true
            ip6tables -t raw -C OUTPUT -p tcp --sport "$port" -m comment --comment "$TAG" -j NOTRACK 2>/dev/null || \
                ip6tables -t raw -I OUTPUT 1 -p tcp --sport "$port" -m comment --comment "$TAG" -j NOTRACK 2>/dev/null || true
            ip6tables -t mangle -C OUTPUT -p tcp --sport "$port" -m comment --comment "$TAG" --tcp-flags RST RST -j DROP 2>/dev/null || \
                ip6tables -t mangle -I OUTPUT 1 -p tcp --sport "$port" -m comment --comment "$TAG" --tcp-flags RST RST -j DROP 2>/dev/null || true
        fi
    fi
}

_remove_firewall() {
    if ! _is_firewalld_active && ! command -v iptables &>/dev/null; then
        return 0
    fi
    _egress_guard_remove

    if [ "$BACKEND" = "gfw-knocker" ]; then
        local vio_port
        if [ "$ROLE" = "server" ]; then
            vio_port="${GFK_VIO_PORT:-45000}"
        else
            vio_port="${GFK_VIO_CLIENT_PORT:-40000}"
        fi

        if _is_firewalld_active; then
            firewall-cmd --direct --remove-rule ipv4 raw PREROUTING 0 -p tcp --dport "$vio_port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || true
            firewall-cmd --direct --remove-rule ipv4 raw OUTPUT 0 -p tcp --sport "$vio_port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || true
            firewall-cmd --direct --remove-rule ipv4 filter INPUT 0 -p tcp --dport "$vio_port" -m comment --comment "paqctl" -j DROP 2>/dev/null || true
            firewall-cmd --direct --remove-rule ipv4 filter OUTPUT 0 -p tcp --sport "$vio_port" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP 2>/dev/null || true
            firewall-cmd --direct --remove-rule ipv6 filter INPUT 0 -p tcp --dport "$vio_port" -m comment --comment "paqctl" -j DROP 2>/dev/null || true
            firewall-cmd --direct --remove-rule ipv6 filter OUTPUT 0 -p tcp --sport "$vio_port" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP 2>/dev/null || true
        else
            local TAG="paqctl"
            iptables -t raw -D PREROUTING -p tcp --dport "$vio_port" -m comment --comment "$TAG" -j NOTRACK 2>/dev/null || true
            iptables -t raw -D OUTPUT -p tcp --sport "$vio_port" -m comment --comment "$TAG" -j NOTRACK 2>/dev/null || true
            iptables -t raw -D PREROUTING -p tcp --dport "$vio_port" -j NOTRACK 2>/dev/null || true
            iptables -t raw -D OUTPUT -p tcp --sport "$vio_port" -j NOTRACK 2>/dev/null || true
            iptables -D INPUT -p tcp --dport "$vio_port" -m comment --comment "$TAG" -j DROP 2>/dev/null || true
            iptables -D OUTPUT -p tcp --sport "$vio_port" --tcp-flags RST RST -m comment --comment "$TAG" -j DROP 2>/dev/null || true
            iptables -D INPUT -p tcp --dport "$vio_port" -j DROP 2>/dev/null || true
            iptables -D OUTPUT -p tcp --sport "$vio_port" --tcp-flags RST RST -j DROP 2>/dev/null || true
            if command -v ip6tables &>/dev/null; then
                ip6tables -D INPUT -p tcp --dport "$vio_port" -m comment --comment "$TAG" -j DROP 2>/dev/null || true
                ip6tables -D OUTPUT -p tcp --sport "$vio_port" --tcp-flags RST RST -m comment --comment "$TAG" -j DROP 2>/dev/null || true
                ip6tables -D INPUT -p tcp --dport "$vio_port" -j DROP 2>/dev/null || true
                ip6tables -D OUTPUT -p tcp --sport "$vio_port" --tcp-flags RST RST -j DROP 2>/dev/null || true
            fi
        fi
        return 0
    fi

    [ "$ROLE" != "server" ] && return 0
    local port="${LISTEN_PORT:-8443}"

    if _is_firewalld_active; then
        firewall-cmd --direct --remove-rule ipv4 raw PREROUTING 0 -p tcp --dport "$port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || true
        firewall-cmd --direct --remove-rule ipv4 raw OUTPUT 0 -p tcp --sport "$port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || true
        firewall-cmd --direct --remove-rule ipv4 mangle OUTPUT 0 -p tcp --sport "$port" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP 2>/dev/null || true
        firewall-cmd --direct --remove-rule ipv6 raw PREROUTING 0 -p tcp --dport "$port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || true
        firewall-cmd --direct --remove-rule ipv6 raw OUTPUT 0 -p tcp --sport "$port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null || true
        firewall-cmd --direct --remove-rule ipv6 mangle OUTPUT 0 -p tcp --sport "$port" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP 2>/dev/null || true
    else
        local TAG="paqctl"
        iptables -t raw -D PREROUTING -p tcp --dport "$port" -m comment --comment "$TAG" -j NOTRACK 2>/dev/null || true
        iptables -t raw -D OUTPUT -p tcp --sport "$port" -m comment --comment "$TAG" -j NOTRACK 2>/dev/null || true
        iptables -t mangle -D OUTPUT -p tcp --sport "$port" -m comment --comment "$TAG" --tcp-flags RST RST -j DROP 2>/dev/null || true
        iptables -t raw -D PREROUTING -p tcp --dport "$port" -j NOTRACK 2>/dev/null || true
        iptables -t raw -D OUTPUT -p tcp --sport "$port" -j NOTRACK 2>/dev/null || true
        iptables -t mangle -D OUTPUT -p tcp --sport "$port" --tcp-flags RST RST -j DROP 2>/dev/null || true
        if command -v ip6tables &>/dev/null; then
            ip6tables -t raw -D PREROUTING -p tcp --dport "$port" -m comment --comment "$TAG" -j NOTRACK 2>/dev/null || true
            ip6tables -t raw -D OUTPUT -p tcp --sport "$port" -m comment --comment "$TAG" -j NOTRACK 2>/dev/null || true
            ip6tables -t mangle -D OUTPUT -p tcp --sport "$port" -m comment --comment "$TAG" --tcp-flags RST RST -j DROP 2>/dev/null || true
            ip6tables -t raw -D PREROUTING -p tcp --dport "$port" -j NOTRACK 2>/dev/null || true
            ip6tables -t raw -D OUTPUT -p tcp --sport "$port" -j NOTRACK 2>/dev/null || true
            ip6tables -t mangle -D OUTPUT -p tcp --sport "$port" --tcp-flags RST RST -j DROP 2>/dev/null || true
        fi
    fi
}

# Remove ALL paqctl-tagged firewall rules (for complete uninstall)
_remove_all_paqctl_firewall_rules() {
    _egress_guard_remove
    # firewalld: remove paqctl-tagged direct rules
    if _is_firewalld_active; then
        local _rules
        _rules=$(firewall-cmd --direct --get-all-rules 2>/dev/null) || true
        if [ -n "$_rules" ]; then
            echo "$_rules" | grep "paqctl" | while IFS= read -r _rule; do
                firewall-cmd --direct --remove-rule $_rule 2>/dev/null || true
                firewall-cmd --permanent --direct --remove-rule $_rule 2>/dev/null || true
            done
        fi
        return 0
    fi

    command -v iptables &>/dev/null || return 0
    local TAG="paqctl"

    # Remove all rules with "paqctl" comment from all tables
    # Loop to remove multiple rules if port was changed
    local i
    for i in {1..10}; do
        iptables -t raw -S 2>/dev/null | grep -q "paqctl" || break
        iptables -t raw -S 2>/dev/null | grep "paqctl" | while read -r rule; do
            # Convert -A to -D for deletion
            local del_rule="${rule/-A /-D }"
            eval "iptables -t raw $del_rule" 2>/dev/null || true
        done
    done

    for i in {1..10}; do
        iptables -t mangle -S 2>/dev/null | grep -q "paqctl" || break
        iptables -t mangle -S 2>/dev/null | grep "paqctl" | while read -r rule; do
            local del_rule="${rule/-A /-D }"
            eval "iptables -t mangle $del_rule" 2>/dev/null || true
        done
    done

    for i in {1..10}; do
        iptables -S 2>/dev/null | grep -q "paqctl" || break
        iptables -S 2>/dev/null | grep "paqctl" | while read -r rule; do
            local del_rule="${rule/-A /-D }"
            eval "iptables $del_rule" 2>/dev/null || true
        done
    done

    # Same for IPv6
    if command -v ip6tables &>/dev/null; then
        for i in {1..10}; do
            ip6tables -t raw -S 2>/dev/null | grep -q "paqctl" || break
            ip6tables -t raw -S 2>/dev/null | grep "paqctl" | while read -r rule; do
                local del_rule="${rule/-A /-D }"
                eval "ip6tables -t raw $del_rule" 2>/dev/null || true
            done
        done

        for i in {1..10}; do
            ip6tables -t mangle -S 2>/dev/null | grep -q "paqctl" || break
            ip6tables -t mangle -S 2>/dev/null | grep "paqctl" | while read -r rule; do
                local del_rule="${rule/-A /-D }"
                eval "ip6tables -t mangle $del_rule" 2>/dev/null || true
            done
        done

        for i in {1..10}; do
            ip6tables -S 2>/dev/null | grep -q "paqctl" || break
            ip6tables -S 2>/dev/null | grep "paqctl" | while read -r rule; do
                local del_rule="${rule/-A /-D }"
                eval "ip6tables $del_rule" 2>/dev/null || true
            done
        done
    fi
}

_persist_firewall() {
    persist_iptables_rules
}
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
            local eg_on=false eg_active=false
            _egress_guard_wanted && eg_on=true
            _egress_guard_active && eg_active=true
            printf '"listen_port":%s,' "$(_json_num "${LISTEN_PORT:-}")"
            printf '"egress_guard":{"enabled":%s,"active":%s,"allow":%s},' \
                "$(_json_bool "$eg_on")" "$(_json_bool "$eg_active")" "$(_json_str "${EGRESS_ALLOW:-}")"
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
            if ! _egress_guard_wanted; then
                echo -e "  Egress:     ${YELLOW}Guard off${NC} ${DIM}(clients can reach private networks)${NC}"
            elif _egress_guard_active; then
                echo -e "  Egress:     ${GREEN}Private networks blocked${NC}${EGRESS_ALLOW:+ ${DIM}(allowed: ${EGRESS_ALLOW})${NC}}"
            elif is_running; then
                echo -e "  Egress:     ${RED}Guard missing${NC} ${DIM}(sudo paqctl doctor --fix)${NC}"
            else
                echo -e "  Egress:     ${DIM}Guard installed on start${NC}"
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
            if ! _egress_guard_wanted; then
                _hc warn "Egress guard is off: clients can reach this host's loopback, private networks and cloud metadata" \
                    "Turn it on: sudo paqctl config set EGRESS_GUARD=true"
            elif _is_firewalld_active; then
                _hc warn "Egress guard is not available with firewalld: clients can reach this host's private networks"
            elif [ ! -d /run/systemd/system ]; then
                _hc warn "Egress guard needs systemd: clients can reach this host's private networks"
            elif _egress_guard_active; then
                _hc ok "Egress guard on (clients cannot reach private/loopback/metadata addresses)"
            elif is_running; then
                _hc fail "Egress guard missing: clients can reach this host's private networks" \
                    "Apply firewall rules: sudo paqctl doctor --fix" firewall
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

        if [ "$ROLE" = "server" ] && _egress_guard_wanted && _egress_guard_active && is_running; then
            case "$(_egress_selftest)" in
                blocked) _hc ok "Egress guard verified (paqet's connection to 127.0.0.1 was rejected)" ;;
                open)    _hc fail "Egress guard is not blocking paqet (stale rule?)" \
                             "Rebuild it: sudo paqctl doctor --fix (or sudo paqctl restart)" firewall ;;
            esac
            local _blocks _nblk
            _blocks=$(_egress_recent_blocks "24 hours ago")
            if [ -n "$_blocks" ]; then
                _nblk=$(awk '{s += $1} END {print s + 0}' <<< "$_blocks")
                _hc info "Egress guard rejected ${_nblk}+ connection(s) in 24h; top: $(head -3 <<< "$_blocks" | awk '{c=$1; $1=""; printf "%s%s (x%s)", (NR>1?", ":""), substr($0,2), c}')" \
                    "If a client really needs one of these, allow it: sudo paqctl config set EGRESS_ALLOW=\"127.0.0.1:80\" (see: paqctl help config)"
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
#═══════════════════════════════════════════════════════════════════════
# Update
#═══════════════════════════════════════════════════════════════════════

update_gfk() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  UPDATE GFW-KNOCKER${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""

    log_info "Downloading latest GFW-knocker scripts..."
    local tmp_dir
    tmp_dir=$(mktemp -d)
    local server_files="mainserver.py quic_server.py vio_server.py"
    local client_files="mainclient.py quic_client.py vio_client.py"
    local f changed=false
    # Download server scripts
    for f in $server_files; do
        if ! curl -sL "$GFK_RAW_URL/server/$f" -o "$tmp_dir/$f"; then
            log_error "Failed to download $f"
            rm -rf "$tmp_dir"
            return 1
        fi
        if ! diff -q "$tmp_dir/$f" "$GFK_DIR/$f" &>/dev/null; then
            changed=true
        fi
    done
    # Download client scripts
    for f in $client_files; do
        if ! curl -sL "$GFK_RAW_URL/client/$f" -o "$tmp_dir/$f"; then
            log_error "Failed to download $f"
            rm -rf "$tmp_dir"
            return 1
        fi
        if ! diff -q "$tmp_dir/$f" "$GFK_DIR/$f" &>/dev/null; then
            changed=true
        fi
    done

    if [ "$changed" = true ]; then
        local was_running=false
        is_running && was_running=true
        [ "$was_running" = true ] && stop_paqet

        # Backup old scripts
        mkdir -p "$BACKUP_DIR"
        local all_files="$server_files $client_files"
        for f in $all_files; do
            [ -f "$GFK_DIR/$f" ] && cp "$GFK_DIR/$f" "$BACKUP_DIR/${f}.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true
        done

        for f in $all_files; do
            cp "$tmp_dir/$f" "$GFK_DIR/$f"
        done
        chmod 600 "$GFK_DIR"/*.py
        # Patch mainserver.py to use venv python for subprocesses
        [ -f "$GFK_DIR/mainserver.py" ] && sed -i "s|'python3'|'$INSTALL_DIR/venv/bin/python'|g" "$GFK_DIR/mainserver.py"
        log_success "GFW-knocker scripts updated"

        # Also upgrade Python deps in venv
        "$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade scapy aioquic 2>/dev/null || true

        [ "$was_running" = true ] && start_paqet
    else
        log_success "GFW-knocker scripts are already up to date"
        "$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade scapy aioquic 2>/dev/null || true
    fi
    rm -rf "$tmp_dir"

    # Regenerate client wrapper (removes legacy microsocks startup)
    if [ "$ROLE" = "client" ]; then
        create_gfk_client_wrapper
        pkill -f "${INSTALL_DIR}/bin/microsocks" 2>/dev/null || true
    fi

    # Also check for management script updates
    update_management_script
    echo ""
}

update_paqet() {
    if [ "$BACKEND" = "gfw-knocker" ]; then
        update_gfk
        return
    fi

    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  UPDATE PAQET${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""

    log_info "Querying GitHub for latest release..."

    # Get latest version from GitHub with retry
    local response
    response=$(_curl_with_retry "$PAQET_API_URL" 3)
    if [ -z "$response" ]; then
        log_error "Failed to query GitHub API after retries. Check your internet connection."
        return 1
    fi

    local latest_tag
    latest_tag=$(echo "$response" | grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | grep -o '"[^"]*"$' | tr -d '"')
    if [ -z "$latest_tag" ] || ! _validate_version_tag "$latest_tag"; then
        log_error "Could not determine valid version from GitHub"
        return 1
    fi

    # Extract release date
    local release_date
    release_date=$(echo "$response" | grep -o '"published_at"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | grep -o '"[^"]*"$' | tr -d '"' | cut -dT -f1)

    # Extract release notes (body field)
    local release_notes=""
    if command -v python3 &>/dev/null; then
        release_notes=$(python3 -c "
import json,sys
try:
    d=json.loads(sys.stdin.read())
    body=d.get('body','')
    if body:
        # Truncate to first 500 chars, strip markdown
        body=body[:500].replace('**','').replace('##','').replace('# ','')
        print(body)
except: pass
" <<< "$response" 2>/dev/null)
    fi

    local current="${PAQET_VERSION:-unknown}"
    local bin_ver
    bin_ver=$("$INSTALL_DIR/bin/paqet" version 2>/dev/null || echo "unknown")

    echo ""
    echo -e "  ${DIM}── Version Info ──${NC}"
    echo -e "  Installed version:  ${BOLD}${current}${NC}"
    echo -e "  Binary reports:     ${BOLD}${bin_ver}${NC}"
    echo -e "  Latest release:     ${BOLD}${latest_tag}${NC}"
    [ -n "$release_date" ] && echo -e "  Release date:       ${release_date}"

    if [ "$current" = "$latest_tag" ]; then
        echo ""
        log_success "You are already on the latest version!"
        if [ "$ASSUME_YES" = true ] || ! _has_tty; then
            update_management_script
            return
        fi
        echo ""
        echo -e "  ${DIM}Options:${NC}"
        echo "  1. Force reinstall current version"
        echo "  2. Rollback to previous version"
        echo "  3. Update management script only"
        echo "  b. Back"
        echo ""
        read -p "  Choice: " up_choice < /dev/tty || true
        case "$up_choice" in
            1)
                _confirm "Force reinstall ${current}?" || { log_info "Cancelled"; return 0; }
                ;;
            2) rollback_paqet; return ;;
            3) update_management_script; return ;;
            [bB]) return 0 ;;
            *) return 0 ;;
        esac
    fi

    # Show release notes if available
    if [ -n "$release_notes" ]; then
        echo ""
        echo -e "  ${DIM}── Release Notes ──${NC}"
        echo "$release_notes" | while IFS= read -r line; do
            echo -e "  ${DIM}${line}${NC}"
        done
        echo ""
    fi

    echo ""
    echo -e "${YELLOW}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║  ${BOLD}⚠ WARNING: Updating may cause compatibility issues!${NC}${YELLOW}            ║${NC}"
    echo -e "${YELLOW}╠════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${YELLOW}║${NC}  paqctl was tested with: ${BOLD}${PAQET_VERSION_PINNED}${NC}"
    echo -e "${YELLOW}║${NC}  Newer versions may have breaking changes or bugs."
    echo -e "${YELLOW}║${NC}  You can rollback with: ${BOLD}sudo paqctl rollback${NC}"
    echo -e "${YELLOW}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    if ! _confirm "Update to ${latest_tag}?"; then
        log_info "Update cancelled"
        return 1
    fi

    # Download new binary
    _download_and_install_binary "$latest_tag" || return 1

    # Check for management script update
    update_management_script
}

_download_and_install_binary() {
    local target_tag="$1"
    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64|amd64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *) log_error "Unsupported architecture: $arch"; return 1 ;;
    esac

    local filename="paqet-linux-${arch}-${target_tag}.tar.gz"
    local url="https://github.com/${PAQET_REPO}/releases/download/${target_tag}/${filename}"
    local tmp_file
    tmp_file=$(mktemp "/tmp/paqet-update-XXXXXXXX.tar.gz")

    log_info "Downloading ${filename}..."
    if ! curl -sL --max-time 120 --fail -o "$tmp_file" "$url"; then
        log_error "Download failed: $url"
        rm -f "$tmp_file"
        return 1
    fi

    # Validate
    local fsize
    fsize=$(stat -c%s "$tmp_file" 2>/dev/null || stat -f%z "$tmp_file" 2>/dev/null || wc -c < "$tmp_file" 2>/dev/null || echo 0)
    if [ "$fsize" -lt 1000 ]; then
        log_error "Downloaded file too small ($fsize bytes). Aborting."
        rm -f "$tmp_file"
        return 1
    fi

    # Extract
    local tmp_extract
    tmp_extract=$(mktemp -d "/tmp/paqet-update-extract-XXXXXXXX")
    if ! tar -xzf "$tmp_file" -C "$tmp_extract" 2>/dev/null; then
        log_error "Failed to extract archive"
        rm -f "$tmp_file"
        rm -rf "$tmp_extract"
        return 1
    fi

    local binary_name="paqet_linux_${arch}"
    local found_binary
    found_binary=$(find "$tmp_extract" -name "$binary_name" -type f 2>/dev/null | head -1)
    [ -z "$found_binary" ] && found_binary=$(find "$tmp_extract" -name "paqet*" -type f -executable 2>/dev/null | head -1)
    [ -z "$found_binary" ] && found_binary=$(find "$tmp_extract" -name "paqet*" -type f 2>/dev/null | head -1)

    if [ -z "$found_binary" ]; then
        log_error "Could not find paqet binary in archive"
        rm -f "$tmp_file"
        rm -rf "$tmp_extract"
        return 1
    fi

    # Stop service, replace, start
    local was_running=false
    if is_running; then
        was_running=true
        stop_paqet
    fi

    # Backup old binary with version tag for rollback
    if ! mkdir -p "$BACKUP_DIR"; then
        log_warn "Failed to create backup directory"
    fi
    local old_ver="${PAQET_VERSION:-unknown}"
    cp "$INSTALL_DIR/bin/paqet" "$BACKUP_DIR/paqet.${old_ver}.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true

    if ! cp "$found_binary" "$INSTALL_DIR/bin/paqet"; then
        log_error "Failed to copy new binary"
        rm -f "$tmp_file"
        rm -rf "$tmp_extract"
        # Restore from backup
        local latest_backup
        latest_backup=$(ls -t "$BACKUP_DIR"/paqet.* 2>/dev/null | head -1)
        [ -n "$latest_backup" ] && cp "$latest_backup" "$INSTALL_DIR/bin/paqet" && chmod +x "$INSTALL_DIR/bin/paqet"
        [ "$was_running" = true ] && start_paqet
        return 1
    fi
    chmod +x "$INSTALL_DIR/bin/paqet"

    rm -f "$tmp_file"
    rm -rf "$tmp_extract"

    # Verify the new binary works
    if ! "$INSTALL_DIR/bin/paqet" version &>/dev/null; then
        log_warn "New binary failed verification. Restoring backup..."
        local latest_backup
        latest_backup=$(ls -t "$BACKUP_DIR"/paqet.* 2>/dev/null | head -1)
        if [ -n "$latest_backup" ]; then
            cp "$latest_backup" "$INSTALL_DIR/bin/paqet"
            chmod +x "$INSTALL_DIR/bin/paqet"
            log_error "Update failed — previous version restored"
            return 1
        fi
        log_error "Update failed and no backup available"
        return 1
    fi

    # Update version in settings
    PAQET_VERSION="$target_tag"
    _safe_update_setting "PAQET_VERSION" "$target_tag" "$INSTALL_DIR/settings.conf"

    log_success "paqet updated to ${target_tag}"

    if [ "$was_running" = true ]; then
        start_paqet
    fi
}

rollback_paqet() {
    echo ""
    if [ ! -d "$BACKUP_DIR" ]; then
        log_warn "No backups found"
        return 1
    fi

    local backups=()
    local i=1
    echo -e "  ${BOLD}Available binary backups:${NC}"
    echo ""
    for f in "$BACKUP_DIR"/paqet.*; do
        [ -f "$f" ] || continue
        backups+=("$f")
        local bname=$(basename "$f")
        local bsize=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f" 2>/dev/null || wc -c < "$f" 2>/dev/null || echo "?")
        echo "  $i. $bname  (${bsize} bytes)"
        i=$((i + 1))
    done

    if [ ${#backups[@]} -eq 0 ]; then
        log_warn "No binary backups found in $BACKUP_DIR"
        return 1
    fi

    echo ""
    echo "  0. Cancel"
    echo ""
    read -p "  Select backup to restore [0-${#backups[@]}]: " choice < /dev/tty || true
    if [ "$choice" = "0" ]; then
        log_info "Cancelled"
        return 0
    fi
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt ${#backups[@]} ]; then
        log_error "Invalid choice"
        return 1
    fi

    local selected="${backups[$((choice-1))]}"
    log_info "Rolling back to: $(basename "$selected")"

    local was_running=false
    is_running && was_running=true
    [ "$was_running" = true ] && stop_paqet

    if ! cp "$selected" "$INSTALL_DIR/bin/paqet"; then
        log_error "Failed to restore backup"
        [ "$was_running" = true ] && start_paqet
        return 1
    fi
    chmod +x "$INSTALL_DIR/bin/paqet"

    # Verify restored binary
    if ! "$INSTALL_DIR/bin/paqet" version &>/dev/null; then
        log_warn "Restored binary failed verification (may need libpcap)"
    fi

    # Try to extract version from the filename (format: paqet.vX.Y.Z.TIMESTAMP)
    local restored_ver=""
    local _bname
    _bname=$(basename "$selected")
    # Extract version: remove 'paqet.' prefix and '.YYYYMMDDHHMMSS' timestamp suffix
    restored_ver=$(echo "$_bname" | sed 's/^paqet\.//' | sed 's/\.[0-9]\{14\}$//')
    # Validate extracted version looks reasonable
    if [ -n "$restored_ver" ] && [ "$restored_ver" != "backup" ] && [ "$restored_ver" != "$_bname" ]; then
        if _validate_version_tag "$restored_ver"; then
            PAQET_VERSION="$restored_ver"
            _safe_update_setting "PAQET_VERSION" "$restored_ver" "$INSTALL_DIR/settings.conf"
            log_info "Restored version: $restored_ver"
        else
            log_warn "Could not determine version from backup filename, keeping current version setting"
        fi
    else
        log_warn "Could not extract version from backup filename"
    fi

    log_success "Rolled back successfully"

    [ "$was_running" = true ] && start_paqet
}

update_management_script() {
    local update_url="https://raw.githubusercontent.com/4H1R/paqctl/main/paqctl.sh"
    local tmp_script
    tmp_script=$(mktemp "/tmp/paqctl-update-XXXXXXXX.sh")

    log_info "Checking for management script updates..."
    if ! curl -sfL --max-time 30 --max-filesize 4194304 -o "$tmp_script" "$update_url" 2>/dev/null; then
        log_warn "Could not download the management script update"
        rm -f "$tmp_script"
        return 1
    fi

    # Validate: must contain our markers, be a bash script, and pass syntax check
    if ! head -n 1 "$tmp_script" 2>/dev/null | grep -q "^#!.*bash"; then
        log_warn "Downloaded file is not a bash script, skipping"
        rm -f "$tmp_script"
        return 1
    fi
    local _rc=0
    if grep -q "PAQET_REPO=" "$tmp_script" && \
       grep -q "create_management_script" "$tmp_script" && \
       grep -q "PAQCTL_VERSION=" "$tmp_script" && \
       bash -n "$tmp_script" 2>/dev/null; then
        local _new_ver
        _new_ver=$(grep -m1 '^VERSION=' "$tmp_script" | cut -d'"' -f2)
        local _update_output
        if _update_output=$(bash "$tmp_script" --update-components 2>&1); then
            log_success "Management script updated (${VERSION} → ${_new_ver:-unknown})"
        else
            log_warn "Management script update execution failed: ${_update_output:-unknown error}"
            _rc=1
        fi
    else
        log_warn "Downloaded script failed validation, skipping"
        _rc=1
    fi
    rm -f "$tmp_script"
    return $_rc
}

#═══════════════════════════════════════════════════════════════════════
# Secret Key Generation
#═══════════════════════════════════════════════════════════════════════

generate_secret() {
    echo ""
    local key
    key=$("$INSTALL_DIR/bin/paqet" secret 2>/dev/null || true)
    if [ -z "$key" ]; then
        key=$(openssl rand -base64 32 2>/dev/null | tr -d '=+/' | head -c 32)
    fi
    echo -e "  ${GREEN}${BOLD}New encryption key: ${key}${NC}"
    echo ""
    echo -e "  ${DIM}Share this key securely with client users.${NC}"
    echo ""
}
#═══════════════════════════════════════════════════════════════════════
# Firewall Display
#═══════════════════════════════════════════════════════════════════════

show_firewall() {
    if [ "$ROLE" != "server" ] && [ "$BACKEND" != "gfw-knocker" ]; then
        echo ""
        log_info "Firewall rules only apply in server mode or GFK client mode"
        echo ""
        return
    fi

    local redraw=true
    while true; do
        if [ "$redraw" = true ]; then
            echo ""
            echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
            echo -e "${BOLD}  FIREWALL RULES${NC}"
            echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
            echo ""

            local _fw_backend="iptables"
            _is_firewalld_active && _fw_backend="firewalld"
            echo -e "  ${DIM}Backend: ${_fw_backend}${NC}"
            echo ""

            if [ "$BACKEND" = "gfw-knocker" ]; then
                local vio_port
                if [ "$ROLE" = "server" ]; then
                    vio_port="${GFK_VIO_PORT:-45000}"
                else
                    vio_port="${GFK_VIO_CLIENT_PORT:-40000}"
                fi
                echo -e "  ${BOLD}Required rules for VIO port ${vio_port}:${NC}"
                echo ""
                if [ "$_fw_backend" = "firewalld" ]; then
                    firewall-cmd --direct --query-rule ipv4 raw PREROUTING 0 -p tcp --dport "$vio_port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null \
                        && echo -e "  ${GREEN}✓${NC} PREROUTING NOTRACK (dport $vio_port)" \
                        || echo -e "  ${RED}✗${NC} PREROUTING NOTRACK (dport $vio_port)  ${DIM}MISSING${NC}"
                    firewall-cmd --direct --query-rule ipv4 raw OUTPUT 0 -p tcp --sport "$vio_port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null \
                        && echo -e "  ${GREEN}✓${NC} OUTPUT NOTRACK (sport $vio_port)" \
                        || echo -e "  ${RED}✗${NC} OUTPUT NOTRACK (sport $vio_port)  ${DIM}MISSING${NC}"
                    firewall-cmd --direct --query-rule ipv4 filter INPUT 0 -p tcp --dport "$vio_port" -m comment --comment "paqctl" -j DROP 2>/dev/null \
                        && echo -e "  ${GREEN}✓${NC} INPUT DROP (dport $vio_port)" \
                        || echo -e "  ${RED}✗${NC} INPUT DROP (dport $vio_port)  ${DIM}MISSING${NC}"
                    firewall-cmd --direct --query-rule ipv4 filter OUTPUT 0 -p tcp --sport "$vio_port" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP 2>/dev/null \
                        && echo -e "  ${GREEN}✓${NC} RST DROP (sport $vio_port)" \
                        || echo -e "  ${RED}✗${NC} RST DROP (sport $vio_port)  ${DIM}MISSING${NC}"
                else
                    iptables -t raw -C PREROUTING -p tcp --dport "$vio_port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null \
                        && echo -e "  ${GREEN}✓${NC} PREROUTING NOTRACK (dport $vio_port)" \
                        || echo -e "  ${RED}✗${NC} PREROUTING NOTRACK (dport $vio_port)  ${DIM}MISSING${NC}"
                    iptables -t raw -C OUTPUT -p tcp --sport "$vio_port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null \
                        && echo -e "  ${GREEN}✓${NC} OUTPUT NOTRACK (sport $vio_port)" \
                        || echo -e "  ${RED}✗${NC} OUTPUT NOTRACK (sport $vio_port)  ${DIM}MISSING${NC}"
                    iptables -C INPUT -p tcp --dport "$vio_port" -m comment --comment "paqctl" -j DROP 2>/dev/null \
                        && echo -e "  ${GREEN}✓${NC} INPUT DROP (dport $vio_port)" \
                        || echo -e "  ${RED}✗${NC} INPUT DROP (dport $vio_port)  ${DIM}MISSING${NC}"
                    iptables -C OUTPUT -p tcp --sport "$vio_port" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP 2>/dev/null \
                        && echo -e "  ${GREEN}✓${NC} RST DROP (sport $vio_port)" \
                        || echo -e "  ${RED}✗${NC} RST DROP (sport $vio_port)  ${DIM}MISSING${NC}"
                fi
            else
                local port="${LISTEN_PORT:-8443}"
                echo -e "  ${BOLD}Required rules for port ${port}:${NC}"
                echo ""
                if [ "$_fw_backend" = "firewalld" ]; then
                    firewall-cmd --direct --query-rule ipv4 raw PREROUTING 0 -p tcp --dport "$port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null \
                        && echo -e "  ${GREEN}✓${NC} PREROUTING NOTRACK (dport $port)" \
                        || echo -e "  ${RED}✗${NC} PREROUTING NOTRACK (dport $port)  ${DIM}MISSING${NC}"
                    firewall-cmd --direct --query-rule ipv4 raw OUTPUT 0 -p tcp --sport "$port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null \
                        && echo -e "  ${GREEN}✓${NC} OUTPUT NOTRACK (sport $port)" \
                        || echo -e "  ${RED}✗${NC} OUTPUT NOTRACK (sport $port)  ${DIM}MISSING${NC}"
                    firewall-cmd --direct --query-rule ipv4 mangle OUTPUT 0 -p tcp --sport "$port" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP 2>/dev/null \
                        && echo -e "  ${GREEN}✓${NC} RST DROP (sport $port)" \
                        || echo -e "  ${RED}✗${NC} RST DROP (sport $port)  ${DIM}MISSING${NC}"
                else
                    iptables -t raw -C PREROUTING -p tcp --dport "$port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null \
                        && echo -e "  ${GREEN}✓${NC} PREROUTING NOTRACK (dport $port)" \
                        || echo -e "  ${RED}✗${NC} PREROUTING NOTRACK (dport $port)  ${DIM}MISSING${NC}"
                    iptables -t raw -C OUTPUT -p tcp --sport "$port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null \
                        && echo -e "  ${GREEN}✓${NC} OUTPUT NOTRACK (sport $port)" \
                        || echo -e "  ${RED}✗${NC} OUTPUT NOTRACK (sport $port)  ${DIM}MISSING${NC}"
                    iptables -t mangle -C OUTPUT -p tcp --sport "$port" -m comment --comment "paqctl" --tcp-flags RST RST -j DROP 2>/dev/null \
                        && echo -e "  ${GREEN}✓${NC} RST DROP (sport $port)" \
                        || echo -e "  ${RED}✗${NC} RST DROP (sport $port)  ${DIM}MISSING${NC}"
                fi
                echo ""
                if ! _egress_guard_wanted; then
                    echo -e "  ${YELLOW}!${NC} Egress guard OFF  ${DIM}(sudo paqctl config set EGRESS_GUARD=true)${NC}"
                elif _egress_guard_active; then
                    echo -e "  ${GREEN}✓${NC} Egress guard (paqet cannot reach private/loopback/metadata addresses)"
                    [ -n "${EGRESS_ALLOW:-}" ] && echo -e "    ${DIM}Allowed: ${EGRESS_ALLOW}${NC}"
                elif is_running; then
                    echo -e "  ${RED}✗${NC} Egress guard  ${DIM}MISSING${NC}"
                else
                    echo -e "  ${DIM}• Egress guard is installed when paqet starts${NC}"
                fi
            fi

            echo ""
            echo -e "  ${BOLD}Actions:${NC}"
            echo "  1. Apply missing rules"
            echo "  2. Remove all rules"
            echo "  b. Back"
            echo ""
            redraw=false
        fi

        read -p "  Choice: " fw_choice < /dev/tty || break
        case "$fw_choice" in
            1)
                _apply_firewall
                _persist_firewall
                log_success "Firewall rules applied and persisted"
                read -n 1 -s -r -p "  Press any key..." < /dev/tty || true
                redraw=true
                ;;
            2)
                _remove_firewall
                _persist_firewall
                log_success "Firewall rules removed"
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
#═══════════════════════════════════════════════════════════════════════
# Backup & Restore
#═══════════════════════════════════════════════════════════════════════

# Files (relative to $INSTALL_DIR) that make up a paqctl configuration
_BACKUP_FILES=(config.yaml settings.conf banned_ips gfk/parameters.py gfk/cert.pem gfk/key.pem bin/gfk-client.sh)
PAQCTL_BACKUP_KEEP="${PAQCTL_BACKUP_KEEP:-10}"

# Newest first
_list_backups() {
    [ -d "$BACKUP_DIR" ] || return 0
    ls -1t "$BACKUP_DIR"/paqctl-backup-*.tar.gz 2>/dev/null || true
}

_prune_backups() {
    local keep="$PAQCTL_BACKUP_KEEP" f n=0 removed=0
    [[ "$keep" =~ ^[0-9]+$ ]] && [ "$keep" -ge 1 ] || keep=10
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        n=$((n + 1))
        if [ "$n" -gt "$keep" ]; then
            rm -f "$f" && removed=$((removed + 1))
        fi
    done < <(_list_backups)
    echo "$removed"
}

# backup_config [--quiet] [--label NAME] [--no-prune]
# Prints the backup path on stdout when --quiet is given.
backup_config() {
    local quiet=false label="" prune=true
    while [ $# -gt 0 ]; do
        case "$1" in
            --quiet) quiet=true; shift ;;
            --label) label="${2:-}"; shift 2 ;;
            --no-prune) prune=false; shift ;;
            *) log_error "Unknown option for backup: $1"; return 2 ;;
        esac
    done
    (umask 077; mkdir -p "$BACKUP_DIR")
    chmod 700 "$BACKUP_DIR" 2>/dev/null

    local -a members=()
    local m
    for m in "${_BACKUP_FILES[@]}"; do
        [ -f "$INSTALL_DIR/$m" ] && members+=("$m")
    done
    if [ ${#members[@]} -eq 0 ]; then
        log_error "Nothing to back up (no configuration files found in $INSTALL_DIR)"
        return 1
    fi

    local ts backup_file i=1
    ts=$(date +%Y%m%d%H%M%S)
    [[ "$label" =~ ^[a-z0-9-]+$ ]] && ts="${ts}-${label}"
    backup_file="$BACKUP_DIR/paqctl-backup-${ts}.tar.gz"
    while [ -e "$backup_file" ]; do
        backup_file="$BACKUP_DIR/paqctl-backup-${ts}-${i}.tar.gz"
        i=$((i + 1))
    done

    if ! (umask 077; tar -czf "$backup_file" -C "$INSTALL_DIR" "${members[@]}" 2>/dev/null); then
        log_error "Failed to create backup archive"
        rm -f "$backup_file"
        return 1
    fi
    local pruned=0
    [ "$prune" = true ] && pruned=$(_prune_backups)

    if [ "$quiet" = true ]; then
        echo "$backup_file"
    else
        echo ""
        log_success "Backup saved to: $backup_file"
        echo -e "  ${DIM}Contains: ${members[*]}${NC}"
        [ "$pruned" -gt 0 ] 2>/dev/null && echo -e "  ${DIM}Removed $pruned old backup(s); keeping the newest ${PAQCTL_BACKUP_KEEP}.${NC}"
        echo ""
    fi
}

# Refuse archives containing anything other than known config files
_backup_members_ok() {
    local archive="$1" entry allowed ok
    local listing
    listing=$(tar -tzf "$archive" 2>/dev/null) || return 1
    [ -n "$listing" ] || return 1
    while IFS= read -r entry; do
        entry="${entry#./}"
        [ -z "$entry" ] && continue
        ok=false
        for allowed in "${_BACKUP_FILES[@]}" gfk/ bin/; do
            [ "$entry" = "$allowed" ] && { ok=true; break; }
        done
        if [ "$ok" != true ]; then
            log_error "Backup contains an unexpected file: $entry"
            return 1
        fi
    done <<< "$listing"
}

# restore_config [FILE | latest | N]
restore_config() {
    echo ""
    local -a backups=()
    local f
    while IFS= read -r f; do [ -n "$f" ] && backups+=("$f"); done < <(_list_backups)

    local selected="" arg="${1:-}"
    if [ -n "$arg" ]; then
        if [ "$arg" = "latest" ]; then
            [ ${#backups[@]} -gt 0 ] || { log_warn "No backups found in $BACKUP_DIR"; return 1; }
            selected="${backups[0]}"
        elif [[ "$arg" =~ ^[0-9]+$ ]]; then
            if [ "$arg" -lt 1 ] || [ "$arg" -gt ${#backups[@]} ]; then
                log_error "No backup #$arg (have ${#backups[@]}; newest is #1)"
                return 1
            fi
            selected="${backups[$((arg - 1))]}"
        elif [ -f "$arg" ]; then
            selected="$arg"
        elif [ -f "$BACKUP_DIR/$arg" ]; then
            selected="$BACKUP_DIR/$arg"
        else
            log_error "Backup not found: $arg"
            return 1
        fi
    else
        if [ ${#backups[@]} -eq 0 ]; then
            log_warn "No backups found in $BACKUP_DIR"
            return 1
        fi
        if ! _has_tty; then
            log_error "No terminal for interactive selection. Use: paqctl restore latest | paqctl restore <file>"
            return 1
        fi
        echo -e "${BOLD}Available backups (newest first):${NC}"
        echo ""
        local i=1
        for f in "${backups[@]}"; do
            echo "  $i. $(basename "$f")"
            i=$((i + 1))
        done
        echo ""
        echo "  0. Cancel"
        echo ""
        local choice
        read -r -p "  Select backup [0-${#backups[@]}]: " choice < /dev/tty || true
        if [ "$choice" = "0" ] || [ -z "$choice" ]; then
            log_info "Cancelled"
            return 0
        fi
        if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt ${#backups[@]} ]; then
            log_error "Invalid choice"
            return 1
        fi
        selected="${backups[$((choice - 1))]}"
    fi

    if ! _backup_members_ok "$selected"; then
        log_error "Refusing to restore $(basename "$selected"): not a valid paqctl backup"
        return 1
    fi

    _confirm "Restore $(basename "$selected")? Your current configuration is backed up first." || { log_info "Cancelled"; return 1; }

    # Safety net. No pruning here so the archive being restored is never removed.
    local safety
    if safety=$(backup_config --quiet --label pre-restore --no-prune 2>/dev/null); then
        log_info "Current configuration saved to: $safety"
    fi

    log_info "Restoring from: $(basename "$selected")"
    local was_running=false
    is_running && was_running=true
    [ "$was_running" = true ] && stop_paqet

    if ! (umask 077; tar -xzf "$selected" -C "$INSTALL_DIR" 2>/dev/null); then
        log_error "Failed to extract backup archive"
        [ "$was_running" = true ] && start_paqet
        return 1
    fi
    local m
    for m in "${_BACKUP_FILES[@]}"; do
        [ -f "$INSTALL_DIR/$m" ] || continue
        chown root:root "$INSTALL_DIR/$m" 2>/dev/null
        case "$m" in
            bin/*) chmod 700 "$INSTALL_DIR/$m" 2>/dev/null ;;
            *) chmod 600 "$INSTALL_DIR/$m" 2>/dev/null ;;
        esac
    done

    _load_settings
    _prune_backups >/dev/null
    log_success "Configuration restored"

    if [ "$was_running" = true ]; then
        start_paqet || return 1
    fi
}
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
#═══════════════════════════════════════════════════════════════════════
# Uninstall
#═══════════════════════════════════════════════════════════════════════

uninstall_paqctl() {
    echo ""
    echo -e "${RED}${BOLD}  UNINSTALL PAQCTL${NC}"
    echo ""
    echo -e "  This will remove:"
    if [ "$BACKEND" = "gfw-knocker" ]; then
        echo "  - GFW-knocker scripts and config"
    else
        echo "  - paqet binary"
    fi
    echo "  - All configuration files"
    echo "  - Systemd services"
    echo "  - Firewall rules (including IP bans)"
    echo "  - Telegram service, watchdog and shell completion"
    echo "  - Backups in $BACKUP_DIR"
    echo ""
    if ! _confirm "Are you sure?"; then
        log_info "Cancelled"
        return 1
    fi

    # Stop services
    stop_paqet
    stop_telegram_service
    manage_watchdog disable &>/dev/null || true
    rm -f /usr/share/bash-completion/completions/paqctl /etc/bash_completion.d/paqctl \
          /usr/share/zsh/site-functions/_paqctl /usr/local/share/zsh/site-functions/_paqctl 2>/dev/null || true

    # Stop standalone GFK xray and clean up config
    pkill -f "xray run -c.*gfk-socks.json" 2>/dev/null || true
    rm -f /usr/local/etc/xray/gfk-socks.json 2>/dev/null
    # If xray is paqctl's standalone install, stop and disable it entirely
    if _is_paqctl_standalone_xray; then
        log_info "Stopping paqctl's standalone Xray..."
        systemctl stop xray 2>/dev/null || true
        systemctl disable xray 2>/dev/null || true
    elif [ -f "$XRAY_CONFIG_FILE" ] && command -v python3 &>/dev/null; then
        # Remove gfk-socks inbound from panel's xray config if present
        python3 -c "
import json, sys
try:
    with open(sys.argv[1], 'r') as f:
        cfg = json.load(f)
    orig_len = len(cfg.get('inbounds', []))
    cfg['inbounds'] = [i for i in cfg.get('inbounds', []) if i.get('tag') != 'gfk-socks']
    if len(cfg['inbounds']) < orig_len:
        with open(sys.argv[1], 'w') as f:
            json.dump(cfg, f, indent=2)
except: pass
" "$XRAY_CONFIG_FILE" 2>/dev/null
        systemctl restart xray 2>/dev/null || true
    fi

    # Remove ALL paqctl firewall rules (tagged with "paqctl" comment)
    log_info "Removing firewall rules..."
    _remove_all_paqctl_firewall_rules
    # Also try the port-specific removal for backwards compatibility
    _remove_firewall

    # Remove systemd services
    if command -v systemctl &>/dev/null; then
        systemctl stop paqctl.service 2>/dev/null || true
        systemctl disable paqctl.service 2>/dev/null || true
        systemctl stop paqctl-telegram.service 2>/dev/null || true
        systemctl disable paqctl-telegram.service 2>/dev/null || true
        rm -f /etc/systemd/system/paqctl.service
        rm -f /etc/systemd/system/paqctl-telegram.service
        systemctl daemon-reload 2>/dev/null || true
    fi

    # Remove OpenRC/SysVinit
    rm -f /etc/init.d/paqctl 2>/dev/null

    # Remove symlink
    rm -f /usr/local/bin/paqctl

    # Remove install directory
    rm -rf "${INSTALL_DIR:?}"

    echo ""
    log_success "paqctl has been completely uninstalled"
    echo ""
}
#═══════════════════════════════════════════════════════════════════════
# Help
#═══════════════════════════════════════════════════════════════════════

#───────────────────────────────────────────────────────────────────────
# Command registry: the single source for help, aliases, suggestions
# and shell completion.   name;aliases;usage;group;summary
#───────────────────────────────────────────────────────────────────────
_PAQCTL_COMMANDS=(
"menu;;menu;General;Interactive menu (default when no command is given)"
"status;;status [--json];General;Show service status and configuration"
"info;details client;info [--ip ADDR] [--qr] [--json];General;Show connection info and the shareable client string"
"help;--help -h;help [COMMAND];General;Show help, or detailed help for one command"
"version;--version;version;General;Show version info"
"completion;;completion [bash|zsh];General;Print a shell completion script"
"start;;start;Service;Start the active backend(s)"
"stop;;stop;Service;Stop the active backend(s)"
"restart;;restart;Service;Restart the active backend(s)"
"start-paqet;;start-paqet;Service;Start only the paqet backend"
"stop-paqet;;stop-paqet;Service;Stop only the paqet backend"
"start-gfk;;start-gfk;Service;Start only the GFK backend"
"stop-gfk;;stop-gfk;Service;Stop only the GFK backend"
"start-all;;start-all;Service;Start every installed backend"
"stop-all;;stop-all;Service;Stop every installed backend"
"enable;boot-enable;enable;Service;Enable auto-start on boot (systemd, OpenRC, SysVinit)"
"disable;boot-disable;disable;Service;Disable auto-start on boot"
"watchdog;;watchdog [enable|disable|status];Service;Self-healing watchdog that restarts a failed service"
"health;;health [--json];Diagnostics;Run health checks (exits 1 if any check fails)"
"doctor;;doctor [--fix] [--json];Diagnostics;Health checks plus suggested fixes; --fix applies the safe ones"
"test;;test [--url URL];Diagnostics;End-to-end request through the local proxy (run on a client)"
"logs;;logs [-n N] [--no-follow] [--since TIME] [--backend paqet|gfk] [--errors];Diagnostics;View service logs"
"ping;;ping;Diagnostics;Test connectivity with paqet ping"
"dump;;dump;Diagnostics;Capture packets for diagnostics (paqet dump)"
"monitor;top clients;monitor;Diagnostics;Active client monitor"
"speedtest;speed;speedtest;Diagnostics;Server speed and bandwidth test"
"routing;dns check-dns;routing;Diagnostics;DNS leak and proxy routing check"
"config;;config [show [--reveal] | edit | set KEY=VALUE...];Configuration;Change configuration (interactive with no arguments)"
"export;share;export [--ip ADDR] [--qr] [--json];Configuration;Print the shareable client config string"
"import;;import [STRING | -];Configuration;Import a paqet:// or gfk:// string ('-' reads stdin)"
"rotate-key;rotate;rotate-key;Configuration;Rotate the encryption key / auth code and restart"
"secret;;secret;Configuration;Generate a new encryption key (prints it, does not apply it)"
"tune;tuning;tune;Configuration;Performance and KCP profile tuning menu"
"turbo;;turbo;Configuration;Enable kernel turbo mode (BBR, larger socket buffers)"
"turbo-off;;turbo-off;Configuration;Disable kernel turbo mode"
"telegram;;telegram;Configuration;Telegram notification settings"
"firewall;;firewall;Security;Show and manage paqctl's firewall rules"
"ban;;ban <IP[/CIDR]> | ban list;Security;Block an IP or range (IPv4/IPv6, survives restarts)"
"unban;;unban <IP[/CIDR]>;Security;Remove a ban"
"backup;;backup;Maintenance;Back up configuration (keeps the newest 10)"
"restore;;restore [FILE | latest | N];Maintenance;Restore configuration from a backup"
"update;;update;Maintenance;Update the backend binary and the management script"
"self-update;;self-update;Maintenance;Update only the paqctl management script"
"rollback;;rollback;Maintenance;Roll back to a previous paqet version"
"cleanup;clean;cleanup [--journal];Maintenance;Remove paqctl's old logs, temp files and backups"
"uninstall;;uninstall;Maintenance;Remove paqctl completely"
)
_PAQCTL_GROUPS=(General Service Diagnostics Configuration Security Maintenance)

# Canonical command name for a name or alias
_resolve_command() {
    local input="$1" entry name aliases a
    [ -n "$input" ] || return 1
    for entry in "${_PAQCTL_COMMANDS[@]}"; do
        IFS=';' read -r name aliases _ <<< "$entry"
        [ "$input" = "$name" ] && { echo "$name"; return 0; }
        for a in $aliases; do
            [ "$input" = "$a" ] && { echo "$name"; return 0; }
        done
    done
    return 1
}

_command_entry() {
    local want="$1" entry name
    for entry in "${_PAQCTL_COMMANDS[@]}"; do
        IFS=';' read -r name _ <<< "$entry"
        [ "$name" = "$want" ] && { echo "$entry"; return 0; }
    done
    return 1
}

# Every name and alias (used by completion)
_command_words() {
    local entry name aliases
    for entry in "${_PAQCTL_COMMANDS[@]}"; do
        IFS=';' read -r name aliases _ <<< "$entry"
        echo "$name"
        local a
        for a in $aliases; do
            [[ "$a" == -* ]] || echo "$a"
        done
    done
}

_command_names() {
    local entry name
    for entry in "${_PAQCTL_COMMANDS[@]}"; do
        IFS=';' read -r name _ <<< "$entry"
        echo "$name"
    done
}

_levenshtein() {
    local a="$1" b="$2" i j cost la=${#1} lb=${#2} del ins sub m
    local -a prev cur
    for ((j = 0; j <= lb; j++)); do prev[j]=$j; done
    for ((i = 1; i <= la; i++)); do
        cur=([0]=$i)
        for ((j = 1; j <= lb; j++)); do
            if [ "${a:i-1:1}" = "${b:j-1:1}" ]; then cost=0; else cost=1; fi
            del=$((prev[j] + 1)); ins=$((cur[j-1] + 1)); sub=$((prev[j-1] + cost))
            m=$del
            [ "$ins" -lt "$m" ] && m=$ins
            [ "$sub" -lt "$m" ] && m=$sub
            cur[j]=$m
        done
        prev=("${cur[@]}")
    done
    echo "${prev[lb]}"
}

# Closest command to a typo (prefix match first, then edit distance <= 2)
_suggest_command() {
    local input="$1" w best="" best_d=99 d
    [ -n "$input" ] || return 1
    local -a prefix_hits=()
    while IFS= read -r w; do
        [[ "$w" == "$input"* ]] && prefix_hits+=("$w")
    done < <(_command_words)
    if [ ${#prefix_hits[@]} -eq 1 ]; then
        _resolve_command "${prefix_hits[0]}"
        return 0
    fi
    while IFS= read -r w; do
        d=$(_levenshtein "$input" "$w")
        if [ "$d" -lt "$best_d" ]; then best_d=$d; best=$w; fi
    done < <(_command_words)
    if [ -n "$best" ] && [ "$best_d" -le 2 ] && [ "$best_d" -lt ${#input} ]; then
        _resolve_command "$best"
        return 0
    fi
    return 1
}

# Longer help text and examples for 'paqctl help <command>'
_command_details() {
    case "$1" in
        status)  echo "  Exit code is 0 whether or not the service runs; use --json and read \"running\"." ;;
        logs)    cat << 'EOF'
  Options:
    -n, --lines N      Number of lines to show (default 50)
    --no-follow        Print and exit (default when output is not a terminal)
    -f, --follow       Keep following new lines
    --since TIME       Only entries since TIME (systemd journal only), e.g. "1 hour ago"
    --backend NAME     paqet or gfk: read that backend's own log file if it has one
    --errors           Only lines that look like errors or warnings
  Examples:
    paqctl logs -n 200 --no-follow --errors
    paqctl logs --since "30 min ago"
EOF
            ;;
        health)  echo "  Exit code: 0 when every check passes, 1 when any check fails." ;;
        doctor)  cat << 'EOF'
  Runs the health checks plus extra ones (interface/IP/gateway drift, MTU,
  port conflicts, config/settings mismatch, disk, DNS) and prints a fix for
  each problem. --fix applies the safe fixes: re-adding firewall rules,
  regenerating config.yaml from settings.conf, starting the service and
  enabling auto-start. Exit code is 1 while any check still fails.
EOF
            ;;
        test)    cat << 'EOF'
  On a client, fetches a URL through the local SOCKS5 proxy and reports the
  exit IP, location, HTTP status and timing. Warns when the exit IP equals
  this machine's direct IP. In forward mode it checks the forward port.
  Default URL: https://www.cloudflare.com/cdn-cgi/trace
EOF
            ;;
        config)  cat << 'EOF'
  config                 Interactive wizard (needs a terminal)
  config show [--reveal] Print settings.conf (secrets masked unless --reveal; --json supported)
  config edit            Open config.yaml (or GFK parameters.py) in $EDITOR, validate, restart
  config set KEY=VALUE   Change settings, regenerate config and restart if running
  Settable keys:
    LISTEN_PORT SOCKS_PORT FORWARD_PORT REMOTE_SERVER FORWARD_TARGET INTERFACE
    LOCAL_IP GATEWAY_MAC ENCRYPTION_KEY PAQET_TCP_LOCAL_FLAG PAQET_TCP_REMOTE_FLAG
    ROUTING_MODE KCP_MODE KCP_MTU KCP_CONN KCP_SNDWND KCP_RCVWND GFK_SERVER_IP GFK_AUTH_CODE
    TELEGRAM_SERVER_LABEL EGRESS_GUARD EGRESS_ALLOW
  Examples:
    paqctl config set LISTEN_PORT=9443
    paqctl config set KCP_MTU=1200 SOCKS_PORT=1081
    paqctl config set KCP_MODE=fast2      (normal, fast, fast2, fast3 or manual)
  Egress guard (server): clients cannot reach this host's loopback, private
  networks or cloud metadata (169.254.169.254). Allow specific targets, e.g.
  for a client in forward mode whose target is a service on this server:
    paqctl config set EGRESS_ALLOW="127.0.0.1:80"
    paqctl config set EGRESS_ALLOW="127.0.0.1:8080, 10.0.0.0/8, [fd00::5]:443"
    paqctl config set EGRESS_GUARD=false  (not recommended)
  Egress changes apply immediately, without a restart.
EOF
            ;;
        export)  cat << 'EOF'
  The string contains your encryption key / auth code: share it privately.
  --ip ADDR   Address clients should use (default: configured IP; looks up the
              public IP via api.ipify.org only if nothing is configured)
  --qr        Also print a QR code (needs qrencode)
EOF
            ;;
        import)  cat << 'EOF'
  paqctl import 'paqet://...'     Import from an argument
  paqctl import - < string.txt    Read the string from stdin
  paqctl import                   Prompt for it
  The current configuration is backed up first; every field is validated.
EOF
            ;;
        rotate-key) echo "  Backs up the current config, generates a new secret, restarts the service and prints the new client string. Use -y to skip the confirmation." ;;
        ban)     cat << 'EOF'
  Bans are tagged "paqctl-ban", recorded in /opt/paqctl/banned_ips and
  re-applied whenever the service starts, so they survive restarts and reboots.
  Examples:
    paqctl ban 203.0.113.7
    paqctl ban 198.51.100.0/24
    paqctl ban 2001:db8::/32
    paqctl ban list            (add --json for machine-readable output)
EOF
            ;;
        restore) echo "  'latest' picks the newest backup, N picks the Nth newest. The current config is backed up first." ;;
        cleanup) echo "  Removes archived paqctl logs, stale temp files and old backups. --journal also vacuums the system-wide journal (all services) to 7 days." ;;
        watchdog) echo "  With no argument shows status. 'watchdog check' is what the timer runs; it skips if another paqctl command is in progress." ;;
        update)  echo "  Updates the paqet binary (or GFK scripts) and then the management script. Use -y to update without prompting." ;;
        completion) cat << 'EOF'
  bash:  paqctl completion bash | sudo tee /etc/bash_completion.d/paqctl
  zsh:   paqctl completion zsh  > "${fpath[1]}/_paqctl"
  (The installer sets up bash completion automatically.)
EOF
            ;;
    esac
}

show_help() {
    local topic="${1:-}"
    if [ -n "$topic" ]; then
        _show_command_help "$topic"
        return
    fi
    echo ""
    echo -e "${BOLD}paqctl${NC} - Paqet Manager v${VERSION}"
    echo ""
    echo -e "${BOLD}Usage:${NC} sudo paqctl <command> [options]"
    echo ""
    local group entry name aliases usage g summary
    for group in "${_PAQCTL_GROUPS[@]}"; do
        echo -e "${BOLD}${group}:${NC}"
        for entry in "${_PAQCTL_COMMANDS[@]}"; do
            IFS=';' read -r name aliases usage g summary <<< "$entry"
            [ "$g" = "$group" ] || continue
            printf "  %-13s %s\n" "$name" "$summary"
        done
        echo ""
    done
    echo -e "${BOLD}Global options:${NC}"
    echo "  -y, --yes     Answer yes to confirmation prompts (for scripts)"
    echo "  --json        Machine-readable output (status, info, health, doctor, export, config show, ban list)"
    echo "  --no-color    Disable colours (also NO_COLOR=1, or when output is not a terminal)"
    echo ""
    echo "Run 'paqctl help <command>' for options, aliases and examples."
    echo ""
    echo -e "${BOLD}Paqet:${NC} https://github.com/SamNet-dev/paqctl"
    echo ""
}

_show_command_help() {
    local cmd entry name aliases usage group summary
    if ! cmd=$(_resolve_command "$1"); then
        echo -e "${RED}Unknown command: $1${NC}" >&2
        local guess
        guess=$(_suggest_command "$1") && echo -e "Did you mean: ${BOLD}paqctl help ${guess}${NC} ?" >&2
        return 2
    fi
    entry=$(_command_entry "$cmd")
    IFS=';' read -r name aliases usage group summary <<< "$entry"
    echo ""
    echo -e "${BOLD}paqctl ${name}${NC} - ${summary}"
    echo ""
    echo -e "${BOLD}Usage:${NC} sudo paqctl ${usage}"
    [ -n "$aliases" ] && echo -e "${BOLD}Aliases:${NC} ${aliases}"
    local details
    details=$(_command_details "$name")
    if [ -n "$details" ]; then
        echo ""
        echo "$details"
    fi
    echo ""
}

_completion_bash() {
    local words names
    words=$(_command_words | tr '\n' ' ')
    names=$(_command_names | tr '\n' ' ')
    cat << EOF
# bash completion for paqctl (generated by paqctl ${VERSION})
_paqctl() {
    local cur prev sub i
    cur="\${COMP_WORDS[COMP_CWORD]}"
    prev="\${COMP_WORDS[COMP_CWORD-1]}"
    sub=""
    for ((i = 1; i < COMP_CWORD; i++)); do
        case "\${COMP_WORDS[i]}" in
            -y|--yes|--json|--no-color) ;;
            *) sub="\${COMP_WORDS[i]}"; break ;;
        esac
    done
    if [ -z "\$sub" ]; then
        COMPREPLY=( \$(compgen -W "${words}-y --yes --json --no-color" -- "\$cur") )
        return 0
    fi
    case "\$sub" in
        help) COMPREPLY=( \$(compgen -W "${names}" -- "\$cur") ) ;;
        watchdog) COMPREPLY=( \$(compgen -W "enable disable status" -- "\$cur") ) ;;
        logs)
            case "\$prev" in
                --backend) COMPREPLY=( \$(compgen -W "paqet gfk" -- "\$cur") ) ;;
                -n|--lines|--since) COMPREPLY=() ;;
                *) COMPREPLY=( \$(compgen -W "-n --no-follow --follow --since --backend --errors" -- "\$cur") ) ;;
            esac ;;
        config)
            if [ "\$prev" = "set" ] || [[ "\$cur" == *=* ]]; then
                COMPREPLY=( \$(compgen -W "LISTEN_PORT= SOCKS_PORT= FORWARD_PORT= REMOTE_SERVER= FORWARD_TARGET= INTERFACE= LOCAL_IP= GATEWAY_MAC= ENCRYPTION_KEY= PAQET_TCP_LOCAL_FLAG= PAQET_TCP_REMOTE_FLAG= ROUTING_MODE= KCP_MODE= KCP_MTU= KCP_CONN= KCP_SNDWND= KCP_RCVWND= GFK_SERVER_IP= GFK_AUTH_CODE= TELEGRAM_SERVER_LABEL= EGRESS_GUARD= EGRESS_ALLOW=" -- "\$cur") )
                compopt -o nospace 2>/dev/null
            else
                COMPREPLY=( \$(compgen -W "show edit set --reveal" -- "\$cur") )
            fi ;;
        ban) COMPREPLY=( \$(compgen -W "list" -- "\$cur") ) ;;
        restore) COMPREPLY=( \$(compgen -W "latest" -- "\$cur") \$(compgen -f -- "\$cur") ) ;;
        export|share|info|details|client)
            COMPREPLY=( \$(compgen -W "--ip --qr --json" -- "\$cur") ) ;;
        status|health) COMPREPLY=( \$(compgen -W "--json" -- "\$cur") ) ;;
        doctor) COMPREPLY=( \$(compgen -W "--fix --json" -- "\$cur") ) ;;
        cleanup|clean) COMPREPLY=( \$(compgen -W "--journal" -- "\$cur") ) ;;
        test) COMPREPLY=( \$(compgen -W "--url" -- "\$cur") ) ;;
        completion) COMPREPLY=( \$(compgen -W "bash zsh" -- "\$cur") ) ;;
        *) COMPREPLY=() ;;
    esac
}
complete -F _paqctl paqctl
EOF
}

show_completion() {
    case "${1:-bash}" in
        bash) _completion_bash ;;
        zsh)
            echo "#compdef paqctl"
            echo "autoload -U +X bashcompinit && bashcompinit"
            _completion_bash
            ;;
        *) log_error "Unsupported shell: $1 (use bash or zsh)"; return 2 ;;
    esac
}

#───────────────────────────────────────────────────────────────────────
# config show / edit / set
#───────────────────────────────────────────────────────────────────────
_SECRET_KEYS=" ENCRYPTION_KEY GFK_AUTH_CODE TELEGRAM_BOT_TOKEN "
_CONFIG_SET_KEYS="LISTEN_PORT SOCKS_PORT FORWARD_PORT REMOTE_SERVER FORWARD_TARGET INTERFACE LOCAL_IP GATEWAY_MAC ENCRYPTION_KEY PAQET_TCP_LOCAL_FLAG PAQET_TCP_REMOTE_FLAG ROUTING_MODE KCP_MODE KCP_MTU KCP_CONN KCP_SNDWND KCP_RCVWND GFK_SERVER_IP GFK_AUTH_CODE TELEGRAM_SERVER_LABEL EGRESS_GUARD EGRESS_ALLOW"

_mask_secret() {
    local s="$1"
    if [ ${#s} -le 8 ]; then printf '****'; else printf '%s****%s' "${s:0:4}" "${s: -2}"; fi
}

config_command() {
    case "${1:-}" in
        "")   change_config ;;
        show) shift; config_show "$@" ;;
        edit) shift; config_edit "$@" ;;
        set)  shift; config_set "$@" ;;
        *)
            log_error "Unknown config subcommand: $1"
            echo "  Usage: paqctl config [show [--reveal] | edit | set KEY=VALUE...]" >&2
            return 2
            ;;
    esac
}

config_show() {
    local reveal=false a
    for a in "$@"; do
        case "$a" in
            --reveal) reveal=true ;;
            *) log_error "Unknown option for config show: $a"; return 2 ;;
        esac
    done
    if [ ! -r "$INSTALL_DIR/settings.conf" ]; then
        log_error "No settings found at $INSTALL_DIR/settings.conf"
        return 1
    fi
    local k v first=true
    if [ "$JSON_OUTPUT" = true ]; then
        printf '{'
    else
        _print_section "CONFIGURATION (settings.conf)"
    fi
    while IFS='=' read -r k v; do
        [[ "$k" =~ ^[A-Z_][A-Z0-9_]*$ ]] || continue
        v="${v#\"}"; v="${v%\"}"
        if [[ "$_SECRET_KEYS" == *" $k "* ]] && [ "$reveal" != true ] && [ -n "$v" ]; then
            v=$(_mask_secret "$v")
        fi
        if [ "$JSON_OUTPUT" = true ]; then
            [ "$first" = true ] || printf ','
            first=false
            printf '%s:%s' "$(_json_str "$k")" "$(_json_str "$v")"
        else
            printf "  %-26s %s\n" "$k" "$v"
        fi
    done < "$INSTALL_DIR/settings.conf"
    if [ "$JSON_OUTPUT" = true ]; then
        printf '}\n'
    else
        echo ""
        [ "$reveal" = true ] || echo -e "  ${DIM}Secrets are masked; add --reveal to show them.${NC}"
        echo -e "  ${DIM}Change values with: sudo paqctl config set KEY=VALUE${NC}"
        echo ""
    fi
}

# _config_validate KEY VALUE -> 0 valid, 1 invalid, 3 unknown key
_config_validate() {
    local k="$1" v="$2"
    case "$k" in
        LISTEN_PORT|SOCKS_PORT|FORWARD_PORT) _validate_port "$v" ;;
        REMOTE_SERVER|FORWARD_TARGET) _valid_hostport "$v" ;;
        INTERFACE) _validate_iface "$v" ;;
        LOCAL_IP) _validate_ip "$v" ;;
        GATEWAY_MAC) _validate_mac "$v" ;;
        ENCRYPTION_KEY) [[ "$v" =~ ^[A-Za-z0-9+/=_-]{8,128}$ ]] ;;
        PAQET_TCP_LOCAL_FLAG|PAQET_TCP_REMOTE_FLAG) [[ "$v" =~ ^[FSRPAUEC]+(,[FSRPAUEC]+)*$ ]] ;;
        ROUTING_MODE) [ "$v" = "socks5" ] || [ "$v" = "forward" ] ;;
        KCP_MTU) [[ "$v" =~ ^[0-9]+$ ]] && [ "$v" -ge 500 ] && [ "$v" -le 9000 ] ;;
        KCP_MODE) [[ "$v" =~ ^(normal|fast|fast2|fast3|manual)$ ]] ;;
        KCP_CONN) [[ "$v" =~ ^[0-9]+$ ]] && [ "$v" -ge 1 ] && [ "$v" -le 64 ] ;;
        KCP_SNDWND|KCP_RCVWND) [[ "$v" =~ ^[0-9]+$ ]] && [ "$v" -ge 16 ] && [ "$v" -le 65535 ] ;;
        GFK_SERVER_IP) _validate_ip "$v" ;;   # GFK sends raw packets to it: IPv4 only
        GFK_AUTH_CODE) [[ "$v" =~ ^[A-Za-z0-9_-]{4,128}$ ]] ;;
        TELEGRAM_SERVER_LABEL) [[ "$v" =~ ^[A-Za-z0-9\ ._-]{1,64}$ ]] ;;
        EGRESS_GUARD) [ "$v" = true ] || [ "$v" = false ] ;;
        EGRESS_ALLOW) [ ${#v} -le 1024 ] && _egress_valid_allow "$v" ;;
        *) return 3 ;;
    esac
}

config_set() {
    if [ $# -eq 0 ]; then
        log_error "Usage: paqctl config set KEY=VALUE [KEY=VALUE...]   (see: paqctl help config)"
        return 2
    fi
    local -a keys=() vals=()
    local pair k v rc
    for pair in "$@"; do
        if [[ "$pair" != *=* ]]; then
            log_error "Expected KEY=VALUE, got: $pair"
            return 2
        fi
        k="${pair%%=*}"; v="${pair#*=}"
        k="${k^^}"
        rc=0
        _config_validate "$k" "$v" || rc=$?
        if [ "$rc" -eq 3 ]; then
            log_error "Unknown or read-only setting: $k"
            echo "  Settable keys: $_CONFIG_SET_KEYS" >&2
            return 2
        elif [ "$rc" -ne 0 ]; then
            log_error "Invalid value for $k: $v"
            return 2
        fi
        keys+=("$k"); vals+=("$v")
    done

    local needs_restart=false touches_paqet=false touches_gfk=false touches_egress=false i
    for k in "${keys[@]}"; do
        case "$k" in
            TELEGRAM_SERVER_LABEL) ;;
            EGRESS_*) touches_egress=true ;;
            GFK_*) touches_gfk=true; needs_restart=true ;;
            *) touches_paqet=true; needs_restart=true ;;
        esac
    done

    local bk
    bk=$(backup_config --quiet --label pre-config 2>/dev/null) && log_info "Previous configuration backed up to: $bk"

    local was_running=false
    if [ "$needs_restart" = true ] && is_running; then
        was_running=true
        # Stop first so firewall rules for the old port are removed
        stop_paqet
    fi

    local old shown_old shown_new
    for ((i = 0; i < ${#keys[@]}; i++)); do
        k="${keys[$i]}"; v="${vals[$i]}"
        old="${!k:-}"
        printf -v "$k" '%s' "$v"
        shown_old="$old"; shown_new="$v"
        if [[ "$_SECRET_KEYS" == *" $k "* ]]; then
            shown_old=$(_mask_secret "$old"); shown_new=$(_mask_secret "$v")
        fi
        log_info "${k}: ${shown_old:-<empty>} → ${shown_new}"
    done

    local result=0
    if ! save_settings; then
        log_error "Failed to save settings"
        result=1
    fi
    if [ "$result" -eq 0 ] && [ "$touches_paqet" = true ] && _paqet_installed; then
        _write_paqet_config || result=1
    fi
    if [ "$result" -eq 0 ] && [ "$touches_gfk" = true ] && _gfk_installed; then
        generate_gfk_config || result=1
    fi
    [ "$result" -eq 0 ] && log_success "Configuration updated"

    # The egress guard is rebuilt in place (start_paqet below rebuilds it anyway)
    if [ "$result" -eq 0 ] && [ "$touches_egress" = true ] && [ "$was_running" != true ] && [ "$ROLE" = "server" ]; then
        local eg_rc=0
        _egress_guard_apply || eg_rc=$?
        case "$eg_rc" in
            0) if _egress_guard_wanted; then log_success "Egress guard updated"; else log_warn "Egress guard removed: clients can reach this host's private networks"; fi ;;
            2) log_info "Egress guard will be installed when paqet starts." ;;
            *) log_error "Could not update the egress guard"; result=1 ;;
        esac
    fi

    if [ "$was_running" = true ]; then
        start_paqet || result=1
    elif [ "$needs_restart" = true ]; then
        log_info "Service is not running; changes apply on next start."
    fi
    return $result
}

config_edit() {
    local file kind
    if [ "$BACKEND" = "gfw-knocker" ]; then
        file="$GFK_DIR/parameters.py"; kind="python"
    else
        file="$INSTALL_DIR/config.yaml"; kind="yaml"
    fi
    if [ ! -f "$file" ]; then
        log_error "$file does not exist. Create it with: sudo paqctl config"
        return 1
    fi
    if ! _has_tty; then
        log_error "config edit needs a terminal. Use 'paqctl config set KEY=VALUE' in scripts."
        return 1
    fi
    local editor="${VISUAL:-${EDITOR:-}}" e
    if [ -z "$editor" ]; then
        for e in nano vim vi; do
            command -v "$e" &>/dev/null && { editor="$e"; break; }
        done
    fi
    [ -n "$editor" ] || { log_error "No editor found. Set EDITOR, e.g.: sudo EDITOR=nano paqctl config edit"; return 1; }

    local tmp
    tmp=$(mktemp "${file}.XXXXXXXX") || { log_error "Failed to create temp file"; return 1; }
    chmod 600 "$tmp"
    cp -p "$file" "$tmp"
    # shellcheck disable=SC2086
    $editor "$tmp" < /dev/tty > /dev/tty
    if cmp -s "$file" "$tmp"; then
        rm -f "$tmp"
        log_info "No changes made"
        return 0
    fi

    local valid=true
    if [ "$kind" = "yaml" ]; then
        if command -v python3 &>/dev/null && python3 -c 'import yaml' 2>/dev/null; then
            python3 -c 'import sys, yaml; yaml.safe_load(open(sys.argv[1]))' "$tmp" 2>/dev/null || valid=false
        fi
        grep -qE '^role:[[:space:]]*"?(server|client)"?' "$tmp" || valid=false
    else
        if command -v python3 &>/dev/null; then
            python3 -c 'import ast, sys; ast.parse(open(sys.argv[1]).read())' "$tmp" 2>/dev/null || valid=false
        fi
    fi
    if [ "$valid" != true ]; then
        log_error "The edited file does not look valid; nothing was changed."
        log_error "Your edited copy is kept at: $tmp"
        return 1
    fi

    local bk
    bk=$(backup_config --quiet --label pre-edit 2>/dev/null) && log_info "Previous configuration backed up to: $bk"
    mv -f "$tmp" "$file" && chmod 600 "$file"
    log_success "Saved $file"
    echo -e "  ${DIM}Note: 'config', 'config set', 'tune', 'import' and 'rotate-key' regenerate this file from settings.conf and overwrite manual edits.${NC}"
    if is_running && _confirm "Restart now to apply the changes?"; then
        restart_paqet
    fi
}

#───────────────────────────────────────────────────────────────────────
# End-to-end test through the tunnel (client side)
#───────────────────────────────────────────────────────────────────────
run_e2e_test() {
    local url="https://www.cloudflare.com/cdn-cgi/trace"
    while [ $# -gt 0 ]; do
        case "$1" in
            --url) [ -n "${2:-}" ] || { log_error "--url needs a value"; return 2; }; url="$2"; shift 2 ;;
            --url=*) url="${1#--url=}"; shift ;;
            *) log_error "Unknown option for test: $1"; echo "  Usage: paqctl test [--url URL]" >&2; return 2 ;;
        esac
    done
    [[ "$url" =~ ^https?:// ]] || { log_error "URL must start with http:// or https://"; return 2; }
    command -v curl &>/dev/null || { log_error "curl is required"; return 1; }
    _print_section "END-TO-END TEST"

    if [ "$ROLE" = "server" ]; then
        log_info "This machine is a server; run 'paqctl test' on a client to test the tunnel."
        log_info "Checking this server's own outbound connectivity instead..."
        local direct pub_ip
        if direct=$(curl -s --max-time 10 "$url"); then
            pub_ip=$(echo "$direct" | sed -n 's/^ip=//p' | head -1)
            log_success "Outbound HTTPS works${pub_ip:+ (public IP: $pub_ip)}"
            return 0
        fi
        log_error "Could not reach $url from this server"
        return 1
    fi

    if ! is_running; then
        log_error "paqctl is not running. Start it with: sudo paqctl start"
        return 1
    fi

    local port
    if [ "$BACKEND" = "gfw-knocker" ]; then
        port=$(_gfk_client_socks_port)
    elif [ "${ROUTING_MODE:-socks5}" = "forward" ]; then
        local fport="${FORWARD_PORT:-14000}"
        log_info "Forward mode: checking that 127.0.0.1:${fport} accepts connections..."
        if timeout 5 bash -c "exec 3<>/dev/tcp/127.0.0.1/${fport}" 2>/dev/null; then
            log_success "Forward port ${fport} accepts connections (target: ${FORWARD_TARGET:-127.0.0.1:80})"
            return 0
        fi
        log_error "Nothing is accepting connections on 127.0.0.1:${fport}"
        return 1
    else
        port="${SOCKS_PORT:-1080}"
    fi

    log_info "Fetching $url through SOCKS5 127.0.0.1:${port}..."
    local out rc=0
    out=$(curl -s --max-time 20 --socks5-hostname "127.0.0.1:${port}" \
        -w $'\n__PAQCTL__ %{http_code} %{time_connect} %{time_total}' "$url" 2>&1) || rc=$?
    if [ "$rc" -ne 0 ]; then
        log_error "Request through the tunnel failed (curl exit code $rc)"
        echo -e "  ${DIM}Next steps: sudo paqctl doctor   |   sudo paqctl logs --errors --no-follow${NC}"
        return 1
    fi
    local meta body code total exit_ip loc
    meta=$(echo "$out" | grep '^__PAQCTL__' | tail -1)
    body=$(echo "$out" | grep -v '^__PAQCTL__')
    code=$(echo "$meta" | awk '{print $2}')
    total=$(echo "$meta" | awk '{print $4}')
    exit_ip=$(echo "$body" | sed -n 's/^ip=//p' | head -1)
    loc=$(echo "$body" | sed -n 's/^loc=//p' | head -1)

    if ! [[ "$code" =~ ^[23] ]]; then
        log_error "Tunnel reached the site but got HTTP ${code:-?}"
        return 1
    fi
    log_success "Tunnel works: HTTP ${code} in ${total}s"
    [ -n "$exit_ip" ] && echo -e "  Exit IP:   ${BOLD}${exit_ip}${NC}${loc:+ (${loc})}"

    if [ -n "$exit_ip" ]; then
        local direct_ip
        direct_ip=$(curl -s --max-time 5 "$url" 2>/dev/null | sed -n 's/^ip=//p' | head -1)
        if [ -n "$direct_ip" ] && [ "$direct_ip" = "$exit_ip" ]; then
            log_warn "The exit IP equals this machine's direct IP - traffic may not be going through the tunnel."
        elif [ -n "$direct_ip" ]; then
            echo -e "  Direct IP: ${direct_ip} ${DIM}(different from the exit IP, as expected)${NC}"
        fi
    fi
    echo ""
}

#───────────────────────────────────────────────────────────────────────
# Start/stop every installed backend, reporting partial failures
#───────────────────────────────────────────────────────────────────────
_start_all() {
    local -a failed=()
    local any=false
    if _paqet_installed; then any=true; start_paqet_backend || failed+=(paqet); fi
    if _gfk_installed; then any=true; start_gfk_backend || failed+=(gfk); fi
    if [ "$any" != true ]; then
        log_error "No backends are installed"
        return 1
    fi
    if [ ${#failed[@]} -gt 0 ]; then
        log_error "Failed to start: ${failed[*]}"
        return 1
    fi
}

_stop_all() {
    local -a failed=()
    if _paqet_installed; then stop_paqet_backend || failed+=(paqet); fi
    if _gfk_installed; then stop_gfk_backend || failed+=(gfk); fi
    if [ ${#failed[@]} -gt 0 ]; then
        log_error "Failed to stop: ${failed[*]}"
        return 1
    fi
}

show_version() {
    echo ""
    echo -e "  paqctl version:  ${BOLD}${VERSION}${NC}"
    if [ "$BACKEND" = "gfw-knocker" ]; then
        echo -e "  backend:         ${BOLD}gfw-knocker${NC}"
        local py_ver; py_ver=$(python3 --version 2>/dev/null || echo "unknown")
        echo -e "  python:          ${BOLD}${py_ver}${NC}"
    else
        echo -e "  paqet version:   ${BOLD}${PAQET_VERSION}${NC}"
        local bin_ver
        bin_ver=$("$INSTALL_DIR/bin/paqet" version 2>/dev/null || echo "unknown")
        echo -e "  paqet binary:    ${BOLD}${bin_ver}${NC}"
        if echo "$PAQET_VERSION" | grep -qi "alpha\|beta\|rc"; then
            echo ""
            echo -e "  ${YELLOW}Note: paqet is in alpha phase — expect breaking changes between versions.${NC}"
        fi
    fi
    echo ""
    echo -e "  ${DIM}paqctl by SamNet-dev: https://github.com/SamNet-dev/paqctl${NC}"
    echo ""
}
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
#═══════════════════════════════════════════════════════════════════════
# CLI Command Router
#═══════════════════════════════════════════════════════════════════════

_main() {
    local input="${1:-menu}" cmd
    case "$input" in
        # Internal hooks used by the service units
        _apply-firewall)  _require_root || return 1; _apply_firewall; return ;;
        _remove-firewall) _require_root || return 1; _remove_firewall; return ;;
        # Hidden: list command words (completion/tests)
        commands) _command_words; return 0 ;;
    esac

    if ! cmd=$(_resolve_command "$input"); then
        echo -e "${RED}Unknown command: ${input}${NC}" >&2
        local guess
        if guess=$(_suggest_command "$input"); then
            echo -e "Did you mean: ${BOLD}paqctl ${guess}${NC} ?" >&2
        fi
        echo "Run 'paqctl help' for the list of commands." >&2
        return 2
    fi
    [ $# -gt 0 ] && shift

    case "$cmd" in
        help|version|completion) ;;
        *) _require_root || return 1 ;;
    esac

    # Serialise commands that change state (the watchdog skips instead of waiting)
    case "$cmd" in
        start|stop|restart|start-paqet|stop-paqet|start-gfk|stop-gfk|start-all|stop-all|\
        update|self-update|rollback|import|rotate-key|restore|ban|unban|turbo|turbo-off|\
        tune|cleanup|uninstall|enable|disable)
            _acquire_lock || return 1 ;;
        config)
            [ "${1:-}" = "show" ] || { _acquire_lock || return 1; } ;;
        watchdog)
            case "${1:-status}" in
                check) _acquire_lock nowait || return 0 ;;
                enable|disable) _acquire_lock || return 1 ;;
            esac ;;
        doctor)
            case " $* " in *" --fix "*) _acquire_lock || return 1 ;; esac ;;
    esac

    case "$cmd" in
        menu)        show_menu ;;
        status)      show_status ;;
        info)        show_connection_info "$@" ;;
        help)        show_help "$@" ;;
        version)     show_version ;;
        completion)  show_completion "$@" ;;
        start)       start_paqet ;;
        stop)        stop_paqet ;;
        restart)     restart_paqet ;;
        start-paqet) start_paqet_backend ;;
        stop-paqet)  stop_paqet_backend ;;
        start-gfk)   start_gfk_backend ;;
        stop-gfk)    stop_gfk_backend ;;
        start-all)   _start_all ;;
        stop-all)    _stop_all ;;
        enable)      _set_boot enable ;;
        disable)     _set_boot disable ;;
        watchdog)
            case "${1:-status}" in
                enable|disable|status|check) manage_watchdog "${1:-status}" ;;
                *) log_error "Usage: paqctl watchdog [enable|disable|status]"; return 2 ;;
            esac ;;
        health)      health_check ;;
        doctor)      run_doctor "$@" ;;
        test)        run_e2e_test "$@" ;;
        logs)        show_logs "$@" ;;
        ping)        run_ping ;;
        dump)        run_dump ;;
        monitor)     show_active_clients ;;
        speedtest)   run_speedtest ;;
        routing)     check_proxy_routing ;;
        config)      config_command "$@" ;;
        export)      export_config_string "$@" ;;
        import)      import_config_string "$@" ;;
        rotate-key)  rotate_key ;;
        secret)      generate_secret ;;
        tune)        tune_menu ;;
        turbo)       apply_turbo_mode ;;
        turbo-off)   remove_turbo_mode ;;
        telegram)    show_telegram_menu ;;
        firewall)    show_firewall ;;
        ban)         manage_ip_ban ban "${1:-}" ;;
        unban)       manage_ip_ban unban "${1:-}" ;;
        backup)      backup_config "$@" ;;
        restore)     restore_config "$@" ;;
        update)      update_paqet ;;
        self-update) update_management_script ;;
        rollback)    rollback_paqet ;;
        cleanup)     system_cleanup "$@" ;;
        uninstall)   uninstall_paqctl ;;
        *)
            # A registry entry without a handler is a bug
            log_error "Command '$cmd' is registered but not implemented"
            return 70
            ;;
    esac
}

# Tests source this file with PAQCTL_SOURCE_ONLY=1 to reach the functions
if [ "${PAQCTL_SOURCE_ONLY:-}" != "1" ]; then
    _main "$@"
    exit $?
fi
MANAGEMENT

    # Replace placeholder
    sed "s#REPLACE_ME_INSTALL_DIR#$INSTALL_DIR#g" "$tmp_script" > "$tmp_script.sed" && mv "$tmp_script.sed" "$tmp_script"

    if ! chmod +x "$tmp_script"; then
        log_error "Failed to make management script executable"
        rm -f "$tmp_script"
        return 1
    fi
    if ! mv -f "$tmp_script" "$INSTALL_DIR/paqctl"; then
        log_error "Failed to install management script"
        rm -f "$tmp_script"
        return 1
    fi

    # Create symlink
    rm -f /usr/local/bin/paqctl 2>/dev/null
    if ! ln -sf "$INSTALL_DIR/paqctl" /usr/local/bin/paqctl; then
        log_warn "Failed to create symlink /usr/local/bin/paqctl"
    fi

    # Bash completion (generated from the management script's command table)
    local _comp_dir=""
    if [ -d /usr/share/bash-completion/completions ]; then
        _comp_dir=/usr/share/bash-completion/completions
    elif [ -d /etc/bash_completion.d ]; then
        _comp_dir=/etc/bash_completion.d
    fi
    if [ -n "$_comp_dir" ]; then
        if "$INSTALL_DIR/paqctl" completion bash > "$_comp_dir/paqctl.tmp" 2>/dev/null && [ -s "$_comp_dir/paqctl.tmp" ]; then
            mv -f "$_comp_dir/paqctl.tmp" "$_comp_dir/paqctl"
            chmod 644 "$_comp_dir/paqctl" 2>/dev/null || true
        else
            rm -f "$_comp_dir/paqctl.tmp" 2>/dev/null
        fi
    fi

    log_success "Management script installed → /usr/local/bin/paqctl"
}
#═══════════════════════════════════════════════════════════════════════
# Main Installation Flow
#═══════════════════════════════════════════════════════════════════════

# Handle --update-components flag (called during self-update)
if [ "${1:-}" = "--update-components" ]; then
    INSTALL_DIR="${INSTALL_DIR:-/opt/paqctl}"
    _load_settings
    create_management_script
    # Bring firewall rules up to date for the running service (e.g. install
    # the egress guard after an upgrade) without restarting it
    if [ "${ROLE:-}" = "server" ] && command -v systemctl &>/dev/null && \
       systemctl is-active --quiet paqctl.service 2>/dev/null; then
        /usr/local/bin/paqctl _apply-firewall >/dev/null 2>&1 || true
    fi
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
            KCP_NODELAY KCP_INTERVAL KCP_RESEND KCP_NOCONGESTION KCP_SOCKBUF KCP_SMUXBUF \
            EGRESS_GUARD EGRESS_ALLOW
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
