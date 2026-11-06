#!/bin/bash
#
# paqctl - Paqet Manager
# https://github.com/SamNet-dev/paqctl
#

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

INSTALL_DIR="REPLACE_ME_INSTALL_DIR"
#@include lib/constants.sh

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

#@include lib/common.sh
#@include lib/egress.sh
#@include lib/backends.sh
#@include lib/xray.sh

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
