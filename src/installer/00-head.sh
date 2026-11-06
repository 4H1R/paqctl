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
#@include lib/constants.sh
#@include lib/common.sh
#@include lib/egress.sh
#@include lib/backends.sh
#@include lib/xray.sh
