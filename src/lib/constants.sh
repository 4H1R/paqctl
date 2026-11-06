# shellcheck shell=bash
# Versions, repositories and colours shared by the installer and the management script.
# INSTALL_DIR must be set before this file is included.

VERSION="1.2.0"

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
