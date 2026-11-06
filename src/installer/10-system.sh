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
