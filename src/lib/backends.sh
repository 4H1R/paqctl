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
