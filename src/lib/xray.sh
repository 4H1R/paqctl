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
