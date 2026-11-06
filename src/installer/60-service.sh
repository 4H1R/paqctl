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
