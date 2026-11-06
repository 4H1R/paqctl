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
