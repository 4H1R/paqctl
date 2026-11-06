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
