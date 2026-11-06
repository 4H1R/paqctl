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
