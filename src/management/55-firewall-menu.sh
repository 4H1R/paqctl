#═══════════════════════════════════════════════════════════════════════
# Firewall Display
#═══════════════════════════════════════════════════════════════════════

show_firewall() {
    if [ "$ROLE" != "server" ] && [ "$BACKEND" != "gfw-knocker" ]; then
        echo ""
        log_info "Firewall rules only apply in server mode or GFK client mode"
        echo ""
        return
    fi

    local redraw=true
    while true; do
        if [ "$redraw" = true ]; then
            echo ""
            echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
            echo -e "${BOLD}  FIREWALL RULES${NC}"
            echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
            echo ""

            local _fw_backend="iptables"
            _is_firewalld_active && _fw_backend="firewalld"
            echo -e "  ${DIM}Backend: ${_fw_backend}${NC}"
            echo ""

            if [ "$BACKEND" = "gfw-knocker" ]; then
                local vio_port
                if [ "$ROLE" = "server" ]; then
                    vio_port="${GFK_VIO_PORT:-45000}"
                else
                    vio_port="${GFK_VIO_CLIENT_PORT:-40000}"
                fi
                echo -e "  ${BOLD}Required rules for VIO port ${vio_port}:${NC}"
                echo ""
                if [ "$_fw_backend" = "firewalld" ]; then
                    firewall-cmd --direct --query-rule ipv4 raw PREROUTING 0 -p tcp --dport "$vio_port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null \
                        && echo -e "  ${GREEN}✓${NC} PREROUTING NOTRACK (dport $vio_port)" \
                        || echo -e "  ${RED}✗${NC} PREROUTING NOTRACK (dport $vio_port)  ${DIM}MISSING${NC}"
                    firewall-cmd --direct --query-rule ipv4 raw OUTPUT 0 -p tcp --sport "$vio_port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null \
                        && echo -e "  ${GREEN}✓${NC} OUTPUT NOTRACK (sport $vio_port)" \
                        || echo -e "  ${RED}✗${NC} OUTPUT NOTRACK (sport $vio_port)  ${DIM}MISSING${NC}"
                    firewall-cmd --direct --query-rule ipv4 filter INPUT 0 -p tcp --dport "$vio_port" -m comment --comment "paqctl" -j DROP 2>/dev/null \
                        && echo -e "  ${GREEN}✓${NC} INPUT DROP (dport $vio_port)" \
                        || echo -e "  ${RED}✗${NC} INPUT DROP (dport $vio_port)  ${DIM}MISSING${NC}"
                    firewall-cmd --direct --query-rule ipv4 filter OUTPUT 0 -p tcp --sport "$vio_port" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP 2>/dev/null \
                        && echo -e "  ${GREEN}✓${NC} RST DROP (sport $vio_port)" \
                        || echo -e "  ${RED}✗${NC} RST DROP (sport $vio_port)  ${DIM}MISSING${NC}"
                else
                    iptables -t raw -C PREROUTING -p tcp --dport "$vio_port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null \
                        && echo -e "  ${GREEN}✓${NC} PREROUTING NOTRACK (dport $vio_port)" \
                        || echo -e "  ${RED}✗${NC} PREROUTING NOTRACK (dport $vio_port)  ${DIM}MISSING${NC}"
                    iptables -t raw -C OUTPUT -p tcp --sport "$vio_port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null \
                        && echo -e "  ${GREEN}✓${NC} OUTPUT NOTRACK (sport $vio_port)" \
                        || echo -e "  ${RED}✗${NC} OUTPUT NOTRACK (sport $vio_port)  ${DIM}MISSING${NC}"
                    iptables -C INPUT -p tcp --dport "$vio_port" -m comment --comment "paqctl" -j DROP 2>/dev/null \
                        && echo -e "  ${GREEN}✓${NC} INPUT DROP (dport $vio_port)" \
                        || echo -e "  ${RED}✗${NC} INPUT DROP (dport $vio_port)  ${DIM}MISSING${NC}"
                    iptables -C OUTPUT -p tcp --sport "$vio_port" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP 2>/dev/null \
                        && echo -e "  ${GREEN}✓${NC} RST DROP (sport $vio_port)" \
                        || echo -e "  ${RED}✗${NC} RST DROP (sport $vio_port)  ${DIM}MISSING${NC}"
                fi
            else
                local port="${LISTEN_PORT:-8443}"
                echo -e "  ${BOLD}Required rules for port ${port}:${NC}"
                echo ""
                if [ "$_fw_backend" = "firewalld" ]; then
                    firewall-cmd --direct --query-rule ipv4 raw PREROUTING 0 -p tcp --dport "$port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null \
                        && echo -e "  ${GREEN}✓${NC} PREROUTING NOTRACK (dport $port)" \
                        || echo -e "  ${RED}✗${NC} PREROUTING NOTRACK (dport $port)  ${DIM}MISSING${NC}"
                    firewall-cmd --direct --query-rule ipv4 raw OUTPUT 0 -p tcp --sport "$port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null \
                        && echo -e "  ${GREEN}✓${NC} OUTPUT NOTRACK (sport $port)" \
                        || echo -e "  ${RED}✗${NC} OUTPUT NOTRACK (sport $port)  ${DIM}MISSING${NC}"
                    firewall-cmd --direct --query-rule ipv4 mangle OUTPUT 0 -p tcp --sport "$port" --tcp-flags RST RST -m comment --comment "paqctl" -j DROP 2>/dev/null \
                        && echo -e "  ${GREEN}✓${NC} RST DROP (sport $port)" \
                        || echo -e "  ${RED}✗${NC} RST DROP (sport $port)  ${DIM}MISSING${NC}"
                else
                    iptables -t raw -C PREROUTING -p tcp --dport "$port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null \
                        && echo -e "  ${GREEN}✓${NC} PREROUTING NOTRACK (dport $port)" \
                        || echo -e "  ${RED}✗${NC} PREROUTING NOTRACK (dport $port)  ${DIM}MISSING${NC}"
                    iptables -t raw -C OUTPUT -p tcp --sport "$port" -m comment --comment "paqctl" -j NOTRACK 2>/dev/null \
                        && echo -e "  ${GREEN}✓${NC} OUTPUT NOTRACK (sport $port)" \
                        || echo -e "  ${RED}✗${NC} OUTPUT NOTRACK (sport $port)  ${DIM}MISSING${NC}"
                    iptables -t mangle -C OUTPUT -p tcp --sport "$port" -m comment --comment "paqctl" --tcp-flags RST RST -j DROP 2>/dev/null \
                        && echo -e "  ${GREEN}✓${NC} RST DROP (sport $port)" \
                        || echo -e "  ${RED}✗${NC} RST DROP (sport $port)  ${DIM}MISSING${NC}"
                fi
                echo ""
                if ! _egress_guard_wanted; then
                    echo -e "  ${YELLOW}!${NC} Egress guard OFF  ${DIM}(sudo paqctl config set EGRESS_GUARD=true)${NC}"
                elif _egress_guard_active; then
                    echo -e "  ${GREEN}✓${NC} Egress guard (paqet cannot reach private/loopback/metadata addresses)"
                    [ -n "${EGRESS_ALLOW:-}" ] && echo -e "    ${DIM}Allowed: ${EGRESS_ALLOW}${NC}"
                elif is_running; then
                    echo -e "  ${RED}✗${NC} Egress guard  ${DIM}MISSING${NC}"
                else
                    echo -e "  ${DIM}• Egress guard is installed when paqet starts${NC}"
                fi
            fi

            echo ""
            echo -e "  ${BOLD}Actions:${NC}"
            echo "  1. Apply missing rules"
            echo "  2. Remove all rules"
            echo "  b. Back"
            echo ""
            redraw=false
        fi

        read -p "  Choice: " fw_choice < /dev/tty || break
        case "$fw_choice" in
            1)
                _apply_firewall
                _persist_firewall
                log_success "Firewall rules applied and persisted"
                read -n 1 -s -r -p "  Press any key..." < /dev/tty || true
                redraw=true
                ;;
            2)
                _remove_firewall
                _persist_firewall
                log_success "Firewall rules removed"
                read -n 1 -s -r -p "  Press any key..." < /dev/tty || true
                redraw=true
                ;;
            b|B) return ;;
            "") ;;
            *) echo -e "  ${RED}Invalid choice${NC}" ;;
        esac
    done
}
