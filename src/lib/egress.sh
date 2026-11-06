#═══════════════════════════════════════════════════════════════════════
# Egress guard (paqet server)
#
# A paqet server dials whatever address a client asks for. Without this
# guard anyone holding the key can reach this host's loopback services, its
# Docker/private networks and the cloud metadata service (169.254.169.254).
#
# The guard rejects such connections for processes in paqctl.service only
# (iptables cgroup match). paqet's tunnel packets are injected below iptables
# and are not affected; neither is anything else on the host.
#
# The cgroup match binds to the cgroup that exists when the rule is added,
# so the rules are rebuilt on every start (ExecStartPre -> _apply_firewall)
# and kept out of saved rulesets, where they would fail to restore at boot.
#
# Settings: EGRESS_GUARD=true|false (default true)
#           EGRESS_ALLOW="127.0.0.1:80, 10.0.0.0/8, [fd00::1]:443"
#═══════════════════════════════════════════════════════════════════════

_EGRESS_CHAIN="PAQCTL_EGRESS"
_EGRESS_DENY="PAQCTL_EGRESS_DENY"
_EGRESS_TAG="paqctl-egress"
_EGRESS_LOG_PREFIX="paqctl-egress: "
_EGRESS_CGROUP="system.slice/paqctl.service"
_EGRESS_RESOLV_CONF="/etc/resolv.conf"
# Loopback, "this host", RFC1918, CGNAT, link-local (cloud metadata),
# IETF/benchmark ranges, multicast and reserved
_EGRESS_BLOCK4="0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.168.0.0/16 198.18.0.0/15 224.0.0.0/4 240.0.0.0/4"
# Unspecified, loopback, link-local, site-local, unique-local, multicast
_EGRESS_BLOCK6="::/128 ::1/128 fe80::/10 fec0::/10 fc00::/7 ff00::/8"

# Is the guard wanted for this install? (paqet server, not switched off)
_egress_guard_wanted() {
    [ "${BACKEND:-paqet}" = "paqet" ] && [ "${ROLE:-}" = "server" ] && [ "${EGRESS_GUARD:-true}" = "true" ]
}

_egress_valid_ip6() {
    [[ "$1" == *:* ]] && [[ "$1" =~ ^[0-9A-Fa-f:.]+$ ]] && [ ${#1} -le 45 ] || return 1
    local rest="${1#*::}"
    [[ "$rest" != *::* ]]   # at most one "::"
}

# _egress_parse_allow ENTRY -> "FAMILY|CIDR|PORT" (PORT may be empty); 1 if invalid
# Accepts: 1.2.3.4  1.2.3.0/24  1.2.3.4:80  1.2.3.0/24:80  fd00::1  fd00::/8  [fd00::1]:80  [fd00::/8]:80
_egress_parse_allow() {
    local e="$1" addr port="" ip pfx="" fam
    if [[ "$e" =~ ^\[([^]]+)\]:([0-9]+)$ ]]; then
        addr="${BASH_REMATCH[1]}"; port="${BASH_REMATCH[2]}"
    elif [[ "$e" =~ ^([0-9./]+):([0-9]+)$ ]]; then
        addr="${BASH_REMATCH[1]}"; port="${BASH_REMATCH[2]}"
    else
        addr="$e"
    fi
    ip="${addr%%/*}"
    [[ "$addr" == */* ]] && pfx="${addr#*/}"
    if _validate_ip "$ip"; then
        fam=4
        [ -z "$pfx" ] || { [[ "$pfx" =~ ^[0-9]{1,2}$ ]] && [ "$pfx" -le 32 ]; } || return 1
    elif _egress_valid_ip6 "$ip"; then
        fam=6
        [ -z "$pfx" ] || { [[ "$pfx" =~ ^[0-9]{1,3}$ ]] && [ "$pfx" -le 128 ]; } || return 1
    else
        return 1
    fi
    [ -z "$port" ] || _validate_port "$port" || return 1
    printf '%s|%s|%s\n' "$fam" "$addr" "$port"
}

# EGRESS_ALLOW split on commas and whitespace
_egress_allow_list() {
    local list="${EGRESS_ALLOW:-}"
    list="${list//,/ }"
    local e
    for e in $list; do printf '%s\n' "$e"; done
}

# Every EGRESS_ALLOW entry valid? (empty is valid)
_egress_valid_allow() {
    local e
    for e in $(EGRESS_ALLOW="$1" _egress_allow_list); do
        _egress_parse_allow "$e" >/dev/null || return 1
    done
    return 0
}

# DNS resolvers paqet needs to reach (they are often on loopback, e.g. 127.0.0.53)
_egress_resolvers() {
    local fam="$1" ns any=false
    while read -r _ ns _; do
        any=true
        ns="${ns%%\%*}"
        if [ "$fam" = 4 ] && _validate_ip "$ns"; then
            echo "$ns"
        elif [ "$fam" = 6 ] && _egress_valid_ip6 "$ns"; then
            echo "$ns"
        fi
    done < <(grep -E '^[[:space:]]*nameserver[[:space:]]' "$_EGRESS_RESOLV_CONF" 2>/dev/null)
    # No nameserver line: resolvers fall back to localhost
    if [ "$any" = false ]; then
        if [ "$fam" = 4 ]; then echo "127.0.0.1"; else echo "::1"; fi
    fi
}

# Root of the cgroup v2 hierarchy (unified or hybrid mode)
_egress_cgroup_root() {
    if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
        echo /sys/fs/cgroup
    elif [ -f /sys/fs/cgroup/unified/cgroup.controllers ]; then
        echo /sys/fs/cgroup/unified
    else
        return 1
    fi
}

# _egress_build_family iptables|ip6tables  - (re)create the guard chains
_egress_build_family() {
    local ipt="$1" fam=4 rej="icmp-admin-prohibited" block="$_EGRESS_BLOCK4"
    if [ "$ipt" = "ip6tables" ]; then
        fam=6; rej="icmp6-adm-prohibited"; block="$_EGRESS_BLOCK6"
    fi
    local c
    for c in "$_EGRESS_DENY" "$_EGRESS_CHAIN"; do
        "$ipt" -w -N "$c" 2>/dev/null || "$ipt" -w -F "$c" 2>/dev/null || return 1
    done

    # Deny: log (rate-limited, for 'paqctl doctor') and fail fast
    "$ipt" -w -A "$_EGRESS_DENY" -m limit --limit 10/min --limit-burst 20 \
        -j LOG --log-prefix "$_EGRESS_LOG_PREFIX" --log-level info 2>/dev/null || true
    "$ipt" -w -A "$_EGRESS_DENY" -p tcp -j REJECT --reject-with tcp-reset || return 1
    "$ipt" -w -A "$_EGRESS_DENY" -j REJECT --reject-with "$rej" || return 1

    # Published ports (e.g. Docker): the client asked for a public or local
    # address that was DNATed to a private one - allowed, as from anywhere else
    "$ipt" -w -A "$_EGRESS_CHAIN" -m conntrack --ctstate DNAT -j RETURN || return 1

    local r proto
    while IFS= read -r r; do
        [ -n "$r" ] || continue
        for proto in udp tcp; do
            "$ipt" -w -A "$_EGRESS_CHAIN" -d "$r" -p "$proto" --dport 53 -j RETURN || return 1
        done
    done < <(_egress_resolvers "$fam")

    local e parsed f cidr port
    while IFS= read -r e; do
        parsed=$(_egress_parse_allow "$e") || continue
        IFS='|' read -r f cidr port <<< "$parsed"
        [ "$f" = "$fam" ] || continue
        if [ -n "$port" ]; then
            for proto in tcp udp; do
                "$ipt" -w -A "$_EGRESS_CHAIN" -d "$cidr" -p "$proto" --dport "$port" -j RETURN || return 1
            done
        else
            "$ipt" -w -A "$_EGRESS_CHAIN" -d "$cidr" -j RETURN || return 1
        fi
    done < <(_egress_allow_list)

    for cidr in $block; do
        "$ipt" -w -A "$_EGRESS_CHAIN" -d "$cidr" -j "$_EGRESS_DENY" || return 1
    done
}

# Delete every OUTPUT jump to the guard (by number: the cgroup a stale rule
# points to may no longer exist), then the chains
_egress_remove_family() {
    local ipt="$1" n
    command -v "$ipt" &>/dev/null || return 0
    for _ in $(seq 1 20); do
        n=$("$ipt" -w -L OUTPUT -n --line-numbers 2>/dev/null | awk -v c="$_EGRESS_CHAIN" '$2 == c {print $1; exit}')
        [ -n "$n" ] || break
        "$ipt" -w -D OUTPUT "$n" 2>/dev/null || break
    done
    local c
    for c in "$_EGRESS_CHAIN" "$_EGRESS_DENY"; do
        "$ipt" -w -F "$c" 2>/dev/null || true
        "$ipt" -w -X "$c" 2>/dev/null || true
    done
}

_egress_guard_remove() {
    _egress_remove_family iptables
    _egress_remove_family ip6tables
}

# Is the guard jump in place (IPv4)?
_egress_guard_active() {
    command -v iptables &>/dev/null || return 1
    iptables -w -L OUTPUT -n 2>/dev/null | awk -v c="$_EGRESS_CHAIN" '$1 == c {f = 1} END {exit !f}'
}

# Rebuild the guard, or remove it when it is not wanted.
# Returns 0 when done (or not wanted), 2 when paqet is not running (the guard
# is installed at the next start), 1 on failure.
_egress_guard_apply() {
    _egress_guard_remove
    _egress_guard_wanted || return 0

    if _is_firewalld_active; then
        echo -e "${YELLOW}[!]${NC} Egress guard is not available with firewalld: paqet clients can reach this host's private networks." >&2
        return 1
    fi
    if ! command -v iptables &>/dev/null; then
        echo -e "${YELLOW}[!]${NC} Egress guard needs iptables." >&2
        return 1
    fi
    if [ ! -d /run/systemd/system ]; then
        echo -e "${YELLOW}[!]${NC} Egress guard needs systemd: paqet clients can reach this host's private networks." >&2
        return 1
    fi
    local root
    if ! root=$(_egress_cgroup_root); then
        echo -e "${YELLOW}[!]${NC} Egress guard needs cgroup v2 (not available on this system)." >&2
        return 1
    fi
    # The service cgroup only exists while it runs (ExecStartPre included)
    [ -d "$root/$_EGRESS_CGROUP" ] || return 2
    modprobe xt_cgroup 2>/dev/null || true

    local ok=true
    if _egress_build_family iptables; then
        iptables -w -I OUTPUT 1 -m cgroup --path "$_EGRESS_CGROUP" -m comment --comment "$_EGRESS_TAG" \
            -j "$_EGRESS_CHAIN" 2>/dev/null || ok=false
    else
        ok=false
    fi
    if command -v ip6tables &>/dev/null && [ -d /proc/sys/net/ipv6 ]; then
        if _egress_build_family ip6tables; then
            ip6tables -w -I OUTPUT 1 -m cgroup --path "$_EGRESS_CGROUP" -m comment --comment "$_EGRESS_TAG" \
                -j "$_EGRESS_CHAIN" 2>/dev/null || ok=false
        else
            ok=false
        fi
    fi
    if [ "$ok" != true ]; then
        echo -e "${YELLOW}[!]${NC} Could not install the egress guard (iptables cgroup match unavailable?)." >&2
        return 1
    fi
    return 0
}

# Prove the guard works: from inside paqet's cgroup, connect to a TCP port
# that is reachable from outside it. Prints "blocked", "open" or "skipped".
_egress_selftest() {
    local root dir port
    root=$(_egress_cgroup_root) || { echo skipped; return 0; }
    dir="$root/$_EGRESS_CGROUP"
    [ -w "$dir/cgroup.procs" ] || { echo skipped; return 0; }
    # A loopback-reachable TCP listener, not DNS and not allow-listed
    port=$(ss -Hltn 2>/dev/null | awk '{print $4}' | grep -E '^(127\.0\.0\.1|0\.0\.0\.0|\*):[0-9]+$' \
        | sed 's/.*://' | grep -vx 53 | sort -un | head -1)
    [ -n "$port" ] || { echo skipped; return 0; }
    local e
    for e in $(_egress_allow_list); do
        case "$e" in 127.*|0.*) echo skipped; return 0 ;; esac
    done
    timeout 3 bash -c "exec 3<>/dev/tcp/127.0.0.1/$port" 2>/dev/null || { echo skipped; return 0; }
    # shellcheck disable=SC2016  # expanded by the inner shell
    if timeout 3 bash -c 'echo "$BASHPID" > "$1/cgroup.procs" && exec 3<>"/dev/tcp/127.0.0.1/$2"' _ "$dir" "$port" 2>/dev/null; then
        echo open
    else
        echo blocked
    fi
}

# Client side: a forward-mode target on the server's private side (e.g. a
# panel on its 127.0.0.1) has to be allowed on the server
_egress_forward_hint() {
    local target="$1" host
    host="${target%:*}"; host="${host#[}"; host="${host%]}"
    case "$host" in
        localhost|127.*|0.*|10.*|192.168.*|169.254.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|\
        100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*|::1|[fF][cCdD]*|[fF][eE]80*) ;;
        *) return 0 ;;
    esac
    echo -e "  ${YELLOW}Note:${NC} paqet servers block private/loopback targets by default. Allow this one on the server:"
    echo -e "    ${BOLD}sudo paqctl config set EGRESS_ALLOW=\"${target/localhost/127.0.0.1}\"${NC}"
}

# Connections the guard rejected recently (kernel log, rate-limited): "COUNT DST:PORT" lines
_egress_recent_blocks() {
    local since="${1:-24 hours ago}"
    command -v journalctl &>/dev/null || return 0
    journalctl -k --since "$since" --no-pager -o cat 2>/dev/null | grep -F "$_EGRESS_LOG_PREFIX" \
        | sed -nE 's/.* DST=([^ ]+) .*PROTO=([A-Z0-9]+)( .* DPT=([0-9]+))?.*/\1:\4 (\2)/p' \
        | sed 's/: (/ (/' | sort | uniq -c | sort -rn
}
