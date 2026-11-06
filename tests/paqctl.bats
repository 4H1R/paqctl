#!/usr/bin/env bats
# Tests for the paqctl management CLI (the script embedded in paqctl.sh).
# They need no root and touch nothing outside a temp directory.

setup() {
    ROOT="$(cd "$BATS_TEST_DIRNAME/.." && pwd)"
    WORK="$(mktemp -d)"
    mkdir -p "$WORK/opt"
    "$ROOT/tests/extract-management.sh" "$ROOT/paqctl.sh" "$WORK/opt" > "$WORK/paqctl"
    chmod +x "$WORK/paqctl"
    P="$WORK/paqctl"
}

teardown() {
    rm -rf "$WORK"
}

# Source the script's functions without running a command
load_paqctl() {
    export PAQCTL_SOURCE_ONLY=1
    # shellcheck disable=SC1090
    source "$P"
}

@test "installer and management script pass bash -n" {
    bash -n "$ROOT/paqctl.sh"
    bash -n "$P"
}

@test "paqctl.sh is up to date with src/" {
    run bash "$ROOT/build.sh" --check
    echo "$output"
    [ "$status" -eq 0 ]
}

@test "no function is defined in more than one source file" {
    # Shared code lives in src/lib and is included into both scripts by build.sh
    # (definitions inside heredocs belong to generated helper scripts and are skipped)
    run bash -c '
        cd "$1/src"
        for f in lib/*.sh installer/*.sh management/*.sh; do
            awk -v f="$f" "
                hd != \"\" { if (\$0 == hd) hd = \"\"; next }
                /^[A-Za-z_][A-Za-z0-9_]*\\(\\) *\\{/ { n = \$0; sub(/\\(.*/, \"\", n); print n, f }
                match(\$0, /<<-? *[\x27\"]?[A-Za-z_][A-Za-z0-9_]*[\x27\"]? *\$/) && \$0 !~ /<<</ {
                    hd = substr(\$0, RSTART); gsub(/[<\x27\" -]/, \"\", hd)
                }" "$f"
        done | sort | awk "{ if (\$1 == prev && \$2 != prevf) print \"duplicate: \" \$1 \" in \" prevf \" and \" \$2; prev = \$1; prevf = \$2 }"' _ "$ROOT"
    echo "$output"
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

@test "help lists every registered command" {
    run "$P" help
    [ "$status" -eq 0 ]
    local names
    names=$(PAQCTL_SOURCE_ONLY=1 bash -c "source '$P'; _command_names")
    [ -n "$names" ]
    while IFS= read -r name; do
        if [[ "$output" != *"  $name "* ]]; then
            echo "help is missing: $name"
            return 1
        fi
    done <<< "$names"
}

@test "every registered command has a handler in _main" {
    run env PAQCTL_SOURCE_ONLY=1 bash -c '
        source "$1"
        body=$(declare -f _main)
        for n in $(_command_names); do
            grep -qE "^ +${n}\)" <<< "$body" || { echo "no handler: $n"; exit 1; }
        done' _ "$P"
    echo "$output"
    [ "$status" -eq 0 ]
}

@test "aliases resolve to their canonical command" {
    load_paqctl
    [ "$(_resolve_command rotate)" = "rotate-key" ]
    [ "$(_resolve_command top)" = "monitor" ]
    [ "$(_resolve_command clean)" = "cleanup" ]
    [ "$(_resolve_command share)" = "export" ]
    [ "$(_resolve_command dns)" = "routing" ]
    [ "$(_resolve_command -h)" = "help" ]
    run _resolve_command nope
    [ "$status" -ne 0 ]
}

@test "unknown command suggests the closest one and exits 2" {
    run "$P" staus
    [ "$status" -eq 2 ]
    [[ "$output" == *"Unknown command: staus"* ]]
    [[ "$output" == *"paqctl status"* ]]

    run "$P" rotat
    [ "$status" -eq 2 ]
    [[ "$output" == *"paqctl rotate-key"* ]]

    run "$P" qqqqqq
    [ "$status" -eq 2 ]
    [[ "$output" != *"Did you mean"* ]]
}

@test "help <command> shows usage, aliases and details" {
    run "$P" help top
    [ "$status" -eq 0 ]
    [[ "$output" == *"paqctl monitor"* ]]
    [[ "$output" == *"Aliases: top clients"* ]]

    run "$P" help config
    [ "$status" -eq 0 ]
    [[ "$output" == *"config set KEY=VALUE"* ]]

    run "$P" help nonsense
    [ "$status" -eq 2 ]
}

@test "help, version and completion work without root" {
    run "$P" help
    [ "$status" -eq 0 ]
    run "$P" version
    [ "$status" -eq 0 ]
    [[ "$output" == *"paqctl version"* ]]
    run "$P" completion bash
    [ "$status" -eq 0 ]
}

@test "state-changing commands refuse to run without root" {
    [ "$(id -u)" -ne 0 ] || skip "running as root"
    run "$P" status
    [ "$status" -eq 1 ]
    [[ "$output" == *"must be run as root"* ]]
}

@test "bash completion script is valid and completes commands" {
    run "$P" completion bash
    [ "$status" -eq 0 ]
    bash -n <<< "$output"
    [[ "$output" == *"rotate-key"* ]]

    run bash -c '
        source <("$1" completion bash)
        COMP_WORDS=(paqctl sta); COMP_CWORD=1; _paqctl; echo "${COMPREPLY[*]}"
        COMP_WORDS=(paqctl watchdog ""); COMP_CWORD=2; _paqctl; echo "${COMPREPLY[*]}"
        COMP_WORDS=(paqctl -y logs --backend ""); COMP_CWORD=4; _paqctl; echo "${COMPREPLY[*]}"' _ "$P"
    [ "$status" -eq 0 ]
    [[ "${lines[0]}" == *status* ]]
    [[ "${lines[0]}" == *start* ]]
    [ "${lines[1]}" = "enable disable status" ]
    [ "${lines[2]}" = "paqet gfk" ]
}

@test "zsh completion wraps the bash one" {
    run "$P" completion zsh
    [ "$status" -eq 0 ]
    [[ "${lines[0]}" == "#compdef paqctl" ]]
    run "$P" completion fish
    [ "$status" -eq 2 ]
}

@test "output has no colour codes when not a terminal" {
    run "$P" help
    [ "$status" -eq 0 ]
    [[ "$output" != *$'\033['* ]]
}

@test "global flags are accepted anywhere and removed from arguments" {
    run "$P" --no-color help -y status
    [ "$status" -eq 0 ]
    [[ "$output" == *"paqctl status"* ]]
}

@test "ban targets are validated (IPv4, IPv6, CIDR)" {
    load_paqctl
    [ "$(_parse_ban_target 203.0.113.7)" = "4 203.0.113.7" ]
    [ "$(_parse_ban_target 198.51.100.0/24)" = "4 198.51.100.0/24" ]
    [ "$(_parse_ban_target 2001:db8::1)" = "6 2001:db8::1" ]
    [ "$(_parse_ban_target 2001:db8::/32)" = "6 2001:db8::/32" ]
    [ "$(_parse_ban_target ::1)" = "6 ::1" ]
    for bad in 999.1.1.1 1.2.3 1.2.3.4/33 1.2.3.4/x 2001:db8::/129 2001:::1 1::2::3 \
               12345::1 abc "" "1.2.3.4; rm -rf /" "1.2.3.4 5.6.7.8"; do
        if _parse_ban_target "$bad" >/dev/null; then
            echo "accepted invalid target: '$bad'"
            return 1
        fi
    done
}

@test "JSON helpers escape correctly" {
    load_paqctl
    [ "$(_json_str 'a"b\c')" = '"a\"b\\c"' ]
    [ "$(_json_str $'line1\nline2')" = '"line1\nline2"' ]
    [ "$(_json_bool true)" = "true" ]
    [ "$(_json_bool nope)" = "false" ]
    [ "$(_json_num 42)" = "42" ]
    [ "$(_json_num abc)" = "null" ]
}

@test "export URI encodes the paqet client fields" {
    load_paqctl
    BACKEND=paqet ROLE=server LISTEN_PORT=8443 ENCRYPTION_KEY=0123456789abcdef \
        SOCKS_PORT=1080 ROUTING_MODE=socks5 KCP_PROFILE=standard KCP_MTU=1300
    uri=$(_build_export_uri 203.0.113.5)
    [[ "$uri" == paqet://* ]]
    decoded=$(printf '%s' "${uri#paqet://}" | base64 -d)
    [ "$decoded" = "paqet|203.0.113.5|8443|0123456789abcdef|1080|socks5|14000|127.0.0.1:80|standard|1300" ]

    # host:port form keeps the explicit port
    uri=$(_build_export_uri 203.0.113.5:9443)
    decoded=$(printf '%s' "${uri#paqet://}" | base64 -d)
    [[ "$decoded" == "paqet|203.0.113.5|9443|"* ]]
}

@test "export URI encodes the GFK client fields" {
    load_paqctl
    BACKEND=gfw-knocker GFK_AUTH_CODE=abcd1234 GFK_PORT_MAPPINGS=14000:443 GFK_SOCKS_VIO_PORT=14000
    uri=$(_build_export_uri 203.0.113.5)
    decoded=$(printf '%s' "${uri#gfk://}" | base64 -d)
    [ "$decoded" = "gfk|203.0.113.5|abcd1234|14000:443|14000" ]
}

@test "config set validates keys and values" {
    load_paqctl
    _config_validate LISTEN_PORT 9443
    _config_validate KCP_MTU 1200
    _config_validate REMOTE_SERVER 203.0.113.5:8443
    _config_validate REMOTE_SERVER "[2001:db8::1]:8443"
    _config_validate ROUTING_MODE forward
    _config_validate ENCRYPTION_KEY 0123456789abcdef0123456789abcdef
    run _config_validate LISTEN_PORT 70000;      [ "$status" -eq 1 ]
    run _config_validate KCP_MTU 100;            [ "$status" -eq 1 ]
    run _config_validate ROUTING_MODE magic;     [ "$status" -eq 1 ]
    run _config_validate ENCRYPTION_KEY 'a"b';   [ "$status" -eq 1 ]
    run _config_validate REMOTE_SERVER host;     [ "$status" -eq 1 ]
    run _config_validate BACKEND paqet;          [ "$status" -eq 3 ]
}

@test "YAML escaping never adds quotes and escapes \\ and \"" {
    load_paqctl
    [ "$(_escape_yaml 'plain')" = 'plain' ]
    [ "$(_escape_yaml 'a:b #c')" = 'a:b #c' ]
    [ "$(_escape_yaml 'say "hi"')" = 'say \"hi\"' ]
    [ "$(_escape_yaml 'back\slash')" = 'back\\slash' ]
    [ "$(_escape_yaml ' lead')" = ' lead' ]
}

@test "config.yaml keeps the existing KCP mode and only writes manual params in manual mode" {
    load_paqctl
    INSTALL_DIR="$WORK/opt"
    ROLE=server LISTEN_PORT=8443 INTERFACE=eth0 LOCAL_IP=203.0.113.5 GATEWAY_MAC=aa:bb:cc:dd:ee:ff
    ENCRYPTION_KEY=0123456789abcdef KCP_SOCKBUF=4194304 KCP_CONN=8
    unset KCP_MODE

    # no config yet -> default "fast"
    generate_paqet_yaml "$WORK/opt/config.yaml"
    grep -q '^    mode: "fast"$' "$WORK/opt/config.yaml"
    ! grep -q 'nodelay:' "$WORK/opt/config.yaml"
    # sockbuf belongs to network.pcap, never to transport.kcp; conn is not a server key
    awk '/^  pcap:/{p=1;next} p&&/^    sockbuf:/{found=1} /^[^ ]/{p=0} END{exit !found}' "$WORK/opt/config.yaml"
    ! awk '/^  kcp:/{k=1;next} k&&/^    (sockbuf|conn):/{bad=1} END{exit !bad}' "$WORK/opt/config.yaml"

    # an existing fast2 config stays fast2 when regenerated
    sed -i 's/mode: "fast"/mode: "fast2"/' "$WORK/opt/config.yaml"
    generate_paqet_yaml "$WORK/opt/new.yaml"
    grep -q '^    mode: "fast2"$' "$WORK/opt/new.yaml"

    # an explicit KCP_MODE wins; manual writes the tuning knobs
    KCP_MODE=manual KCP_NODELAY=1 KCP_INTERVAL=10 KCP_RESEND=2 KCP_NOCONGESTION=1
    generate_paqet_yaml "$WORK/opt/manual.yaml"
    grep -q '^    mode: "manual"$' "$WORK/opt/manual.yaml"
    grep -q '^    nodelay: 1$' "$WORK/opt/manual.yaml"
    grep -q '^    interval: 10$' "$WORK/opt/manual.yaml"

    # garbage mode falls back to fast
    KCP_MODE=turbo generate_paqet_yaml "$WORK/opt/bad.yaml"
    grep -q '^    mode: "fast"$' "$WORK/opt/bad.yaml"
}

@test "config set accepts the KCP modes paqet supports" {
    load_paqctl
    for m in normal fast fast2 fast3 manual; do _config_validate KCP_MODE "$m"; done
    run _config_validate KCP_MODE turbo
    [ "$status" -eq 1 ]
}

@test "secrets are masked" {
    load_paqctl
    [ "$(_mask_secret 0123456789abcdef)" = "0123****ef" ]
    [ "$(_mask_secret short)" = "****" ]
}

@test "levenshtein distance" {
    load_paqctl
    [ "$(_levenshtein status staus)" = "1" ]
    [ "$(_levenshtein kitten sitting)" = "3" ]
    [ "$(_levenshtein same same)" = "0" ]
}

@test "egress allow-list entries are parsed and validated" {
    load_paqctl
    [ "$(_egress_parse_allow 127.0.0.1)" = "4|127.0.0.1|" ]
    [ "$(_egress_parse_allow 127.0.0.1:80)" = "4|127.0.0.1|80" ]
    [ "$(_egress_parse_allow 10.0.0.0/8)" = "4|10.0.0.0/8|" ]
    [ "$(_egress_parse_allow 10.1.0.0/16:5432)" = "4|10.1.0.0/16|5432" ]
    [ "$(_egress_parse_allow fd00::5)" = "6|fd00::5|" ]
    [ "$(_egress_parse_allow fd00::/8)" = "6|fd00::/8|" ]
    [ "$(_egress_parse_allow '[fd00::5]:443')" = "6|fd00::5|443" ]
    [ "$(_egress_parse_allow '[fd00::/64]:443')" = "6|fd00::/64|443" ]
    for bad in "" 256.0.0.1 10.0.0.0/33 127.0.0.1:0 127.0.0.1:70000 fd00::/129 '[fd00::5]' \
               'fd00::1::2' example.com '127.0.0.1;reboot' '$(id)' 1.2.3.4/x; do
        if _egress_parse_allow "$bad" >/dev/null; then echo "accepted: $bad"; return 1; fi
    done
    _egress_valid_allow ""
    _egress_valid_allow "127.0.0.1:80, 10.0.0.0/8 [fd00::5]:443"
    ! _egress_valid_allow "127.0.0.1:80, nope"
    _config_validate EGRESS_ALLOW "127.0.0.1:80,10.0.0.0/8"
    _config_validate EGRESS_ALLOW ""
    ! _config_validate EGRESS_ALLOW "127.0.0.1:80 \$(id)"
    _config_validate EGRESS_GUARD true
    _config_validate EGRESS_GUARD false
    ! _config_validate EGRESS_GUARD yes
}

@test "egress guard is only wanted on a paqet server that has not switched it off" {
    load_paqctl
    BACKEND=paqet ROLE=server; unset EGRESS_GUARD
    _egress_guard_wanted
    EGRESS_GUARD=false; ! _egress_guard_wanted
    EGRESS_GUARD=true ROLE=client; ! _egress_guard_wanted
    ROLE=server BACKEND=gfw-knocker; ! _egress_guard_wanted
}

@test "egress settings survive save/load; invalid values are ignored on load" {
    load_paqctl
    INSTALL_DIR="$WORK/opt"
    ROLE=server EGRESS_GUARD=false EGRESS_ALLOW="127.0.0.1:80, 10.0.0.0/8"
    save_settings
    grep -qx 'EGRESS_GUARD="false"' "$WORK/opt/settings.conf"
    grep -qx 'EGRESS_ALLOW="127.0.0.1:80, 10.0.0.0/8"' "$WORK/opt/settings.conf"
    unset EGRESS_GUARD EGRESS_ALLOW
    _load_settings
    [ "$EGRESS_GUARD" = false ]
    [ "$EGRESS_ALLOW" = "127.0.0.1:80, 10.0.0.0/8" ]

    unset EGRESS_GUARD EGRESS_ALLOW
    save_settings
    grep -qx 'EGRESS_GUARD="true"' "$WORK/opt/settings.conf"

    sed -i 's/^EGRESS_ALLOW=.*/EGRESS_ALLOW="127.0.0.1:80 nope"/; s/^EGRESS_GUARD=.*/EGRESS_GUARD="maybe"/' "$WORK/opt/settings.conf"
    unset EGRESS_GUARD EGRESS_ALLOW
    _load_settings
    [ -z "${EGRESS_GUARD:-}" ]
    [ -z "${EGRESS_ALLOW:-}" ]
}

@test "egress guard rules: published ports and DNS first, allow-list before deny, all ranges denied" {
    load_paqctl
    printf 'nameserver 127.0.0.53\nnameserver fe80::1%%eth0\noptions edns0\n' > "$WORK/resolv.conf"
    _EGRESS_RESOLV_CONF="$WORK/resolv.conf"
    EGRESS_ALLOW="127.0.0.1:80, 10.0.0.0/8, [fd00::5]:443"
    iptables()  { echo "$*" >> "$WORK/v4"; }
    ip6tables() { echo "$*" >> "$WORK/v6"; }
    _egress_build_family iptables
    _egress_build_family ip6tables

    # IPv4 chain, in order
    chain4=$(grep -- "-A PAQCTL_EGRESS " "$WORK/v4" | sed 's/^-w -A PAQCTL_EGRESS //')
    [ "$(sed -n 1p <<< "$chain4")" = "-m conntrack --ctstate DNAT -j RETURN" ]
    [ "$(sed -n 2p <<< "$chain4")" = "-d 127.0.0.53 -p udp --dport 53 -j RETURN" ]
    [ "$(sed -n 3p <<< "$chain4")" = "-d 127.0.0.53 -p tcp --dport 53 -j RETURN" ]
    [ "$(sed -n 4p <<< "$chain4")" = "-d 127.0.0.1 -p tcp --dport 80 -j RETURN" ]
    [ "$(sed -n 5p <<< "$chain4")" = "-d 127.0.0.1 -p udp --dport 80 -j RETURN" ]
    [ "$(sed -n 6p <<< "$chain4")" = "-d 10.0.0.0/8 -j RETURN" ]
    for r in $_EGRESS_BLOCK4; do
        grep -qx -- "-d $r -j PAQCTL_EGRESS_DENY" <<< "$chain4" || { echo "not denied: $r"; return 1; }
    done
    [ "$(tail -1 <<< "$chain4")" = "-d 240.0.0.0/4 -j PAQCTL_EGRESS_DENY" ]
    ! grep -q fd00 "$WORK/v4"
    grep -q -- "-A PAQCTL_EGRESS_DENY -p tcp -j REJECT --reject-with tcp-reset" "$WORK/v4"
    grep -q -- "-A PAQCTL_EGRESS_DENY -j REJECT --reject-with icmp-admin-prohibited" "$WORK/v4"

    # IPv6: zone stripped from the resolver, only v6 allow entries
    chain6=$(grep -- "-A PAQCTL_EGRESS " "$WORK/v6" | sed 's/^-w -A PAQCTL_EGRESS //')
    grep -qx -- "-d fe80::1 -p udp --dport 53 -j RETURN" <<< "$chain6"
    grep -qx -- "-d fd00::5 -p tcp --dport 443 -j RETURN" <<< "$chain6"
    ! grep -q -e 127.0.0 -e 10.0.0.0 <<< "$chain6"
    for r in $_EGRESS_BLOCK6; do
        grep -qx -- "-d $r -j PAQCTL_EGRESS_DENY" <<< "$chain6" || { echo "not denied: $r"; return 1; }
    done
    grep -q -- "--reject-with icmp6-adm-prohibited" "$WORK/v6"
}

@test "egress guard falls back to localhost DNS when resolv.conf has no nameserver" {
    load_paqctl
    : > "$WORK/resolv.conf"
    _EGRESS_RESOLV_CONF="$WORK/resolv.conf"
    [ "$(_egress_resolvers 4)" = "127.0.0.1" ]
    [ "$(_egress_resolvers 6)" = "::1" ]
    _EGRESS_RESOLV_CONF="$WORK/missing"
    [ "$(_egress_resolvers 4)" = "127.0.0.1" ]
}

@test "saved firewall rules never contain the egress guard" {
    load_paqctl
    : > "$WORK/calls"
    _egress_guard_active()  { true; }
    _egress_guard_remove()  { echo remove >> "$WORK/calls"; }
    _persist_iptables_rules_now() { echo save >> "$WORK/calls"; }
    _egress_guard_apply()   { echo apply >> "$WORK/calls"; }
    persist_iptables_rules
    [ "$(tr '\n' ' ' < "$WORK/calls")" = "remove save apply " ]

    : > "$WORK/calls"
    _egress_guard_active()  { false; }
    persist_iptables_rules
    [ "$(tr '\n' ' ' < "$WORK/calls")" = "save " ]
}

@test "blocked connections are summarised from the kernel log" {
    load_paqctl
    journalctl() {
        cat << 'LOG'
paqctl-egress: IN= OUT=eth0 SRC=203.0.113.5 DST=169.254.169.254 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=1 DF PROTO=TCP SPT=40000 DPT=80 WINDOW=64240 RES=0x00 SYN URGP=0
paqctl-egress: IN= OUT=eth0 SRC=203.0.113.5 DST=169.254.169.254 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=2 DF PROTO=TCP SPT=40001 DPT=80 WINDOW=64240 RES=0x00 SYN URGP=0
paqctl-egress: IN= OUT=docker0 SRC=172.17.0.1 DST=172.17.0.2 LEN=40 TOS=0x00 PREC=0x00 TTL=64 ID=3 PROTO=UDP SPT=5000 DPT=6379 LEN=20
unrelated kernel line DST=1.1.1.1 PROTO=TCP DPT=1
LOG
    }
    out=$(_egress_recent_blocks)
    [ "$(sed -n 1p <<< "$out" | xargs)" = "2 169.254.169.254:80 (TCP)" ]
    [ "$(sed -n 2p <<< "$out" | xargs)" = "1 172.17.0.2:6379 (UDP)" ]
    [ "$(wc -l <<< "$out")" -eq 2 ]
}

@test "forward mode warns when the target is on the server's private side" {
    load_paqctl
    [[ "$(_egress_forward_hint 127.0.0.1:80)" == *'EGRESS_ALLOW="127.0.0.1:80"'* ]]
    [[ "$(_egress_forward_hint localhost:2053)" == *'EGRESS_ALLOW="127.0.0.1:2053"'* ]]
    [[ "$(_egress_forward_hint 172.20.0.5:5432)" == *'EGRESS_ALLOW="172.20.0.5:5432"'* ]]
    [[ "$(_egress_forward_hint '[::1]:8080')" == *'EGRESS_ALLOW="[::1]:8080"'* ]]
    [ -z "$(_egress_forward_hint 203.0.113.5:443)" ]
    [ -z "$(_egress_forward_hint example.com:443)" ]
    [ -z "$(_egress_forward_hint 172.32.0.1:80)" ]
}
