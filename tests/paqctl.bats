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
