#═══════════════════════════════════════════════════════════════════════
# Help
#═══════════════════════════════════════════════════════════════════════

#───────────────────────────────────────────────────────────────────────
# Command registry: the single source for help, aliases, suggestions
# and shell completion.   name;aliases;usage;group;summary
#───────────────────────────────────────────────────────────────────────
_PAQCTL_COMMANDS=(
"menu;;menu;General;Interactive menu (default when no command is given)"
"status;;status [--json];General;Show service status and configuration"
"info;details client;info [--ip ADDR] [--qr] [--json];General;Show connection info and the shareable client string"
"help;--help -h;help [COMMAND];General;Show help, or detailed help for one command"
"version;--version;version;General;Show version info"
"completion;;completion [bash|zsh];General;Print a shell completion script"
"start;;start;Service;Start the active backend(s)"
"stop;;stop;Service;Stop the active backend(s)"
"restart;;restart;Service;Restart the active backend(s)"
"start-paqet;;start-paqet;Service;Start only the paqet backend"
"stop-paqet;;stop-paqet;Service;Stop only the paqet backend"
"start-gfk;;start-gfk;Service;Start only the GFK backend"
"stop-gfk;;stop-gfk;Service;Stop only the GFK backend"
"start-all;;start-all;Service;Start every installed backend"
"stop-all;;stop-all;Service;Stop every installed backend"
"enable;boot-enable;enable;Service;Enable auto-start on boot (systemd, OpenRC, SysVinit)"
"disable;boot-disable;disable;Service;Disable auto-start on boot"
"watchdog;;watchdog [enable|disable|status];Service;Self-healing watchdog that restarts a failed service"
"health;;health [--json];Diagnostics;Run health checks (exits 1 if any check fails)"
"doctor;;doctor [--fix] [--json];Diagnostics;Health checks plus suggested fixes; --fix applies the safe ones"
"test;;test [--url URL];Diagnostics;End-to-end request through the local proxy (run on a client)"
"logs;;logs [-n N] [--no-follow] [--since TIME] [--backend paqet|gfk] [--errors];Diagnostics;View service logs"
"ping;;ping;Diagnostics;Test connectivity with paqet ping"
"dump;;dump;Diagnostics;Capture packets for diagnostics (paqet dump)"
"monitor;top clients;monitor;Diagnostics;Active client monitor"
"speedtest;speed;speedtest;Diagnostics;Server speed and bandwidth test"
"routing;dns check-dns;routing;Diagnostics;DNS leak and proxy routing check"
"config;;config [show [--reveal] | edit | set KEY=VALUE...];Configuration;Change configuration (interactive with no arguments)"
"export;share;export [--ip ADDR] [--qr] [--json];Configuration;Print the shareable client config string"
"import;;import [STRING | -];Configuration;Import a paqet:// or gfk:// string ('-' reads stdin)"
"rotate-key;rotate;rotate-key;Configuration;Rotate the encryption key / auth code and restart"
"secret;;secret;Configuration;Generate a new encryption key (prints it, does not apply it)"
"tune;tuning;tune;Configuration;Performance and KCP profile tuning menu"
"turbo;;turbo;Configuration;Enable kernel turbo mode (BBR, larger socket buffers)"
"turbo-off;;turbo-off;Configuration;Disable kernel turbo mode"
"telegram;;telegram;Configuration;Telegram notification settings"
"firewall;;firewall;Security;Show and manage paqctl's firewall rules"
"ban;;ban <IP[/CIDR]> | ban list;Security;Block an IP or range (IPv4/IPv6, survives restarts)"
"unban;;unban <IP[/CIDR]>;Security;Remove a ban"
"backup;;backup;Maintenance;Back up configuration (keeps the newest 10)"
"restore;;restore [FILE | latest | N];Maintenance;Restore configuration from a backup"
"update;;update;Maintenance;Update the backend binary and the management script"
"self-update;;self-update;Maintenance;Update only the paqctl management script"
"rollback;;rollback;Maintenance;Roll back to a previous paqet version"
"cleanup;clean;cleanup [--journal];Maintenance;Remove paqctl's old logs, temp files and backups"
"uninstall;;uninstall;Maintenance;Remove paqctl completely"
)
_PAQCTL_GROUPS=(General Service Diagnostics Configuration Security Maintenance)

# Canonical command name for a name or alias
_resolve_command() {
    local input="$1" entry name aliases a
    [ -n "$input" ] || return 1
    for entry in "${_PAQCTL_COMMANDS[@]}"; do
        IFS=';' read -r name aliases _ <<< "$entry"
        [ "$input" = "$name" ] && { echo "$name"; return 0; }
        for a in $aliases; do
            [ "$input" = "$a" ] && { echo "$name"; return 0; }
        done
    done
    return 1
}

_command_entry() {
    local want="$1" entry name
    for entry in "${_PAQCTL_COMMANDS[@]}"; do
        IFS=';' read -r name _ <<< "$entry"
        [ "$name" = "$want" ] && { echo "$entry"; return 0; }
    done
    return 1
}

# Every name and alias (used by completion)
_command_words() {
    local entry name aliases
    for entry in "${_PAQCTL_COMMANDS[@]}"; do
        IFS=';' read -r name aliases _ <<< "$entry"
        echo "$name"
        local a
        for a in $aliases; do
            [[ "$a" == -* ]] || echo "$a"
        done
    done
}

_command_names() {
    local entry name
    for entry in "${_PAQCTL_COMMANDS[@]}"; do
        IFS=';' read -r name _ <<< "$entry"
        echo "$name"
    done
}

_levenshtein() {
    local a="$1" b="$2" i j cost la=${#1} lb=${#2} del ins sub m
    local -a prev cur
    for ((j = 0; j <= lb; j++)); do prev[j]=$j; done
    for ((i = 1; i <= la; i++)); do
        cur=([0]=$i)
        for ((j = 1; j <= lb; j++)); do
            if [ "${a:i-1:1}" = "${b:j-1:1}" ]; then cost=0; else cost=1; fi
            del=$((prev[j] + 1)); ins=$((cur[j-1] + 1)); sub=$((prev[j-1] + cost))
            m=$del
            [ "$ins" -lt "$m" ] && m=$ins
            [ "$sub" -lt "$m" ] && m=$sub
            cur[j]=$m
        done
        prev=("${cur[@]}")
    done
    echo "${prev[lb]}"
}

# Closest command to a typo (prefix match first, then edit distance <= 2)
_suggest_command() {
    local input="$1" w best="" best_d=99 d
    [ -n "$input" ] || return 1
    local -a prefix_hits=()
    while IFS= read -r w; do
        [[ "$w" == "$input"* ]] && prefix_hits+=("$w")
    done < <(_command_words)
    if [ ${#prefix_hits[@]} -eq 1 ]; then
        _resolve_command "${prefix_hits[0]}"
        return 0
    fi
    while IFS= read -r w; do
        d=$(_levenshtein "$input" "$w")
        if [ "$d" -lt "$best_d" ]; then best_d=$d; best=$w; fi
    done < <(_command_words)
    if [ -n "$best" ] && [ "$best_d" -le 2 ] && [ "$best_d" -lt ${#input} ]; then
        _resolve_command "$best"
        return 0
    fi
    return 1
}

# Longer help text and examples for 'paqctl help <command>'
_command_details() {
    case "$1" in
        status)  echo "  Exit code is 0 whether or not the service runs; use --json and read \"running\"." ;;
        logs)    cat << 'EOF'
  Options:
    -n, --lines N      Number of lines to show (default 50)
    --no-follow        Print and exit (default when output is not a terminal)
    -f, --follow       Keep following new lines
    --since TIME       Only entries since TIME (systemd journal only), e.g. "1 hour ago"
    --backend NAME     paqet or gfk: read that backend's own log file if it has one
    --errors           Only lines that look like errors or warnings
  Examples:
    paqctl logs -n 200 --no-follow --errors
    paqctl logs --since "30 min ago"
EOF
            ;;
        health)  echo "  Exit code: 0 when every check passes, 1 when any check fails." ;;
        doctor)  cat << 'EOF'
  Runs the health checks plus extra ones (interface/IP/gateway drift, MTU,
  port conflicts, config/settings mismatch, disk, DNS) and prints a fix for
  each problem. --fix applies the safe fixes: re-adding firewall rules,
  regenerating config.yaml from settings.conf, starting the service and
  enabling auto-start. Exit code is 1 while any check still fails.
EOF
            ;;
        test)    cat << 'EOF'
  On a client, fetches a URL through the local SOCKS5 proxy and reports the
  exit IP, location, HTTP status and timing. Warns when the exit IP equals
  this machine's direct IP. In forward mode it checks the forward port.
  Default URL: https://www.cloudflare.com/cdn-cgi/trace
EOF
            ;;
        config)  cat << 'EOF'
  config                 Interactive wizard (needs a terminal)
  config show [--reveal] Print settings.conf (secrets masked unless --reveal; --json supported)
  config edit            Open config.yaml (or GFK parameters.py) in $EDITOR, validate, restart
  config set KEY=VALUE   Change settings, regenerate config and restart if running
  Settable keys:
    LISTEN_PORT SOCKS_PORT FORWARD_PORT REMOTE_SERVER FORWARD_TARGET INTERFACE
    LOCAL_IP GATEWAY_MAC ENCRYPTION_KEY PAQET_TCP_LOCAL_FLAG PAQET_TCP_REMOTE_FLAG
    ROUTING_MODE KCP_MODE KCP_MTU KCP_CONN KCP_SNDWND KCP_RCVWND GFK_SERVER_IP GFK_AUTH_CODE
    TELEGRAM_SERVER_LABEL EGRESS_GUARD EGRESS_ALLOW
  Examples:
    paqctl config set LISTEN_PORT=9443
    paqctl config set KCP_MTU=1200 SOCKS_PORT=1081
    paqctl config set KCP_MODE=fast2      (normal, fast, fast2, fast3 or manual)
  Egress guard (server): clients cannot reach this host's loopback, private
  networks or cloud metadata (169.254.169.254). Allow specific targets, e.g.
  for a client in forward mode whose target is a service on this server:
    paqctl config set EGRESS_ALLOW="127.0.0.1:80"
    paqctl config set EGRESS_ALLOW="127.0.0.1:8080, 10.0.0.0/8, [fd00::5]:443"
    paqctl config set EGRESS_GUARD=false  (not recommended)
  Egress changes apply immediately, without a restart.
EOF
            ;;
        export)  cat << 'EOF'
  The string contains your encryption key / auth code: share it privately.
  --ip ADDR   Address clients should use (default: configured IP; looks up the
              public IP via api.ipify.org only if nothing is configured)
  --qr        Also print a QR code (needs qrencode)
EOF
            ;;
        import)  cat << 'EOF'
  paqctl import 'paqet://...'     Import from an argument
  paqctl import - < string.txt    Read the string from stdin
  paqctl import                   Prompt for it
  The current configuration is backed up first; every field is validated.
EOF
            ;;
        rotate-key) echo "  Backs up the current config, generates a new secret, restarts the service and prints the new client string. Use -y to skip the confirmation." ;;
        ban)     cat << 'EOF'
  Bans are tagged "paqctl-ban", recorded in /opt/paqctl/banned_ips and
  re-applied whenever the service starts, so they survive restarts and reboots.
  Examples:
    paqctl ban 203.0.113.7
    paqctl ban 198.51.100.0/24
    paqctl ban 2001:db8::/32
    paqctl ban list            (add --json for machine-readable output)
EOF
            ;;
        restore) echo "  'latest' picks the newest backup, N picks the Nth newest. The current config is backed up first." ;;
        cleanup) echo "  Removes archived paqctl logs, stale temp files and old backups. --journal also vacuums the system-wide journal (all services) to 7 days." ;;
        watchdog) echo "  With no argument shows status. 'watchdog check' is what the timer runs; it skips if another paqctl command is in progress." ;;
        update)  echo "  Updates the paqet binary (or GFK scripts) and then the management script. Use -y to update without prompting." ;;
        completion) cat << 'EOF'
  bash:  paqctl completion bash | sudo tee /etc/bash_completion.d/paqctl
  zsh:   paqctl completion zsh  > "${fpath[1]}/_paqctl"
  (The installer sets up bash completion automatically.)
EOF
            ;;
    esac
}

show_help() {
    local topic="${1:-}"
    if [ -n "$topic" ]; then
        _show_command_help "$topic"
        return
    fi
    echo ""
    echo -e "${BOLD}paqctl${NC} - Paqet Manager v${VERSION}"
    echo ""
    echo -e "${BOLD}Usage:${NC} sudo paqctl <command> [options]"
    echo ""
    local group entry name aliases usage g summary
    for group in "${_PAQCTL_GROUPS[@]}"; do
        echo -e "${BOLD}${group}:${NC}"
        for entry in "${_PAQCTL_COMMANDS[@]}"; do
            IFS=';' read -r name aliases usage g summary <<< "$entry"
            [ "$g" = "$group" ] || continue
            printf "  %-13s %s\n" "$name" "$summary"
        done
        echo ""
    done
    echo -e "${BOLD}Global options:${NC}"
    echo "  -y, --yes     Answer yes to confirmation prompts (for scripts)"
    echo "  --json        Machine-readable output (status, info, health, doctor, export, config show, ban list)"
    echo "  --no-color    Disable colours (also NO_COLOR=1, or when output is not a terminal)"
    echo ""
    echo "Run 'paqctl help <command>' for options, aliases and examples."
    echo ""
    echo -e "${BOLD}Paqet:${NC} https://github.com/SamNet-dev/paqctl"
    echo ""
}

_show_command_help() {
    local cmd entry name aliases usage group summary
    if ! cmd=$(_resolve_command "$1"); then
        echo -e "${RED}Unknown command: $1${NC}" >&2
        local guess
        guess=$(_suggest_command "$1") && echo -e "Did you mean: ${BOLD}paqctl help ${guess}${NC} ?" >&2
        return 2
    fi
    entry=$(_command_entry "$cmd")
    IFS=';' read -r name aliases usage group summary <<< "$entry"
    echo ""
    echo -e "${BOLD}paqctl ${name}${NC} - ${summary}"
    echo ""
    echo -e "${BOLD}Usage:${NC} sudo paqctl ${usage}"
    [ -n "$aliases" ] && echo -e "${BOLD}Aliases:${NC} ${aliases}"
    local details
    details=$(_command_details "$name")
    if [ -n "$details" ]; then
        echo ""
        echo "$details"
    fi
    echo ""
}

_completion_bash() {
    local words names
    words=$(_command_words | tr '\n' ' ')
    names=$(_command_names | tr '\n' ' ')
    cat << EOF
# bash completion for paqctl (generated by paqctl ${VERSION})
_paqctl() {
    local cur prev sub i
    cur="\${COMP_WORDS[COMP_CWORD]}"
    prev="\${COMP_WORDS[COMP_CWORD-1]}"
    sub=""
    for ((i = 1; i < COMP_CWORD; i++)); do
        case "\${COMP_WORDS[i]}" in
            -y|--yes|--json|--no-color) ;;
            *) sub="\${COMP_WORDS[i]}"; break ;;
        esac
    done
    if [ -z "\$sub" ]; then
        COMPREPLY=( \$(compgen -W "${words}-y --yes --json --no-color" -- "\$cur") )
        return 0
    fi
    case "\$sub" in
        help) COMPREPLY=( \$(compgen -W "${names}" -- "\$cur") ) ;;
        watchdog) COMPREPLY=( \$(compgen -W "enable disable status" -- "\$cur") ) ;;
        logs)
            case "\$prev" in
                --backend) COMPREPLY=( \$(compgen -W "paqet gfk" -- "\$cur") ) ;;
                -n|--lines|--since) COMPREPLY=() ;;
                *) COMPREPLY=( \$(compgen -W "-n --no-follow --follow --since --backend --errors" -- "\$cur") ) ;;
            esac ;;
        config)
            if [ "\$prev" = "set" ] || [[ "\$cur" == *=* ]]; then
                COMPREPLY=( \$(compgen -W "LISTEN_PORT= SOCKS_PORT= FORWARD_PORT= REMOTE_SERVER= FORWARD_TARGET= INTERFACE= LOCAL_IP= GATEWAY_MAC= ENCRYPTION_KEY= PAQET_TCP_LOCAL_FLAG= PAQET_TCP_REMOTE_FLAG= ROUTING_MODE= KCP_MODE= KCP_MTU= KCP_CONN= KCP_SNDWND= KCP_RCVWND= GFK_SERVER_IP= GFK_AUTH_CODE= TELEGRAM_SERVER_LABEL= EGRESS_GUARD= EGRESS_ALLOW=" -- "\$cur") )
                compopt -o nospace 2>/dev/null
            else
                COMPREPLY=( \$(compgen -W "show edit set --reveal" -- "\$cur") )
            fi ;;
        ban) COMPREPLY=( \$(compgen -W "list" -- "\$cur") ) ;;
        restore) COMPREPLY=( \$(compgen -W "latest" -- "\$cur") \$(compgen -f -- "\$cur") ) ;;
        export|share|info|details|client)
            COMPREPLY=( \$(compgen -W "--ip --qr --json" -- "\$cur") ) ;;
        status|health) COMPREPLY=( \$(compgen -W "--json" -- "\$cur") ) ;;
        doctor) COMPREPLY=( \$(compgen -W "--fix --json" -- "\$cur") ) ;;
        cleanup|clean) COMPREPLY=( \$(compgen -W "--journal" -- "\$cur") ) ;;
        test) COMPREPLY=( \$(compgen -W "--url" -- "\$cur") ) ;;
        completion) COMPREPLY=( \$(compgen -W "bash zsh" -- "\$cur") ) ;;
        *) COMPREPLY=() ;;
    esac
}
complete -F _paqctl paqctl
EOF
}

show_completion() {
    case "${1:-bash}" in
        bash) _completion_bash ;;
        zsh)
            echo "#compdef paqctl"
            echo "autoload -U +X bashcompinit && bashcompinit"
            _completion_bash
            ;;
        *) log_error "Unsupported shell: $1 (use bash or zsh)"; return 2 ;;
    esac
}

#───────────────────────────────────────────────────────────────────────
# config show / edit / set
#───────────────────────────────────────────────────────────────────────
_SECRET_KEYS=" ENCRYPTION_KEY GFK_AUTH_CODE TELEGRAM_BOT_TOKEN "
_CONFIG_SET_KEYS="LISTEN_PORT SOCKS_PORT FORWARD_PORT REMOTE_SERVER FORWARD_TARGET INTERFACE LOCAL_IP GATEWAY_MAC ENCRYPTION_KEY PAQET_TCP_LOCAL_FLAG PAQET_TCP_REMOTE_FLAG ROUTING_MODE KCP_MODE KCP_MTU KCP_CONN KCP_SNDWND KCP_RCVWND GFK_SERVER_IP GFK_AUTH_CODE TELEGRAM_SERVER_LABEL EGRESS_GUARD EGRESS_ALLOW"

_mask_secret() {
    local s="$1"
    if [ ${#s} -le 8 ]; then printf '****'; else printf '%s****%s' "${s:0:4}" "${s: -2}"; fi
}

config_command() {
    case "${1:-}" in
        "")   change_config ;;
        show) shift; config_show "$@" ;;
        edit) shift; config_edit "$@" ;;
        set)  shift; config_set "$@" ;;
        *)
            log_error "Unknown config subcommand: $1"
            echo "  Usage: paqctl config [show [--reveal] | edit | set KEY=VALUE...]" >&2
            return 2
            ;;
    esac
}

config_show() {
    local reveal=false a
    for a in "$@"; do
        case "$a" in
            --reveal) reveal=true ;;
            *) log_error "Unknown option for config show: $a"; return 2 ;;
        esac
    done
    if [ ! -r "$INSTALL_DIR/settings.conf" ]; then
        log_error "No settings found at $INSTALL_DIR/settings.conf"
        return 1
    fi
    local k v first=true
    if [ "$JSON_OUTPUT" = true ]; then
        printf '{'
    else
        _print_section "CONFIGURATION (settings.conf)"
    fi
    while IFS='=' read -r k v; do
        [[ "$k" =~ ^[A-Z_][A-Z0-9_]*$ ]] || continue
        v="${v#\"}"; v="${v%\"}"
        if [[ "$_SECRET_KEYS" == *" $k "* ]] && [ "$reveal" != true ] && [ -n "$v" ]; then
            v=$(_mask_secret "$v")
        fi
        if [ "$JSON_OUTPUT" = true ]; then
            [ "$first" = true ] || printf ','
            first=false
            printf '%s:%s' "$(_json_str "$k")" "$(_json_str "$v")"
        else
            printf "  %-26s %s\n" "$k" "$v"
        fi
    done < "$INSTALL_DIR/settings.conf"
    if [ "$JSON_OUTPUT" = true ]; then
        printf '}\n'
    else
        echo ""
        [ "$reveal" = true ] || echo -e "  ${DIM}Secrets are masked; add --reveal to show them.${NC}"
        echo -e "  ${DIM}Change values with: sudo paqctl config set KEY=VALUE${NC}"
        echo ""
    fi
}

# _config_validate KEY VALUE -> 0 valid, 1 invalid, 3 unknown key
_config_validate() {
    local k="$1" v="$2"
    case "$k" in
        LISTEN_PORT|SOCKS_PORT|FORWARD_PORT) _validate_port "$v" ;;
        REMOTE_SERVER|FORWARD_TARGET) _valid_hostport "$v" ;;
        INTERFACE) _validate_iface "$v" ;;
        LOCAL_IP) _validate_ip "$v" ;;
        GATEWAY_MAC) _validate_mac "$v" ;;
        ENCRYPTION_KEY) [[ "$v" =~ ^[A-Za-z0-9+/=_-]{8,128}$ ]] ;;
        PAQET_TCP_LOCAL_FLAG|PAQET_TCP_REMOTE_FLAG) [[ "$v" =~ ^[FSRPAUEC]+(,[FSRPAUEC]+)*$ ]] ;;
        ROUTING_MODE) [ "$v" = "socks5" ] || [ "$v" = "forward" ] ;;
        KCP_MTU) [[ "$v" =~ ^[0-9]+$ ]] && [ "$v" -ge 500 ] && [ "$v" -le 9000 ] ;;
        KCP_MODE) [[ "$v" =~ ^(normal|fast|fast2|fast3|manual)$ ]] ;;
        KCP_CONN) [[ "$v" =~ ^[0-9]+$ ]] && [ "$v" -ge 1 ] && [ "$v" -le 64 ] ;;
        KCP_SNDWND|KCP_RCVWND) [[ "$v" =~ ^[0-9]+$ ]] && [ "$v" -ge 16 ] && [ "$v" -le 65535 ] ;;
        GFK_SERVER_IP) _validate_ip "$v" ;;   # GFK sends raw packets to it: IPv4 only
        GFK_AUTH_CODE) [[ "$v" =~ ^[A-Za-z0-9_-]{4,128}$ ]] ;;
        TELEGRAM_SERVER_LABEL) [[ "$v" =~ ^[A-Za-z0-9\ ._-]{1,64}$ ]] ;;
        EGRESS_GUARD) [ "$v" = true ] || [ "$v" = false ] ;;
        EGRESS_ALLOW) [ ${#v} -le 1024 ] && _egress_valid_allow "$v" ;;
        *) return 3 ;;
    esac
}

config_set() {
    if [ $# -eq 0 ]; then
        log_error "Usage: paqctl config set KEY=VALUE [KEY=VALUE...]   (see: paqctl help config)"
        return 2
    fi
    local -a keys=() vals=()
    local pair k v rc
    for pair in "$@"; do
        if [[ "$pair" != *=* ]]; then
            log_error "Expected KEY=VALUE, got: $pair"
            return 2
        fi
        k="${pair%%=*}"; v="${pair#*=}"
        k="${k^^}"
        rc=0
        _config_validate "$k" "$v" || rc=$?
        if [ "$rc" -eq 3 ]; then
            log_error "Unknown or read-only setting: $k"
            echo "  Settable keys: $_CONFIG_SET_KEYS" >&2
            return 2
        elif [ "$rc" -ne 0 ]; then
            log_error "Invalid value for $k: $v"
            return 2
        fi
        keys+=("$k"); vals+=("$v")
    done

    local needs_restart=false touches_paqet=false touches_gfk=false touches_egress=false i
    for k in "${keys[@]}"; do
        case "$k" in
            TELEGRAM_SERVER_LABEL) ;;
            EGRESS_*) touches_egress=true ;;
            GFK_*) touches_gfk=true; needs_restart=true ;;
            *) touches_paqet=true; needs_restart=true ;;
        esac
    done

    local bk
    bk=$(backup_config --quiet --label pre-config 2>/dev/null) && log_info "Previous configuration backed up to: $bk"

    local was_running=false
    if [ "$needs_restart" = true ] && is_running; then
        was_running=true
        # Stop first so firewall rules for the old port are removed
        stop_paqet
    fi

    local old shown_old shown_new
    for ((i = 0; i < ${#keys[@]}; i++)); do
        k="${keys[$i]}"; v="${vals[$i]}"
        old="${!k:-}"
        printf -v "$k" '%s' "$v"
        shown_old="$old"; shown_new="$v"
        if [[ "$_SECRET_KEYS" == *" $k "* ]]; then
            shown_old=$(_mask_secret "$old"); shown_new=$(_mask_secret "$v")
        fi
        log_info "${k}: ${shown_old:-<empty>} → ${shown_new}"
    done

    local result=0
    if ! save_settings; then
        log_error "Failed to save settings"
        result=1
    fi
    if [ "$result" -eq 0 ] && [ "$touches_paqet" = true ] && _paqet_installed; then
        _write_paqet_config || result=1
    fi
    if [ "$result" -eq 0 ] && [ "$touches_gfk" = true ] && _gfk_installed; then
        generate_gfk_config || result=1
    fi
    [ "$result" -eq 0 ] && log_success "Configuration updated"

    # The egress guard is rebuilt in place (start_paqet below rebuilds it anyway)
    if [ "$result" -eq 0 ] && [ "$touches_egress" = true ] && [ "$was_running" != true ] && [ "$ROLE" = "server" ]; then
        local eg_rc=0
        _egress_guard_apply || eg_rc=$?
        case "$eg_rc" in
            0) if _egress_guard_wanted; then log_success "Egress guard updated"; else log_warn "Egress guard removed: clients can reach this host's private networks"; fi ;;
            2) log_info "Egress guard will be installed when paqet starts." ;;
            *) log_error "Could not update the egress guard"; result=1 ;;
        esac
    fi

    if [ "$was_running" = true ]; then
        start_paqet || result=1
    elif [ "$needs_restart" = true ]; then
        log_info "Service is not running; changes apply on next start."
    fi
    return $result
}

config_edit() {
    local file kind
    if [ "$BACKEND" = "gfw-knocker" ]; then
        file="$GFK_DIR/parameters.py"; kind="python"
    else
        file="$INSTALL_DIR/config.yaml"; kind="yaml"
    fi
    if [ ! -f "$file" ]; then
        log_error "$file does not exist. Create it with: sudo paqctl config"
        return 1
    fi
    if ! _has_tty; then
        log_error "config edit needs a terminal. Use 'paqctl config set KEY=VALUE' in scripts."
        return 1
    fi
    local editor="${VISUAL:-${EDITOR:-}}" e
    if [ -z "$editor" ]; then
        for e in nano vim vi; do
            command -v "$e" &>/dev/null && { editor="$e"; break; }
        done
    fi
    [ -n "$editor" ] || { log_error "No editor found. Set EDITOR, e.g.: sudo EDITOR=nano paqctl config edit"; return 1; }

    local tmp
    tmp=$(mktemp "${file}.XXXXXXXX") || { log_error "Failed to create temp file"; return 1; }
    chmod 600 "$tmp"
    cp -p "$file" "$tmp"
    # shellcheck disable=SC2086
    $editor "$tmp" < /dev/tty > /dev/tty
    if cmp -s "$file" "$tmp"; then
        rm -f "$tmp"
        log_info "No changes made"
        return 0
    fi

    local valid=true
    if [ "$kind" = "yaml" ]; then
        if command -v python3 &>/dev/null && python3 -c 'import yaml' 2>/dev/null; then
            python3 -c 'import sys, yaml; yaml.safe_load(open(sys.argv[1]))' "$tmp" 2>/dev/null || valid=false
        fi
        grep -qE '^role:[[:space:]]*"?(server|client)"?' "$tmp" || valid=false
    else
        if command -v python3 &>/dev/null; then
            python3 -c 'import ast, sys; ast.parse(open(sys.argv[1]).read())' "$tmp" 2>/dev/null || valid=false
        fi
    fi
    if [ "$valid" != true ]; then
        log_error "The edited file does not look valid; nothing was changed."
        log_error "Your edited copy is kept at: $tmp"
        return 1
    fi

    local bk
    bk=$(backup_config --quiet --label pre-edit 2>/dev/null) && log_info "Previous configuration backed up to: $bk"
    mv -f "$tmp" "$file" && chmod 600 "$file"
    log_success "Saved $file"
    echo -e "  ${DIM}Note: 'config', 'config set', 'tune', 'import' and 'rotate-key' regenerate this file from settings.conf and overwrite manual edits.${NC}"
    if is_running && _confirm "Restart now to apply the changes?"; then
        restart_paqet
    fi
}

#───────────────────────────────────────────────────────────────────────
# End-to-end test through the tunnel (client side)
#───────────────────────────────────────────────────────────────────────
run_e2e_test() {
    local url="https://www.cloudflare.com/cdn-cgi/trace"
    while [ $# -gt 0 ]; do
        case "$1" in
            --url) [ -n "${2:-}" ] || { log_error "--url needs a value"; return 2; }; url="$2"; shift 2 ;;
            --url=*) url="${1#--url=}"; shift ;;
            *) log_error "Unknown option for test: $1"; echo "  Usage: paqctl test [--url URL]" >&2; return 2 ;;
        esac
    done
    [[ "$url" =~ ^https?:// ]] || { log_error "URL must start with http:// or https://"; return 2; }
    command -v curl &>/dev/null || { log_error "curl is required"; return 1; }
    _print_section "END-TO-END TEST"

    if [ "$ROLE" = "server" ]; then
        log_info "This machine is a server; run 'paqctl test' on a client to test the tunnel."
        log_info "Checking this server's own outbound connectivity instead..."
        local direct pub_ip
        if direct=$(curl -s --max-time 10 "$url"); then
            pub_ip=$(echo "$direct" | sed -n 's/^ip=//p' | head -1)
            log_success "Outbound HTTPS works${pub_ip:+ (public IP: $pub_ip)}"
            return 0
        fi
        log_error "Could not reach $url from this server"
        return 1
    fi

    if ! is_running; then
        log_error "paqctl is not running. Start it with: sudo paqctl start"
        return 1
    fi

    local port
    if [ "$BACKEND" = "gfw-knocker" ]; then
        port=$(_gfk_client_socks_port)
    elif [ "${ROUTING_MODE:-socks5}" = "forward" ]; then
        local fport="${FORWARD_PORT:-14000}"
        log_info "Forward mode: checking that 127.0.0.1:${fport} accepts connections..."
        if timeout 5 bash -c "exec 3<>/dev/tcp/127.0.0.1/${fport}" 2>/dev/null; then
            log_success "Forward port ${fport} accepts connections (target: ${FORWARD_TARGET:-127.0.0.1:80})"
            return 0
        fi
        log_error "Nothing is accepting connections on 127.0.0.1:${fport}"
        return 1
    else
        port="${SOCKS_PORT:-1080}"
    fi

    log_info "Fetching $url through SOCKS5 127.0.0.1:${port}..."
    local out rc=0
    out=$(curl -s --max-time 20 --socks5-hostname "127.0.0.1:${port}" \
        -w $'\n__PAQCTL__ %{http_code} %{time_connect} %{time_total}' "$url" 2>&1) || rc=$?
    if [ "$rc" -ne 0 ]; then
        log_error "Request through the tunnel failed (curl exit code $rc)"
        echo -e "  ${DIM}Next steps: sudo paqctl doctor   |   sudo paqctl logs --errors --no-follow${NC}"
        return 1
    fi
    local meta body code total exit_ip loc
    meta=$(echo "$out" | grep '^__PAQCTL__' | tail -1)
    body=$(echo "$out" | grep -v '^__PAQCTL__')
    code=$(echo "$meta" | awk '{print $2}')
    total=$(echo "$meta" | awk '{print $4}')
    exit_ip=$(echo "$body" | sed -n 's/^ip=//p' | head -1)
    loc=$(echo "$body" | sed -n 's/^loc=//p' | head -1)

    if ! [[ "$code" =~ ^[23] ]]; then
        log_error "Tunnel reached the site but got HTTP ${code:-?}"
        return 1
    fi
    log_success "Tunnel works: HTTP ${code} in ${total}s"
    [ -n "$exit_ip" ] && echo -e "  Exit IP:   ${BOLD}${exit_ip}${NC}${loc:+ (${loc})}"

    if [ -n "$exit_ip" ]; then
        local direct_ip
        direct_ip=$(curl -s --max-time 5 "$url" 2>/dev/null | sed -n 's/^ip=//p' | head -1)
        if [ -n "$direct_ip" ] && [ "$direct_ip" = "$exit_ip" ]; then
            log_warn "The exit IP equals this machine's direct IP - traffic may not be going through the tunnel."
        elif [ -n "$direct_ip" ]; then
            echo -e "  Direct IP: ${direct_ip} ${DIM}(different from the exit IP, as expected)${NC}"
        fi
    fi
    echo ""
}

#───────────────────────────────────────────────────────────────────────
# Start/stop every installed backend, reporting partial failures
#───────────────────────────────────────────────────────────────────────
_start_all() {
    local -a failed=()
    local any=false
    if _paqet_installed; then any=true; start_paqet_backend || failed+=(paqet); fi
    if _gfk_installed; then any=true; start_gfk_backend || failed+=(gfk); fi
    if [ "$any" != true ]; then
        log_error "No backends are installed"
        return 1
    fi
    if [ ${#failed[@]} -gt 0 ]; then
        log_error "Failed to start: ${failed[*]}"
        return 1
    fi
}

_stop_all() {
    local -a failed=()
    if _paqet_installed; then stop_paqet_backend || failed+=(paqet); fi
    if _gfk_installed; then stop_gfk_backend || failed+=(gfk); fi
    if [ ${#failed[@]} -gt 0 ]; then
        log_error "Failed to stop: ${failed[*]}"
        return 1
    fi
}

show_version() {
    echo ""
    echo -e "  paqctl version:  ${BOLD}${VERSION}${NC}"
    if [ "$BACKEND" = "gfw-knocker" ]; then
        echo -e "  backend:         ${BOLD}gfw-knocker${NC}"
        local py_ver; py_ver=$(python3 --version 2>/dev/null || echo "unknown")
        echo -e "  python:          ${BOLD}${py_ver}${NC}"
    else
        echo -e "  paqet version:   ${BOLD}${PAQET_VERSION}${NC}"
        local bin_ver
        bin_ver=$("$INSTALL_DIR/bin/paqet" version 2>/dev/null || echo "unknown")
        echo -e "  paqet binary:    ${BOLD}${bin_ver}${NC}"
        if echo "$PAQET_VERSION" | grep -qi "alpha\|beta\|rc"; then
            echo ""
            echo -e "  ${YELLOW}Note: paqet is in alpha phase — expect breaking changes between versions.${NC}"
        fi
    fi
    echo ""
    echo -e "  ${DIM}paqctl by SamNet-dev: https://github.com/SamNet-dev/paqctl${NC}"
    echo ""
}
