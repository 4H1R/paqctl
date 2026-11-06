#═══════════════════════════════════════════════════════════════════════
# CLI Command Router
#═══════════════════════════════════════════════════════════════════════

_main() {
    local input="${1:-menu}" cmd
    case "$input" in
        # Internal hooks used by the service units
        _apply-firewall)  _require_root || return 1; _apply_firewall; return ;;
        _remove-firewall) _require_root || return 1; _remove_firewall; return ;;
        # Hidden: list command words (completion/tests)
        commands) _command_words; return 0 ;;
    esac

    if ! cmd=$(_resolve_command "$input"); then
        echo -e "${RED}Unknown command: ${input}${NC}" >&2
        local guess
        if guess=$(_suggest_command "$input"); then
            echo -e "Did you mean: ${BOLD}paqctl ${guess}${NC} ?" >&2
        fi
        echo "Run 'paqctl help' for the list of commands." >&2
        return 2
    fi
    [ $# -gt 0 ] && shift

    case "$cmd" in
        help|version|completion) ;;
        *) _require_root || return 1 ;;
    esac

    # Serialise commands that change state (the watchdog skips instead of waiting)
    case "$cmd" in
        start|stop|restart|start-paqet|stop-paqet|start-gfk|stop-gfk|start-all|stop-all|\
        update|self-update|rollback|import|rotate-key|restore|ban|unban|turbo|turbo-off|\
        tune|cleanup|uninstall|enable|disable)
            _acquire_lock || return 1 ;;
        config)
            [ "${1:-}" = "show" ] || { _acquire_lock || return 1; } ;;
        watchdog)
            case "${1:-status}" in
                check) _acquire_lock nowait || return 0 ;;
                enable|disable) _acquire_lock || return 1 ;;
            esac ;;
        doctor)
            case " $* " in *" --fix "*) _acquire_lock || return 1 ;; esac ;;
    esac

    case "$cmd" in
        menu)        show_menu ;;
        status)      show_status ;;
        info)        show_connection_info "$@" ;;
        help)        show_help "$@" ;;
        version)     show_version ;;
        completion)  show_completion "$@" ;;
        start)       start_paqet ;;
        stop)        stop_paqet ;;
        restart)     restart_paqet ;;
        start-paqet) start_paqet_backend ;;
        stop-paqet)  stop_paqet_backend ;;
        start-gfk)   start_gfk_backend ;;
        stop-gfk)    stop_gfk_backend ;;
        start-all)   _start_all ;;
        stop-all)    _stop_all ;;
        enable)      _set_boot enable ;;
        disable)     _set_boot disable ;;
        watchdog)
            case "${1:-status}" in
                enable|disable|status|check) manage_watchdog "${1:-status}" ;;
                *) log_error "Usage: paqctl watchdog [enable|disable|status]"; return 2 ;;
            esac ;;
        health)      health_check ;;
        doctor)      run_doctor "$@" ;;
        test)        run_e2e_test "$@" ;;
        logs)        show_logs "$@" ;;
        ping)        run_ping ;;
        dump)        run_dump ;;
        monitor)     show_active_clients ;;
        speedtest)   run_speedtest ;;
        routing)     check_proxy_routing ;;
        config)      config_command "$@" ;;
        export)      export_config_string "$@" ;;
        import)      import_config_string "$@" ;;
        rotate-key)  rotate_key ;;
        secret)      generate_secret ;;
        tune)        tune_menu ;;
        turbo)       apply_turbo_mode ;;
        turbo-off)   remove_turbo_mode ;;
        telegram)    show_telegram_menu ;;
        firewall)    show_firewall ;;
        ban)         manage_ip_ban ban "${1:-}" ;;
        unban)       manage_ip_ban unban "${1:-}" ;;
        backup)      backup_config "$@" ;;
        restore)     restore_config "$@" ;;
        update)      update_paqet ;;
        self-update) update_management_script ;;
        rollback)    rollback_paqet ;;
        cleanup)     system_cleanup "$@" ;;
        uninstall)   uninstall_paqctl ;;
        *)
            # A registry entry without a handler is a bug
            log_error "Command '$cmd' is registered but not implemented"
            return 70
            ;;
    esac
}

# Tests source this file with PAQCTL_SOURCE_ONLY=1 to reach the functions
if [ "${PAQCTL_SOURCE_ONLY:-}" != "1" ]; then
    _main "$@"
    exit $?
fi
