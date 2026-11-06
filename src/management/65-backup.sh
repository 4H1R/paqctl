#═══════════════════════════════════════════════════════════════════════
# Backup & Restore
#═══════════════════════════════════════════════════════════════════════

# Files (relative to $INSTALL_DIR) that make up a paqctl configuration
_BACKUP_FILES=(config.yaml settings.conf banned_ips gfk/parameters.py gfk/cert.pem gfk/key.pem bin/gfk-client.sh)
PAQCTL_BACKUP_KEEP="${PAQCTL_BACKUP_KEEP:-10}"

# Newest first
_list_backups() {
    [ -d "$BACKUP_DIR" ] || return 0
    ls -1t "$BACKUP_DIR"/paqctl-backup-*.tar.gz 2>/dev/null || true
}

_prune_backups() {
    local keep="$PAQCTL_BACKUP_KEEP" f n=0 removed=0
    [[ "$keep" =~ ^[0-9]+$ ]] && [ "$keep" -ge 1 ] || keep=10
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        n=$((n + 1))
        if [ "$n" -gt "$keep" ]; then
            rm -f "$f" && removed=$((removed + 1))
        fi
    done < <(_list_backups)
    echo "$removed"
}

# backup_config [--quiet] [--label NAME] [--no-prune]
# Prints the backup path on stdout when --quiet is given.
backup_config() {
    local quiet=false label="" prune=true
    while [ $# -gt 0 ]; do
        case "$1" in
            --quiet) quiet=true; shift ;;
            --label) label="${2:-}"; shift 2 ;;
            --no-prune) prune=false; shift ;;
            *) log_error "Unknown option for backup: $1"; return 2 ;;
        esac
    done
    (umask 077; mkdir -p "$BACKUP_DIR")
    chmod 700 "$BACKUP_DIR" 2>/dev/null

    local -a members=()
    local m
    for m in "${_BACKUP_FILES[@]}"; do
        [ -f "$INSTALL_DIR/$m" ] && members+=("$m")
    done
    if [ ${#members[@]} -eq 0 ]; then
        log_error "Nothing to back up (no configuration files found in $INSTALL_DIR)"
        return 1
    fi

    local ts backup_file i=1
    ts=$(date +%Y%m%d%H%M%S)
    [[ "$label" =~ ^[a-z0-9-]+$ ]] && ts="${ts}-${label}"
    backup_file="$BACKUP_DIR/paqctl-backup-${ts}.tar.gz"
    while [ -e "$backup_file" ]; do
        backup_file="$BACKUP_DIR/paqctl-backup-${ts}-${i}.tar.gz"
        i=$((i + 1))
    done

    if ! (umask 077; tar -czf "$backup_file" -C "$INSTALL_DIR" "${members[@]}" 2>/dev/null); then
        log_error "Failed to create backup archive"
        rm -f "$backup_file"
        return 1
    fi
    local pruned=0
    [ "$prune" = true ] && pruned=$(_prune_backups)

    if [ "$quiet" = true ]; then
        echo "$backup_file"
    else
        echo ""
        log_success "Backup saved to: $backup_file"
        echo -e "  ${DIM}Contains: ${members[*]}${NC}"
        [ "$pruned" -gt 0 ] 2>/dev/null && echo -e "  ${DIM}Removed $pruned old backup(s); keeping the newest ${PAQCTL_BACKUP_KEEP}.${NC}"
        echo ""
    fi
}

# Refuse archives containing anything other than known config files
_backup_members_ok() {
    local archive="$1" entry allowed ok
    local listing
    listing=$(tar -tzf "$archive" 2>/dev/null) || return 1
    [ -n "$listing" ] || return 1
    while IFS= read -r entry; do
        entry="${entry#./}"
        [ -z "$entry" ] && continue
        ok=false
        for allowed in "${_BACKUP_FILES[@]}" gfk/ bin/; do
            [ "$entry" = "$allowed" ] && { ok=true; break; }
        done
        if [ "$ok" != true ]; then
            log_error "Backup contains an unexpected file: $entry"
            return 1
        fi
    done <<< "$listing"
}

# restore_config [FILE | latest | N]
restore_config() {
    echo ""
    local -a backups=()
    local f
    while IFS= read -r f; do [ -n "$f" ] && backups+=("$f"); done < <(_list_backups)

    local selected="" arg="${1:-}"
    if [ -n "$arg" ]; then
        if [ "$arg" = "latest" ]; then
            [ ${#backups[@]} -gt 0 ] || { log_warn "No backups found in $BACKUP_DIR"; return 1; }
            selected="${backups[0]}"
        elif [[ "$arg" =~ ^[0-9]+$ ]]; then
            if [ "$arg" -lt 1 ] || [ "$arg" -gt ${#backups[@]} ]; then
                log_error "No backup #$arg (have ${#backups[@]}; newest is #1)"
                return 1
            fi
            selected="${backups[$((arg - 1))]}"
        elif [ -f "$arg" ]; then
            selected="$arg"
        elif [ -f "$BACKUP_DIR/$arg" ]; then
            selected="$BACKUP_DIR/$arg"
        else
            log_error "Backup not found: $arg"
            return 1
        fi
    else
        if [ ${#backups[@]} -eq 0 ]; then
            log_warn "No backups found in $BACKUP_DIR"
            return 1
        fi
        if ! _has_tty; then
            log_error "No terminal for interactive selection. Use: paqctl restore latest | paqctl restore <file>"
            return 1
        fi
        echo -e "${BOLD}Available backups (newest first):${NC}"
        echo ""
        local i=1
        for f in "${backups[@]}"; do
            echo "  $i. $(basename "$f")"
            i=$((i + 1))
        done
        echo ""
        echo "  0. Cancel"
        echo ""
        local choice
        read -r -p "  Select backup [0-${#backups[@]}]: " choice < /dev/tty || true
        if [ "$choice" = "0" ] || [ -z "$choice" ]; then
            log_info "Cancelled"
            return 0
        fi
        if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt ${#backups[@]} ]; then
            log_error "Invalid choice"
            return 1
        fi
        selected="${backups[$((choice - 1))]}"
    fi

    if ! _backup_members_ok "$selected"; then
        log_error "Refusing to restore $(basename "$selected"): not a valid paqctl backup"
        return 1
    fi

    _confirm "Restore $(basename "$selected")? Your current configuration is backed up first." || { log_info "Cancelled"; return 1; }

    # Safety net. No pruning here so the archive being restored is never removed.
    local safety
    if safety=$(backup_config --quiet --label pre-restore --no-prune 2>/dev/null); then
        log_info "Current configuration saved to: $safety"
    fi

    log_info "Restoring from: $(basename "$selected")"
    local was_running=false
    is_running && was_running=true
    [ "$was_running" = true ] && stop_paqet

    if ! (umask 077; tar -xzf "$selected" -C "$INSTALL_DIR" 2>/dev/null); then
        log_error "Failed to extract backup archive"
        [ "$was_running" = true ] && start_paqet
        return 1
    fi
    local m
    for m in "${_BACKUP_FILES[@]}"; do
        [ -f "$INSTALL_DIR/$m" ] || continue
        chown root:root "$INSTALL_DIR/$m" 2>/dev/null
        case "$m" in
            bin/*) chmod 700 "$INSTALL_DIR/$m" 2>/dev/null ;;
            *) chmod 600 "$INSTALL_DIR/$m" 2>/dev/null ;;
        esac
    done

    _load_settings
    _prune_backups >/dev/null
    log_success "Configuration restored"

    if [ "$was_running" = true ]; then
        start_paqet || return 1
    fi
}
