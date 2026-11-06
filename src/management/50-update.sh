#═══════════════════════════════════════════════════════════════════════
# Update
#═══════════════════════════════════════════════════════════════════════

update_gfk() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  UPDATE GFW-KNOCKER${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""

    log_info "Downloading latest GFW-knocker scripts..."
    local tmp_dir
    tmp_dir=$(mktemp -d)
    local server_files="mainserver.py quic_server.py vio_server.py"
    local client_files="mainclient.py quic_client.py vio_client.py"
    local f changed=false
    # Download server scripts
    for f in $server_files; do
        if ! curl -sL "$GFK_RAW_URL/server/$f" -o "$tmp_dir/$f"; then
            log_error "Failed to download $f"
            rm -rf "$tmp_dir"
            return 1
        fi
        if ! diff -q "$tmp_dir/$f" "$GFK_DIR/$f" &>/dev/null; then
            changed=true
        fi
    done
    # Download client scripts
    for f in $client_files; do
        if ! curl -sL "$GFK_RAW_URL/client/$f" -o "$tmp_dir/$f"; then
            log_error "Failed to download $f"
            rm -rf "$tmp_dir"
            return 1
        fi
        if ! diff -q "$tmp_dir/$f" "$GFK_DIR/$f" &>/dev/null; then
            changed=true
        fi
    done

    if [ "$changed" = true ]; then
        local was_running=false
        is_running && was_running=true
        [ "$was_running" = true ] && stop_paqet

        # Backup old scripts
        mkdir -p "$BACKUP_DIR"
        local all_files="$server_files $client_files"
        for f in $all_files; do
            [ -f "$GFK_DIR/$f" ] && cp "$GFK_DIR/$f" "$BACKUP_DIR/${f}.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true
        done

        for f in $all_files; do
            cp "$tmp_dir/$f" "$GFK_DIR/$f"
        done
        chmod 600 "$GFK_DIR"/*.py
        # Patch mainserver.py to use venv python for subprocesses
        [ -f "$GFK_DIR/mainserver.py" ] && sed -i "s|'python3'|'$INSTALL_DIR/venv/bin/python'|g" "$GFK_DIR/mainserver.py"
        log_success "GFW-knocker scripts updated"

        # Also upgrade Python deps in venv
        "$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade scapy aioquic 2>/dev/null || true

        [ "$was_running" = true ] && start_paqet
    else
        log_success "GFW-knocker scripts are already up to date"
        "$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade scapy aioquic 2>/dev/null || true
    fi
    rm -rf "$tmp_dir"

    # Regenerate client wrapper (removes legacy microsocks startup)
    if [ "$ROLE" = "client" ]; then
        create_gfk_client_wrapper
        pkill -f "${INSTALL_DIR}/bin/microsocks" 2>/dev/null || true
    fi

    # Also check for management script updates
    update_management_script
    echo ""
}

update_paqet() {
    if [ "$BACKEND" = "gfw-knocker" ]; then
        update_gfk
        return
    fi

    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  UPDATE PAQET${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""

    log_info "Querying GitHub for latest release..."

    # Get latest version from GitHub with retry
    local response
    response=$(_curl_with_retry "$PAQET_API_URL" 3)
    if [ -z "$response" ]; then
        log_error "Failed to query GitHub API after retries. Check your internet connection."
        return 1
    fi

    local latest_tag
    latest_tag=$(echo "$response" | grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | grep -o '"[^"]*"$' | tr -d '"')
    if [ -z "$latest_tag" ] || ! _validate_version_tag "$latest_tag"; then
        log_error "Could not determine valid version from GitHub"
        return 1
    fi

    # Extract release date
    local release_date
    release_date=$(echo "$response" | grep -o '"published_at"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | grep -o '"[^"]*"$' | tr -d '"' | cut -dT -f1)

    # Extract release notes (body field)
    local release_notes=""
    if command -v python3 &>/dev/null; then
        release_notes=$(python3 -c "
import json,sys
try:
    d=json.loads(sys.stdin.read())
    body=d.get('body','')
    if body:
        # Truncate to first 500 chars, strip markdown
        body=body[:500].replace('**','').replace('##','').replace('# ','')
        print(body)
except: pass
" <<< "$response" 2>/dev/null)
    fi

    local current="${PAQET_VERSION:-unknown}"
    local bin_ver
    bin_ver=$("$INSTALL_DIR/bin/paqet" version 2>/dev/null || echo "unknown")

    echo ""
    echo -e "  ${DIM}── Version Info ──${NC}"
    echo -e "  Installed version:  ${BOLD}${current}${NC}"
    echo -e "  Binary reports:     ${BOLD}${bin_ver}${NC}"
    echo -e "  Latest release:     ${BOLD}${latest_tag}${NC}"
    [ -n "$release_date" ] && echo -e "  Release date:       ${release_date}"

    if [ "$current" = "$latest_tag" ]; then
        echo ""
        log_success "You are already on the latest version!"
        if [ "$ASSUME_YES" = true ] || ! _has_tty; then
            update_management_script
            return
        fi
        echo ""
        echo -e "  ${DIM}Options:${NC}"
        echo "  1. Force reinstall current version"
        echo "  2. Rollback to previous version"
        echo "  3. Update management script only"
        echo "  b. Back"
        echo ""
        read -p "  Choice: " up_choice < /dev/tty || true
        case "$up_choice" in
            1)
                _confirm "Force reinstall ${current}?" || { log_info "Cancelled"; return 0; }
                ;;
            2) rollback_paqet; return ;;
            3) update_management_script; return ;;
            [bB]) return 0 ;;
            *) return 0 ;;
        esac
    fi

    # Show release notes if available
    if [ -n "$release_notes" ]; then
        echo ""
        echo -e "  ${DIM}── Release Notes ──${NC}"
        echo "$release_notes" | while IFS= read -r line; do
            echo -e "  ${DIM}${line}${NC}"
        done
        echo ""
    fi

    echo ""
    echo -e "${YELLOW}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║  ${BOLD}⚠ WARNING: Updating may cause compatibility issues!${NC}${YELLOW}            ║${NC}"
    echo -e "${YELLOW}╠════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${YELLOW}║${NC}  paqctl was tested with: ${BOLD}${PAQET_VERSION_PINNED}${NC}"
    echo -e "${YELLOW}║${NC}  Newer versions may have breaking changes or bugs."
    echo -e "${YELLOW}║${NC}  You can rollback with: ${BOLD}sudo paqctl rollback${NC}"
    echo -e "${YELLOW}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    if ! _confirm "Update to ${latest_tag}?"; then
        log_info "Update cancelled"
        return 1
    fi

    # Download new binary
    _download_and_install_binary "$latest_tag" || return 1

    # Check for management script update
    update_management_script
}

_download_and_install_binary() {
    local target_tag="$1"
    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64|amd64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *) log_error "Unsupported architecture: $arch"; return 1 ;;
    esac

    local filename="paqet-linux-${arch}-${target_tag}.tar.gz"
    local url="https://github.com/${PAQET_REPO}/releases/download/${target_tag}/${filename}"
    local tmp_file
    tmp_file=$(mktemp "/tmp/paqet-update-XXXXXXXX.tar.gz")

    log_info "Downloading ${filename}..."
    if ! curl -sL --max-time 120 --fail -o "$tmp_file" "$url"; then
        log_error "Download failed: $url"
        rm -f "$tmp_file"
        return 1
    fi

    # Validate
    local fsize
    fsize=$(stat -c%s "$tmp_file" 2>/dev/null || stat -f%z "$tmp_file" 2>/dev/null || wc -c < "$tmp_file" 2>/dev/null || echo 0)
    if [ "$fsize" -lt 1000 ]; then
        log_error "Downloaded file too small ($fsize bytes). Aborting."
        rm -f "$tmp_file"
        return 1
    fi

    # Extract
    local tmp_extract
    tmp_extract=$(mktemp -d "/tmp/paqet-update-extract-XXXXXXXX")
    if ! tar -xzf "$tmp_file" -C "$tmp_extract" 2>/dev/null; then
        log_error "Failed to extract archive"
        rm -f "$tmp_file"
        rm -rf "$tmp_extract"
        return 1
    fi

    local binary_name="paqet_linux_${arch}"
    local found_binary
    found_binary=$(find "$tmp_extract" -name "$binary_name" -type f 2>/dev/null | head -1)
    [ -z "$found_binary" ] && found_binary=$(find "$tmp_extract" -name "paqet*" -type f -executable 2>/dev/null | head -1)
    [ -z "$found_binary" ] && found_binary=$(find "$tmp_extract" -name "paqet*" -type f 2>/dev/null | head -1)

    if [ -z "$found_binary" ]; then
        log_error "Could not find paqet binary in archive"
        rm -f "$tmp_file"
        rm -rf "$tmp_extract"
        return 1
    fi

    # Stop service, replace, start
    local was_running=false
    if is_running; then
        was_running=true
        stop_paqet
    fi

    # Backup old binary with version tag for rollback
    if ! mkdir -p "$BACKUP_DIR"; then
        log_warn "Failed to create backup directory"
    fi
    local old_ver="${PAQET_VERSION:-unknown}"
    cp "$INSTALL_DIR/bin/paqet" "$BACKUP_DIR/paqet.${old_ver}.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true

    if ! cp "$found_binary" "$INSTALL_DIR/bin/paqet"; then
        log_error "Failed to copy new binary"
        rm -f "$tmp_file"
        rm -rf "$tmp_extract"
        # Restore from backup
        local latest_backup
        latest_backup=$(ls -t "$BACKUP_DIR"/paqet.* 2>/dev/null | head -1)
        [ -n "$latest_backup" ] && cp "$latest_backup" "$INSTALL_DIR/bin/paqet" && chmod +x "$INSTALL_DIR/bin/paqet"
        [ "$was_running" = true ] && start_paqet
        return 1
    fi
    chmod +x "$INSTALL_DIR/bin/paqet"

    rm -f "$tmp_file"
    rm -rf "$tmp_extract"

    # Verify the new binary works
    if ! "$INSTALL_DIR/bin/paqet" version &>/dev/null; then
        log_warn "New binary failed verification. Restoring backup..."
        local latest_backup
        latest_backup=$(ls -t "$BACKUP_DIR"/paqet.* 2>/dev/null | head -1)
        if [ -n "$latest_backup" ]; then
            cp "$latest_backup" "$INSTALL_DIR/bin/paqet"
            chmod +x "$INSTALL_DIR/bin/paqet"
            log_error "Update failed — previous version restored"
            return 1
        fi
        log_error "Update failed and no backup available"
        return 1
    fi

    # Update version in settings
    PAQET_VERSION="$target_tag"
    _safe_update_setting "PAQET_VERSION" "$target_tag" "$INSTALL_DIR/settings.conf"

    log_success "paqet updated to ${target_tag}"

    if [ "$was_running" = true ]; then
        start_paqet
    fi
}

rollback_paqet() {
    echo ""
    if [ ! -d "$BACKUP_DIR" ]; then
        log_warn "No backups found"
        return 1
    fi

    local backups=()
    local i=1
    echo -e "  ${BOLD}Available binary backups:${NC}"
    echo ""
    for f in "$BACKUP_DIR"/paqet.*; do
        [ -f "$f" ] || continue
        backups+=("$f")
        local bname=$(basename "$f")
        local bsize=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f" 2>/dev/null || wc -c < "$f" 2>/dev/null || echo "?")
        echo "  $i. $bname  (${bsize} bytes)"
        i=$((i + 1))
    done

    if [ ${#backups[@]} -eq 0 ]; then
        log_warn "No binary backups found in $BACKUP_DIR"
        return 1
    fi

    echo ""
    echo "  0. Cancel"
    echo ""
    read -p "  Select backup to restore [0-${#backups[@]}]: " choice < /dev/tty || true
    if [ "$choice" = "0" ]; then
        log_info "Cancelled"
        return 0
    fi
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt ${#backups[@]} ]; then
        log_error "Invalid choice"
        return 1
    fi

    local selected="${backups[$((choice-1))]}"
    log_info "Rolling back to: $(basename "$selected")"

    local was_running=false
    is_running && was_running=true
    [ "$was_running" = true ] && stop_paqet

    if ! cp "$selected" "$INSTALL_DIR/bin/paqet"; then
        log_error "Failed to restore backup"
        [ "$was_running" = true ] && start_paqet
        return 1
    fi
    chmod +x "$INSTALL_DIR/bin/paqet"

    # Verify restored binary
    if ! "$INSTALL_DIR/bin/paqet" version &>/dev/null; then
        log_warn "Restored binary failed verification (may need libpcap)"
    fi

    # Try to extract version from the filename (format: paqet.vX.Y.Z.TIMESTAMP)
    local restored_ver=""
    local _bname
    _bname=$(basename "$selected")
    # Extract version: remove 'paqet.' prefix and '.YYYYMMDDHHMMSS' timestamp suffix
    restored_ver=$(echo "$_bname" | sed 's/^paqet\.//' | sed 's/\.[0-9]\{14\}$//')
    # Validate extracted version looks reasonable
    if [ -n "$restored_ver" ] && [ "$restored_ver" != "backup" ] && [ "$restored_ver" != "$_bname" ]; then
        if _validate_version_tag "$restored_ver"; then
            PAQET_VERSION="$restored_ver"
            _safe_update_setting "PAQET_VERSION" "$restored_ver" "$INSTALL_DIR/settings.conf"
            log_info "Restored version: $restored_ver"
        else
            log_warn "Could not determine version from backup filename, keeping current version setting"
        fi
    else
        log_warn "Could not extract version from backup filename"
    fi

    log_success "Rolled back successfully"

    [ "$was_running" = true ] && start_paqet
}

update_management_script() {
    local update_url="https://raw.githubusercontent.com/4H1R/paqctl/main/paqctl.sh"
    local tmp_script
    tmp_script=$(mktemp "/tmp/paqctl-update-XXXXXXXX.sh")

    log_info "Checking for management script updates..."
    if ! curl -sfL --max-time 30 --max-filesize 4194304 -o "$tmp_script" "$update_url" 2>/dev/null; then
        log_warn "Could not download the management script update"
        rm -f "$tmp_script"
        return 1
    fi

    # Validate: must contain our markers, be a bash script, and pass syntax check
    if ! head -n 1 "$tmp_script" 2>/dev/null | grep -q "^#!.*bash"; then
        log_warn "Downloaded file is not a bash script, skipping"
        rm -f "$tmp_script"
        return 1
    fi
    local _rc=0
    if grep -q "PAQET_REPO=" "$tmp_script" && \
       grep -q "create_management_script" "$tmp_script" && \
       grep -q "PAQCTL_VERSION=" "$tmp_script" && \
       bash -n "$tmp_script" 2>/dev/null; then
        local _new_ver
        _new_ver=$(grep -m1 '^VERSION=' "$tmp_script" | cut -d'"' -f2)
        local _update_output
        if _update_output=$(bash "$tmp_script" --update-components 2>&1); then
            log_success "Management script updated (${VERSION} → ${_new_ver:-unknown})"
        else
            log_warn "Management script update execution failed: ${_update_output:-unknown error}"
            _rc=1
        fi
    else
        log_warn "Downloaded script failed validation, skipping"
        _rc=1
    fi
    rm -f "$tmp_script"
    return $_rc
}

#═══════════════════════════════════════════════════════════════════════
# Secret Key Generation
#═══════════════════════════════════════════════════════════════════════

generate_secret() {
    echo ""
    local key
    key=$("$INSTALL_DIR/bin/paqet" secret 2>/dev/null || true)
    if [ -z "$key" ]; then
        key=$(openssl rand -base64 32 2>/dev/null | tr -d '=+/' | head -c 32)
    fi
    echo -e "  ${GREEN}${BOLD}New encryption key: ${key}${NC}"
    echo ""
    echo -e "  ${DIM}Share this key securely with client users.${NC}"
    echo ""
}
