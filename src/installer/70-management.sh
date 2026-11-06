#═══════════════════════════════════════════════════════════════════════
# Management Script (Embedded)
#═══════════════════════════════════════════════════════════════════════

create_management_script() {
    local tmp_script
    tmp_script=$(mktemp "$INSTALL_DIR/paqctl.XXXXXXXX") || { log_error "Failed to create temp file"; return 1; }
    cat > "$tmp_script" << 'MANAGEMENT'
#@include management.sh
MANAGEMENT

    # Replace placeholder
    sed "s#REPLACE_ME_INSTALL_DIR#$INSTALL_DIR#g" "$tmp_script" > "$tmp_script.sed" && mv "$tmp_script.sed" "$tmp_script"

    if ! chmod +x "$tmp_script"; then
        log_error "Failed to make management script executable"
        rm -f "$tmp_script"
        return 1
    fi
    if ! mv -f "$tmp_script" "$INSTALL_DIR/paqctl"; then
        log_error "Failed to install management script"
        rm -f "$tmp_script"
        return 1
    fi

    # Create symlink
    rm -f /usr/local/bin/paqctl 2>/dev/null
    if ! ln -sf "$INSTALL_DIR/paqctl" /usr/local/bin/paqctl; then
        log_warn "Failed to create symlink /usr/local/bin/paqctl"
    fi

    # Bash completion (generated from the management script's command table)
    local _comp_dir=""
    if [ -d /usr/share/bash-completion/completions ]; then
        _comp_dir=/usr/share/bash-completion/completions
    elif [ -d /etc/bash_completion.d ]; then
        _comp_dir=/etc/bash_completion.d
    fi
    if [ -n "$_comp_dir" ]; then
        if "$INSTALL_DIR/paqctl" completion bash > "$_comp_dir/paqctl.tmp" 2>/dev/null && [ -s "$_comp_dir/paqctl.tmp" ]; then
            mv -f "$_comp_dir/paqctl.tmp" "$_comp_dir/paqctl"
            chmod 644 "$_comp_dir/paqctl" 2>/dev/null || true
        else
            rm -f "$_comp_dir/paqctl.tmp" 2>/dev/null
        fi
    fi

    log_success "Management script installed → /usr/local/bin/paqctl"
}
