#═══════════════════════════════════════════════════════════════════════
# Binary Download & Install
#═══════════════════════════════════════════════════════════════════════

get_latest_version() {
    local response
    response=$(_curl_with_retry "$PAQET_API_URL" 3)
    if [ -z "$response" ]; then
        log_error "Failed to query GitHub API after retries"
        return 1
    fi
    local tag
    tag=$(echo "$response" | grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | grep -o '"[^"]*"$' | tr -d '"')
    if [ -z "$tag" ]; then
        log_error "Could not determine latest paqet version"
        return 1
    fi
    if ! _validate_version_tag "$tag"; then
        log_error "Invalid version tag format: $tag"
        return 1
    fi
    echo "$tag"
}
