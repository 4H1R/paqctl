#!/usr/bin/env bash
# Assemble paqctl.sh from the sources in src/.
#
#   ./build.sh           write paqctl.sh
#   ./build.sh --check   fail if paqctl.sh is out of date (used by CI)
#
# paqctl.sh stays a single committed file because users install it with
# `curl .../paqctl.sh | sudo bash` and `paqctl self-update` downloads it.
#
# Layout:
#   src/installer.sh      installer entry point (includes src/installer/*.sh)
#   src/management.sh     management script, embedded by the installer and
#                         installed as /usr/local/bin/paqctl (src/management/*.sh)
#   src/lib/*.sh          code shared by both: written once, included twice
#
# A line consisting of "#@include <path>" (relative to src/) is replaced by
# that file's contents, recursively.
set -euo pipefail

cd "$(dirname "$0")"
SRC_DIR="src"
OUT="paqctl.sh"

declare -a STACK=()

expand() {
    local file="$1" line inc
    [ -f "$SRC_DIR/$file" ] || { echo "build.sh: missing include: $file" >&2; exit 1; }
    local f
    for f in "${STACK[@]}"; do
        [ "$f" = "$file" ] && { echo "build.sh: include cycle at $file" >&2; exit 1; }
    done
    STACK+=("$file")
    while IFS= read -r line || [ -n "$line" ]; do
        if [[ "$line" == *$'\r' ]]; then
            echo "build.sh: $file has CRLF line endings (see .gitattributes)" >&2
            exit 1
        fi
        if [[ "$line" =~ ^#@include[[:space:]]+([^[:space:]]+)[[:space:]]*$ ]]; then
            inc="${BASH_REMATCH[1]}"
            expand "$inc"
        else
            printf '%s\n' "$line"
        fi
    done < "$SRC_DIR/$file"
    unset 'STACK[${#STACK[@]}-1]'
}

# The management script is embedded in a quoted heredoc ending at a line
# "MANAGEMENT"; such a line inside it would end the heredoc early.
if grep -rqx 'MANAGEMENT' "$SRC_DIR/management.sh" "$SRC_DIR/management" "$SRC_DIR/lib"; then
    echo "build.sh: a line consisting of 'MANAGEMENT' in the management sources would break the embedded heredoc" >&2
    exit 1
fi

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
expand installer.sh > "$tmp"
bash -n "$tmp" || { echo "build.sh: generated script has syntax errors" >&2; exit 1; }

if [ "${1:-}" = "--check" ]; then
    if ! cmp -s "$tmp" "$OUT"; then
        echo "build.sh: $OUT is out of date. Run ./build.sh and commit the result." >&2
        diff -u "$OUT" "$tmp" | head -40 >&2 || true
        exit 1
    fi
    echo "$OUT is up to date"
    exit 0
fi

cat "$tmp" > "$OUT"
chmod +x "$OUT" 2>/dev/null || true
echo "Built $OUT ($(wc -l < "$OUT") lines)"
