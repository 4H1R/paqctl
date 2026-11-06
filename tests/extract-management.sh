#!/usr/bin/env bash
# Print the management script embedded in paqctl.sh (the one installed as
# /usr/local/bin/paqctl), with INSTALL_DIR filled in.
#
# Usage: tests/extract-management.sh paqctl.sh [install_dir] > paqctl-mgmt.sh
set -euo pipefail

src="${1:?usage: extract-management.sh paqctl.sh [install_dir]}"
dir="${2:-/opt/paqctl}"

out=$(awk '/<< .MANAGEMENT.$/{f=1;next} /^MANAGEMENT$/{f=0} f' "$src")
if [ -z "$out" ]; then
    echo "extract-management: no MANAGEMENT heredoc found in $src" >&2
    exit 1
fi
printf '%s\n' "$out" | sed "s#REPLACE_ME_INSTALL_DIR#${dir}#g"
