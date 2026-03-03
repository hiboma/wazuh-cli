#!/bin/bash
# Verifies that files and directories defined in the spec exist
set -euo pipefail

cd "$(dirname "$0")/.."

EXPECTED_FILES=(
    "src/main.rs"
    "src/cli/mod.rs"
    "src/client/mod.rs"
    "src/client/auth.rs"
    "src/client/tls.rs"
    "src/api/mod.rs"
    "src/config.rs"
    "src/output.rs"
    "src/error.rs"
)

MISSING=0
for f in "${EXPECTED_FILES[@]}"; do
    if [ ! -f "$f" ]; then
        echo "MISSING: $f"
        MISSING=$((MISSING + 1))
    fi
done

if [ $MISSING -eq 0 ]; then
    echo "All expected files exist."
else
    echo "$MISSING files missing."
    exit 1
fi
