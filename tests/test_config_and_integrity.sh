#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# 1. Verify safe config parser does not execute code
tmp_cfg=$(mktemp /tmp/metsuke_cfg_XXXXXX.conf)
marker_file=$(mktemp /tmp/metsuke_pwn_XXXXXX)
rm -f "$marker_file"

cat > "$tmp_cfg" <<EOF
# Test config
THREADS=20
MALICIOUS=\$(touch $marker_file)
BURP_PROXY_PORT=9090; touch $marker_file
EOF

# Test config parsing logic by sourcing metsuke with --config
# We test using a dry-run or directly invoking the parser
output=$(bash "$SCRIPT_DIR/metsuke.sh" -d example.com --dry-run --config "$tmp_cfg" 2>&1 || true)
rm -f "$tmp_cfg"

if [[ -f "$marker_file" ]]; then
    rm -f "$marker_file"
    echo "FAIL: Malicious code in config file was executed!"
    exit 1
fi

# 2. Verify sha256 checksum generation in summary
if ! grep -q 'artifacts.sha256' "$SCRIPT_DIR/metsuke.sh"; then
    echo "FAIL: metsuke.sh does not generate artifacts.sha256 checksum file"
    exit 1
fi

echo "PASS: config parser and integrity checks passed"
