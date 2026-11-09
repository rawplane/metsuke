#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# 1. Test check_tcp_port rejection on metacharacters / invalid input
source <(sed -n '/^check_tcp_port()/,/^}/p' "$SCRIPT_DIR/metsuke.sh")
TIMEOUT_BIN=""

if check_tcp_port '127.0.0.1; echo INJECTED' 80 2>/dev/null; then
    echo "FAIL: check_tcp_port accepted command injection in host"
    exit 1
fi

if check_tcp_port '127.0.0.1' '80; echo INJECTED' 2>/dev/null; then
    echo "FAIL: check_tcp_port accepted command injection in port"
    exit 1
fi

if check_tcp_port '127.0.0.1' 70000 2>/dev/null; then
    echo "FAIL: check_tcp_port accepted port out of range (>65535)"
    exit 1
fi

if check_tcp_port '127.0.0.1' 0 2>/dev/null; then
    echo "FAIL: check_tcp_port accepted port out of range (0)"
    exit 1
fi

# 2. Concurrency test for js_fetch_one using temporary worker directory
# Ensure phase_js_secret_scan uses per-worker temp files instead of direct concurrent append
if ! grep -q '\.js_tmp' "$SCRIPT_DIR/metsuke.sh"; then
    echo "FAIL: metsuke.sh does not use .js_tmp worker directory in phase_js_secret_scan"
    exit 1
fi

echo "PASS: all core hardening checks passed"
