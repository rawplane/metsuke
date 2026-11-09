#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# 1. Verify summary.txt template contains no ANSI escape codes
summary_body=$(sed -n '/cat > "\$OUTDIR\/report\/summary.txt"/,/EOF/p' "$SCRIPT_DIR/metsuke.sh")
if echo "$summary_body" | grep -qE '\$\{BOLD\}|\$\{NC\}|\\033'; then
    echo "FAIL: summary.txt template contains ANSI codes"
    exit 1
fi

# 2. Verify URL discovery filters gau / urlfinder by in-scope domain
if ! grep -q 'DOMAIN_ESCAPED' <(sed -n '/phase_url_discovery()/,/^}/p' "$SCRIPT_DIR/metsuke.sh"); then
    echo "FAIL: phase_url_discovery does not enforce DOMAIN_ESCAPED filter on passive sources"
    exit 1
fi

# 3. Functional test of regex logic on dummy URLs
DOMAIN="example.com"
DOMAIN_ESCAPED="${DOMAIN//./\\.}"
URL_REGEX="^(https?://)?([a-zA-Z0-9.-]+\.)?${DOMAIN_ESCAPED}(:[0-9]+)?(/|$)"

test_urls=(
    "https://example.com/index.html"
    "http://sub.example.com/api"
    "sub.sub2.example.com/path"
    "http://example.com:8080/test"
    "https://example.com"
)
for u in "${test_urls[@]}"; do
    if ! echo "$u" | grep -E -q "$URL_REGEX"; then
        echo "FAIL: In-scope URL falsely rejected: $u"
        exit 1
    fi
done

out_urls=(
    "https://notexample.com/path"
    "https://attacker.com/?redirect=example.com"
    "https://evil-example.com/login"
)
for u in "${out_urls[@]}"; do
    if echo "$u" | grep -E -q "$URL_REGEX"; then
        echo "FAIL: Out-of-scope URL falsely accepted: $u"
        exit 1
    fi
done

echo "PASS: all filtering and output sanitization checks passed"
