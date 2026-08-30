#!/usr/bin/env bash
# =============================================================================
# Bug Bounty Recon & Non-Destructive Scanning Pipeline
# =============================================================================
# DISCLAIMER:
#   This script is intended for use ONLY on targets you have explicit written
#   permission to test (e.g., official bug bounty program or pentest contract).
#   Unauthorized use is illegal. The author assumes no liability for misuse.
# =============================================================================

set -euo pipefail

# ------------------------- Global Configuration -------------------------------
SCOPE_FILE="scope.txt"                 # File containing allowed domains
BASE_DIR="output"                      # Main output directory
RATE_LIMIT_SLEEP=0.5                   # Delay between requests (seconds) for certain tools
THREADS=10                             # Moderate thread count
NUCLEI_SEVERITY="low,medium,high,critical"
NUCLEI_RATE_LIMIT=50                   # Requests per second for nuclei

# ------------------------- Helper Functions -----------------------------------
log()  { echo -e "[$(date +'%H:%M:%S')] $*"; }
die()  { echo -e "[ERROR] $*" >&2; exit 1; }

# Validate target against scope.txt
validate_target() {
    local target="$1"
    [ -f "$SCOPE_FILE" ] || die "File $SCOPE_FILE not found."
    # Check if target is within scope (supports wildcards)
    while IFS= read -r scope; do
        # Skip comments and empty lines
        [[ "$scope" =~ ^#.*$ || -z "$scope" ]] && continue
        # Exact match
        if [[ "$target" == "$scope" ]]; then
            return 0
        # Wildcard at beginning (e.g., *.example.com)
        elif [[ "$scope" == *.* && "$target" == ${scope%%.*}.${scope#*.} ]]; then
            return 0
        # General wildcard handling
        elif [[ "$scope" == *"*"* ]]; then
            local regex="${scope//\*/.*}"
            if [[ "$target" =~ ^$regex$ ]]; then
                return 0
            fi
        fi
    done < "$SCOPE_FILE"
    die "Target '$target' is NOT in scope file $SCOPE_FILE."
}

# ------------------------- Pipeline Stages ------------------------------------
# 1. Subdomain Enumeration
subdomain_enum() {
    local domain="$1"
    local out="$BASE_DIR/$domain/recon/subdomains"
    mkdir -p "$out"

    log "Collecting passive subdomains for $domain..."
    subfinder -d "$domain" -silent > "$out/subfinder.txt" || true
    assetfinder --subs-only "$domain" > "$out/assetfinder.txt" || true
    # crt.sh (using curl + jq)
    curl -s "https://crt.sh/?q=%25.$domain&output=json" | jq -r '.[].name_value' 2>/dev/null \
        | sed 's/\*\.//g' | sort -u > "$out/crtsh.txt" || true

    # Merge, clean, and resolve DNS
    cat "$out"/*.txt | sort -u > "$out/all_raw.txt"
    log "Resolving DNS for unique subdomains..."
    if command -v dnsx >/dev/null; then
        dnsx -l "$out/all_raw.txt" -silent -resp-only -o "$out/resolved.txt" || true
    else
        # Fallback: use host command (slower)
        while read -r sub; do
            if host "$sub" &>/dev/null; then echo "$sub"; fi
        done < "$out/all_raw.txt" > "$out/resolved.txt"
    fi
    sort -u "$out/resolved.txt" -o "$out/resolved.txt"
    log "Found $(wc -l < "$out/resolved.txt") live subdomains."
}

# 2. HTTP Probing & Fingerprinting
http_probe() {
    local domain="$1"
    local out="$BASE_DIR/$domain/recon/http"
    mkdir -p "$out"
    local subdomains="$BASE_DIR/$domain/recon/subdomains/resolved.txt"

    [ -f "$subdomains" ] || die "Resolved subdomain file not found. Run subdomain_enum first."
    log "Probing HTTP/HTTPS and fingerprinting..."
    httpx -l "$subdomains" -silent -title -tech-detect -status-code \
          -follow-redirects -threads "$THREADS" -json -o "$out/httpx.json" || true

    # Extract live URLs for later stages
    jq -r '.url' "$out/httpx.json" 2>/dev/null | sort -u > "$out/live_urls.txt"
    log "Live URLs found: $(wc -l < "$out/live_urls.txt")"
}

# 3. Port & Service Scanning (light, common ports only)
port_scan() {
    local domain="$1"
    local out="$BASE_DIR/$domain/recon/ports"
    mkdir -p "$out"
    local live_urls="$BASE_DIR/$domain/recon/http/live_urls.txt"

    [ -f "$live_urls" ] || die "live_urls.txt not found. Run http_probe first."
    # Extract unique hosts from URLs
    sed -E 's#https?://##; s#/.*##' "$live_urls" | sort -u > "$out/hosts.txt"

    log "Performing port scanning (top 1000 ports) with naabu..."
    if command -v naabu >/dev/null; then
        naabu -l "$out/hosts.txt" -top-ports 1000 -silent -rate 100 -o "$out/naabu.txt" || true
    else
        # Fallback: nmap top ports
        while read -r host; do
            nmap -Pn -sS --top-ports 1000 --max-rate 100 -oG - "$host" 2>/dev/null \
                | grep "/open" >> "$out/naabu.txt"
        done < "$out/hosts.txt"
    fi
    log "Port scan completed."
}

# 4. Content & Endpoint Discovery
content_discovery() {
    local domain="$1"
    local out="$BASE_DIR/$domain/recon/content"
    mkdir -p "$out"
    local live_urls="$BASE_DIR/$domain/recon/http/live_urls.txt"

    [ -f "$live_urls" ] || die "live_urls.txt not found."
    log "Crawling endpoints with katana..."
    katana -list "$live_urls" -d 5 -jc -kf -o "$out/katana.txt" -rl "$RATE_LIMIT_SLEEP" \
           -silent -headless -concurrency "$THREADS" || true

    log "Directory & parameter fuzzing (polite rate limit) with ffuf..."
    # Select a subset of URLs (e.g., those returning 200)
    grep -E ' 200 ' "$BASE_DIR/$domain/recon/http/httpx.json" 2>/dev/null | \
        jq -r '.url' 2>/dev/null | head -n 20 > "$out/targets_ffuf.txt"
    while read -r url; do
        ffuf -u "$url/FUZZ" -w /usr/share/wordlists/dirb/common.txt \
             -rate 50 -t 5 -mc 200,204,301,302,307,401,403 -o "$out/ffuf_$(basename "$url").json" \
             -of json -s || true
        sleep "$RATE_LIMIT_SLEEP"
    done < "$out/targets_ffuf.txt"
    log "Content discovery completed."
}

# 5. Vulnerability Scanning (nuclei, non‑destructive)
vuln_scan() {
    local domain="$1"
    local out="$BASE_DIR/$domain/scan/nuclei"
    mkdir -p "$out"
    local live_urls="$BASE_DIR/$domain/recon/http/live_urls.txt"

    [ -f "$live_urls" ] || die "live_urls.txt not found."
    log "Running nuclei with CVE/misconfig templates (severity: $NUCLEI_SEVERITY)..."

    # Use rate limiting and moderate concurrency
    nuclei -l "$live_urls" -severity "$NUCLEI_SEVERITY" \
           -rate-limit "$NUCLEI_RATE_LIMIT" -concurrency "$THREADS" \
           -o "$out/nuclei_results.txt" -jsonl -silent \
           -exclude-type dos,brute-force  # avoid dangerous templates
    log "Nuclei scan completed."
}

# 6. Deduplication & Prioritization
deduplicate_prioritize() {
    local domain="$1"
    local out="$BASE_DIR/$domain/report"
    mkdir -p "$out"
    local nuclei_raw="$BASE_DIR/$domain/scan/nuclei/nuclei_results.txt"

    log "Merging results and removing duplicates..."
    if [ -f "$nuclei_raw" ]; then
        jq -s 'unique_by(.template_id)' "$nuclei_raw" > "$out/nuclei_dedup.json" 2>/dev/null || true
        # Create severity summary
        jq -r '.[] | "\(.info.severity)\t\(.template_id)\t\(.matched_at)"' \
            "$out/nuclei_dedup.json" | sort -u > "$out/nuclei_summary.txt"
        # Count per severity
        echo "=== Nuclei Findings Summary ===" > "$out/summary.md"
        echo "| Severity | Count |" >> "$out/summary.md"
        echo "|----------|-------|" >> "$out/summary.md"
        for sev in critical high medium low info; do
            count=$(grep -c "^$sev" "$out/nuclei_summary.txt" || true)
            echo "| $sev | $count |" >> "$out/summary.md"
        done
    fi

    # Combine all findings into Markdown report
    {
        echo "# Bug Bounty Report for $domain"
        echo "Date: $(date)"
        echo
        echo "## Summary"
        echo "- Live subdomains: $(wc -l < "$BASE_DIR/$domain/recon/subdomains/resolved.txt" 2>/dev/null || echo 0)"
        echo "- Live HTTP URLs: $(wc -l < "$BASE_DIR/$domain/recon/http/live_urls.txt" 2>/dev/null || echo 0)"
        echo "- Open ports: $(wc -l < "$BASE_DIR/$domain/recon/ports/naabu.txt" 2>/dev/null || echo 0)"
        echo
        echo "## Nuclei Findings (by Severity)"
        cat "$out/summary.md" 2>/dev/null || echo "No nuclei findings."
        echo
        echo "## List of Live Subdomains"
        cat "$BASE_DIR/$domain/recon/subdomains/resolved.txt" 2>/dev/null || true
        echo
        echo "## List of Live URLs"
        cat "$BASE_DIR/$domain/recon/http/live_urls.txt" 2>/dev/null || true
        echo
        echo "## List of Open Ports"
        cat "$BASE_DIR/$domain/recon/ports/naabu.txt" 2>/dev/null || true
        echo
        echo "## Discovered Endpoints (Katana)"
        cat "$BASE_DIR/$domain/recon/content/katana.txt" 2>/dev/null || true
        echo
        echo "## Manual Verification Recommendations"
        echo "- Manually verify each nuclei finding with high/critical severity."
        echo "- Validate impact without destructive exploitation."
        echo "- Use screenshots and reproduction steps for the report."
    } > "$out/report_$domain.md"

    log "Final report: $out/report_$domain.md"
}

# ------------------------- Main Function -------------------------------------
main() {
    if [ $# -lt 1 ]; then
        echo "Usage: $0 <target-domain> [--full | --subenum | --probe | --ports | --content | --vuln | --report]"
        exit 1
    fi

    local target_domain="$1"
    shift

    # Validate target
    validate_target "$target_domain"

    # Create folder structure
    mkdir -p "$BASE_DIR/$target_domain"/{recon/{subdomains,http,ports,content},scan/nuclei,report}

    local mode="${1:---full}"
    case "$mode" in
        --full)
            subdomain_enum "$target_domain"
            http_probe "$target_domain"
            port_scan "$target_domain"
            content_discovery "$target_domain"
            vuln_scan "$target_domain"
            deduplicate_prioritize "$target_domain"
            ;;
        --subenum)   subdomain_enum "$target_domain" ;;
        --probe)     http_probe "$target_domain" ;;
        --ports)     port_scan "$target_domain" ;;
        --content)   content_discovery "$target_domain" ;;
        --vuln)      vuln_scan "$target_domain" ;;
        --report)    deduplicate_prioritize "$target_domain" ;;
        *)           die "Unknown mode: $mode" ;;
    esac

    log "Pipeline completed for $target_domain."
}

# Run main
main "$@"