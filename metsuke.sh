#!/usr/bin/env bash
#
# metsuke.sh (目付) — Modular recon pipeline with authorization discipline & auditing
# The name comes from an Edo-era inspector title: an officially mandated role,
# with a clear mandate, to observe & report before acting.
#
# LEGAL WARNING:
#   This script may ONLY be run against targets for which you already have
#   explicit permission (bug bounty scope, pentest contract, or your own assets).
#   Scanning without authorization is illegal in most jurisdictions.
#
#   The --burp-active-scan option is INTRUSIVE (attacks endpoints) — make sure
#   your authorization scope explicitly allows active scanning, not just passive recon.
#
#   The --extended-workflows option specifically searches for endpoints that could
#   potentially leak credentials/configuration (.env, .git, admin panel,
#   cloud config, token/session endpoints). These remain passive GET
#   requests (not exploits), but make sure your scope allows this kind of
#   sensitive information search.
#
# Required dependencies : subfinder, httpx, naabu, nuclei, curl, jq
# Optional dependencies : assetfinder, gau, gowitness, katana, urlfinder
# Burp Suite (optional): Burp Pro/Community running locally for passive proxy mirroring,
#                        Burp Pro + REST API enabled for active scan triggering
#
set -uo pipefail
IFS=$'\n\t'

# ─────────────────────────────── Config & Globals ───────────────────────────────
SCRIPT_VERSION="3.0.0"
DOMAIN=""
OUTDIR=""
THREADS=50
FULL_SCAN=false
RESUME=false
SKIP_CDN=false
PARALLEL=true
DRY_RUN=false
NUCLEI_SEVERITY="low,medium,high,critical"
WEBHOOK_URL="${RECON_WEBHOOK_URL:-}"

# Katana / active crawling (from yublueflower)
USE_KATANA=false                         # --katana : active JS-aware crawling, not just passive sources (gau)
EXTENDED_WORKFLOWS=false                 # --extended-workflows : search for sensitive endpoints (admin/auth/cloud/secrets)
USE_WEB_ARCHIVES=false                   # --web-archives : use urlfinder (wayback etc.) instead of live-crawl katana
declare -a SESSION_HEADERS=()            # --session-header "Cookie: ..." (can be repeated)
SESSION_HEADERS_FILE=""

# Burp Suite integration (all optional, default off)
BURP_PASSIVE=false                       # --burp : mirror httpx traffic to Burp proxy
BURP_ACTIVE_SCAN=false                   # --burp-active-scan : trigger active scan via REST API
BURP_PROXY_HOST="127.0.0.1"
BURP_PROXY_PORT="8080"
BURP_API_URL="http://127.0.0.1:1337"
BURP_API_KEY="${BURP_API_KEY:-}"

CONFIG_FILE=""
START_TIME=$(date +%s)
LOGFILE=""

# Terminal colors
RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'
BLUE=$'\033[0;34m'; CYAN=$'\033[0;36m'; MAGENTA=$'\033[0;35m'; BOLD=$'\033[1m'; NC=$'\033[0m'

# ─────────────────────────────── Helper Functions ───────────────────────────────
log()      { echo -e "${CYAN}[$(date +'%H:%M:%S')]${NC} $*"; }
log_ok()   { echo -e "${GREEN}[$(date +'%H:%M:%S')] [OK]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[$(date +'%H:%M:%S')] [WARN]${NC} $*"; }
log_err()  { echo -e "${RED}[$(date +'%H:%M:%S')] [ERROR]${NC} $*" >&2; }
log_burp() { echo -e "${MAGENTA}[$(date +'%H:%M:%S')] [BURP]${NC} $*"; }
log_ext()  { echo -e "${MAGENTA}[$(date +'%H:%M:%S')] [EXT]${NC} $*"; }
section()  { echo -e "\n${BOLD}${BLUE}══════════ $* ══════════${NC}"; }

print_banner() {
    echo -e "${CYAN}"
    cat << "EOF"
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣤⣤⣤⣤⣤⣤⣤⣤⣤⣄⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⠖⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠉⠉⠉⠓⠒⣲⠶⠦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⠞⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡤⠖⠋⠀⠀⠀⠘⢧⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣠⠾⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⠴⠚⠉⠀⠀⠀⠀⠀⠀⠀⠈⢷⡀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣠⠞⠁⠸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⠴⠚⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢷⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣼⠃⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣤⣤⠴⠶⠚⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣧⠀⠀⠀⠀⠀
⠀⠀⢰⡇⠀⠀⠀⠳⠤⠤⠤⠤⠶⠒⠛⠛⠉⠉⠉⠀⠀⠀⣀⣤⡔⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣤⠿⠂⠀⠀⠀⠀
⠀⠀⠈⢧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡤⠖⠉⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢈⡿⠃⠀⠀⠀⠀⠀
⠀⠀⠀⠈⢣⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⠴⠾⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⡠⠤⢄⣖⠞⠉⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠙⢦⡀⠀⠀⢀⣠⠤⠲⡍⠀⠀⠀⠈⠻⣷⢤⡀⠀⠀⠀⢀⣀⣤⢤⣶⣲⣯⠭⠵⠓⠒⢘⠏⢹⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠈⠓⠚⠉⢹⡀⠀⢸⠀⠀⠀⠀⠀⠀⠙⠯⣖⣲⠬⠿⠒⠛⠉⠉⠀⠀⠀⠀⠀⢀⠏⠀⢸⠀⣀⠴⠚⠉⢻⣦⠀⠀
⠀⣠⠖⢦⣀⡀⠀⠀⠀⠀⠀⠀⢧⠀⢸⣀⠀⠀⠀⠀⠀⢀⠆⠀⠀⠀⠐⡆⠀⠀⠀⠀⠀⠀⠀⠀⢸⣀⣠⠟⠉⠀⠀⠀⠀⠀⢋⡆⠀
⠸⠁⠀⠀⠀⠈⠑⠢⢄⣀⣀⡤⠞⠛⣉⠁⠀⠀⠀⠀⠀⢸⡀⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠳⣦⡀⠀⠀⣀⠞⠉⠁⠀
⠱⣤⣄⠀⠀⠀⠀⠀⠸⣿⡄⠀⠐⢻⣿⣿⣿⣦⡀⠀⠀⠀⠳⡀⠀⣠⠞⠁⠀⠀⠀⣀⣀⣀⣀⠀⠀⠀⠀⠀⠈⣧⠤⠊⠁⠀⠀⠀⠀             
⠀⠀⠈⠳⢤⣀⠀⠀⠀⠈⢻⡄⠀⠈⢿⣿⣿⣿⣿⣆⠀⠀⠀⡼⢸⡁⢀⣠⣤⣶⣿⢿⣿⡟⠋⠉⠀⠀⠀⢀⡼⠁⠀⠀⠀⠀⠀⠀⠀           ⠀               
⠀⠀⠀⠀⠀⠈⠙⠲⠤⣀⣸⡟⠀⠙⠺⢿⣿⣿⣿⣿⡷⠶⢻⣥⣼⡛⠿⣿⣯⣿⣿⣿⣿⣁⣤⠄⠀⠀⠀⢸⡁⠀⠀⠀⠀⠀⠀⠀⠀        M E T S U K E
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡟⠁⠀⠐⠚⢉⡵⠟⠋⠁⠀⠀⣿⣿⣿⡇⠀⠈⢻⣿⡿⢿⣿⡯⠷⠀⠀⠀⠀⠈⢧⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠟⠋⠉⠉⠈⠉⢹⠦⣄⠀⠀⠀⠀⠻⠛⠛⠃⠀⠀⠀⠀⠉⠀⠀⠀⢀⣤⠒⡟⠉⠒⠺⠃⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⠼⡆⠈⢣⠀⡀⢀⠀⠀⠀⡤⡄⢠⡄⠀⡄⢠⠀⣴⠏⠁⡼⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡤⠒⠉⠀⠀⢣⢰⣉⡖⢣⡜⣿⣠⣄⣧⣀⣨⣧⢤⣵⡾⡔⢁⡴⠊⠀⠀⠉⢳⡄⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣠⡴⠞⢇⠀⠀⠀⢀⡾⢨⢸⠹⠁⣿⣸⢁⡿⢡⢋⣏⣿⣰⣹⣿⠀⡾⢦⡀⠀⠀⠀⣸⠏⠲⢄⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢠⡾⠁⠀⠀⠘⣦⡠⠔⢋⡇⢈⣿⣿⡟⡿⣿⣻⣳⢛⢋⠟⣹⣻⣽⣿⡼⠁⠀⠉⠓⠤⢴⡋⠀⠀⠀⠑⢄⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣰⠏⠀⠀⠀⣠⠾⠋⠀⠀⢀⡷⡿⢯⡃⣻⣿⡿⠋⠛⠚⠛⠞⠛⠁⣩⠟⠀⠀⠀⠀⠀⠀⠀⠙⠢⡀⠀⠀⠀⠳⡀⠀⠀
⠀⠀⠀⢀⡜⠁⠀⣠⡴⠛⠁⠀⠀⠀⠀⠺⣟⠳⢄⣹⣿⣟⣀⣀⣀⣀⣀⠀⢀⡴⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠑⠤⣀⡀⠙⣄⠀
⠀⠀⢠⠎⢀⡴⠚⠁⠀⠀⠀⠀⠀⠀⠀⠀⠈⠓⠺⠋⠁⠀⠀⠀⠀⠉⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠑⠚⠂
⠀⠀⡿⠚⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
EOF
    echo -e "${NC}${BOLD}          \"authorize first, then act\"${NC}"
    echo -e "${CYAN}          recon pipeline v${SCRIPT_VERSION} — modular · authorized · audited${NC}"
    echo ""
}

usage() {
    print_banner
    cat <<EOF
Usage:
  $0 -d <domain> [options]

Basic options:
  -d <domain>       Target domain (required), e.g.: example.com
  -o <dir>          Output directory (default: ./recon_<domain>_<timestamp>)
  -t <threads>      Number of concurrent threads (default: 50)
  --full            Aggressive mode: full port scan (1-65535) + all nuclei severities
  --config <file>   Load default options from a config file (bash source)
  -h                Show this help

Performance options:
  --sequential      Run all phases sequentially (default: parallel)
  --resume          Skip phases whose output already exists from a previous run
  --skip-cdn        Skip port scanning for hosts detected behind a CDN/WAF
  --dry-run         Show the commands that would run without executing them

Advanced URL discovery options (adapted from yublueflower):
  --katana                    Active crawling with katana (JS-aware) in addition to passive gau
  --web-archives               Use urlfinder (wayback/CT etc.) instead of live-crawl katana
  --extended-workflows         Detect sensitive endpoints (admin/auth/cloud-config/.env/.git)
  --session-header "H: V"      Extra header for crawling (e.g. Cookie), can be repeated

Burp Suite integration (optional, default OFF):
  --burp                    Mirror httpx traffic to Burp proxy (auto-populates Site Map)
  --burp-proxy <host:port>  Burp proxy address (default: 127.0.0.1:8080)
  --burp-active-scan        Trigger an ACTIVE SCAN via the Burp REST API (INTRUSIVE!)
  --burp-api-url <url>      Burp REST API address (default: http://127.0.0.1:1337)
  --burp-api-key <key>      Burp REST API key (or set env BURP_API_KEY)

Examples:
  $0 -d example.com
  $0 -d example.com -o ./results -t 100 --full --resume
  $0 -d example.com --katana --extended-workflows
  $0 -d example.com --session-header "Cookie: session=abcd" --katana
  $0 -d example.com --burp --burp-proxy 127.0.0.1:8080
  $0 -d example.com --burp-active-scan --burp-api-key abcd1234

${YELLOW}IMPORTANT: Only use this against targets for which you already have explicit permission.${NC}
EOF
    exit 1
}

confirm_authorization() {
    echo -e "${YELLOW}${BOLD}"
    echo "════════════════════════════════════════════════════════════"
    echo " AUTHORIZATION CONFIRMATION"
    echo "════════════════════════════════════════════════════════════${NC}"
    echo "Target : ${BOLD}${DOMAIN}${NC}"
    echo "Make sure you have explicit permission to perform security"
    echo "testing against this target (bug bounty scope / pentest contract /"
    echo "your own asset)."

    if $EXTENDED_WORKFLOWS; then
        echo ""
        echo -e "${MAGENTA}${BOLD}NOTE:${NC}${YELLOW} --extended-workflows is enabled."
        echo "This phase specifically searches for endpoints that could"
        echo "potentially leak credentials/configuration (.env, .git, admin panel,"
        echo "cloud config, token/session endpoints). These remain passive GET"
        echo "requests, but make sure your scope allows searching for this kind"
        echo "of sensitive information."
    fi

    if $BURP_ACTIVE_SCAN; then
        echo ""
        echo -e "${RED}${BOLD}ADDITIONAL WARNING:${NC}${YELLOW} --burp-active-scan is enabled."
        echo "This will trigger an ACTIVE SCAN (intrusive/actively attacking endpoints)"
        echo "via the Burp Suite REST API. Make sure your authorization scope"
        echo "explicitly allows active scanning, not just passive recon."
    fi
    echo ""
    read -r -p "Type 'I HAVE AUTHORIZATION' to continue: " confirmation
    if [[ "$confirmation" != "I HAVE AUTHORIZATION" ]]; then
        log_err "Confirmation did not match. Exiting."
        exit 1
    fi
    log_ok "Authorization confirmed. Continuing pipeline..."
}

check_dependencies() {
    section "Dependency Check"
    local required=("subfinder" "httpx" "naabu" "nuclei" "curl" "jq")
    local optional=("assetfinder" "gau" "gowitness" "katana" "urlfinder")
    local missing_required=()

    for tool in "${required[@]}"; do
        if command -v "$tool" &>/dev/null; then
            log_ok "$tool detected"
        else
            log_err "$tool NOT found"
            missing_required+=("$tool")
        fi
    done

    for tool in "${optional[@]}"; do
        if command -v "$tool" &>/dev/null; then
            log_ok "$tool detected (optional)"
        else
            log_warn "$tool not found (optional, related feature will be skipped)"
        fi
    done

    if $USE_KATANA && ! command -v katana &>/dev/null; then
        log_warn "--katana requested but katana is not installed. Active crawl phase will be skipped."
    fi
    if $USE_WEB_ARCHIVES && ! command -v urlfinder &>/dev/null; then
        log_warn "--web-archives requested but urlfinder is not installed. This phase will be skipped."
    fi

    if [[ ${#missing_required[@]} -gt 0 ]]; then
        log_err "The following required tools are not installed: ${missing_required[*]}"
        cat <<EOF

Quick install (ProjectDiscovery toolkit + gau):
  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
  go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
  go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  go install -v github.com/projectdiscovery/katana/cmd/katana@latest
  go install -v github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest
  go install -v github.com/lc/gau/v2/cmd/gau@latest
  go install -v github.com/tomnomnom/assetfinder@latest
  sudo apt install jq curl -y

Make sure \$GOPATH/bin is in your \$PATH. This script will NOT automatically
install tools or modify your shell profile files — please install
manually as needed.
EOF
        exit 1
    fi

    if $BURP_PASSIVE; then
        if check_tcp_port "$BURP_PROXY_HOST" "$BURP_PROXY_PORT"; then
            log_ok "Burp proxy reachable at ${BURP_PROXY_HOST}:${BURP_PROXY_PORT}"
        else
            log_warn "Burp proxy NOT reachable at ${BURP_PROXY_HOST}:${BURP_PROXY_PORT} (make sure Burp is running & the proxy listener is active)"
        fi
    fi
    if $BURP_ACTIVE_SCAN && [[ -z "$BURP_API_KEY" ]]; then
        log_warn "--burp-active-scan is enabled but BURP_API_KEY is not set. This phase will be skipped later."
    fi
}

check_tcp_port() {
    local host="$1" port="$2"
    timeout 3 bash -c "cat < /dev/null > /dev/tcp/${host}/${port}" 2>/dev/null
}

retry() {
    # retry <max_attempts> <delay_seconds> <command...>
    local max="$1" delay="$2"; shift 2
    local n=0
    until "$@"; do
        n=$((n + 1))
        if [[ $n -ge $max ]]; then
            return 1
        fi
        log_warn "Attempt $n/$max failed, retrying in ${delay}s..."
        sleep "$delay"
    done
    return 0
}

should_skip_phase() {
    local marker="$1"
    if $RESUME && [[ -s "$marker" ]]; then
        log_ok "Resume enabled: '$marker' already exists, skipping this phase."
        return 0
    fi
    return 1
}

setup_workspace() {
    section "Setup Workspace"
    OUTDIR="${OUTDIR:-./recon_${DOMAIN}_$(date +%Y%m%d_%H%M%S)}"
    mkdir -p "$OUTDIR"/{subdomains,httpx,ports,urls,screenshots,vulns,report}
    echo "$DOMAIN" > "$OUTDIR/scope.txt"

    LOGFILE="$OUTDIR/pipeline.log"
    exec > >(tee -a "$LOGFILE") 2>&1

    if (( ${#SESSION_HEADERS[@]} > 0 )); then
        SESSION_HEADERS_FILE="$OUTDIR/.session_headers.txt"
        printf '%s\n' "${SESSION_HEADERS[@]}" > "$SESSION_HEADERS_FILE"
        chmod 600 "$SESSION_HEADERS_FILE"
        log_ok "Session headers saved to $SESSION_HEADERS_FILE (permission 600)"
    fi

    log_ok "Workspace created at: $OUTDIR"
    log_ok "Full log saved at: $LOGFILE"
}

notify() {
    [[ -z "$WEBHOOK_URL" ]] && return 0
    curl -s -X POST -H 'Content-Type: application/json' \
        -d "{\"text\": \"[recon_pipeline] $1\"}" "$WEBHOOK_URL" &>/dev/null || true
}

# ─────────────────────────────── Phase 1: Subdomain Enumeration ───────────────────────────────
phase_subdomain_enum() {
    section "Phase 1: Subdomain Enumeration"
    local out="$OUTDIR/subdomains"
    should_skip_phase "$out/all_subdomains.txt" && return

    if $DRY_RUN; then
        log "[DRY-RUN] subfinder -d $DOMAIN -all -silent -o $out/subfinder.txt"
        log "[DRY-RUN] assetfinder --subs-only $DOMAIN"
        log "[DRY-RUN] curl crt.sh?q=%25.$DOMAIN"
        return
    fi

    log "Running subfinder..."
    subfinder -d "$DOMAIN" -all -silent -o "$out/subfinder.txt" 2>/dev/null

    if command -v assetfinder &>/dev/null; then
        log "Running assetfinder..."
        assetfinder --subs-only "$DOMAIN" > "$out/assetfinder.txt" 2>/dev/null
    fi

    log "Querying crt.sh (Certificate Transparency logs, with retry)..."
    fetch_crtsh() {
        curl -s --max-time 15 "https://crt.sh/?q=%25.${DOMAIN}&output=json" -o "$out/.crtsh_raw.json"
    }
    if retry 3 5 fetch_crtsh; then
        jq -r '.[].name_value' "$out/.crtsh_raw.json" 2>/dev/null \
            | sed 's/\*\.//g' | sort -u > "$out/crtsh.txt"
    else
        log_warn "crt.sh query failed after several attempts, skipping this source"
    fi

    log "Merging and deduplicating results..."
    cat "$out"/*.txt 2>/dev/null | sed 's/^\*\.//' | grep -F ".$DOMAIN" \
        | sort -u > "$out/all_subdomains.txt"

    local count
    count=$(wc -l < "$out/all_subdomains.txt" | tr -d ' ')
    log_ok "Found $count unique subdomains → $out/all_subdomains.txt"
    notify "Subdomain enum completed: $count subdomains found for $DOMAIN"
}

# ─────────────────────────────── Phase 2: Live Host Probing (+ Burp passive mirror) ───────────────────────────────
phase_httpx_probe() {
    section "Phase 2: Live Host Probing (httpx)"
    local in="$OUTDIR/subdomains/all_subdomains.txt"
    local out="$OUTDIR/httpx"
    should_skip_phase "$out/httpx_full.json" && return

    if [[ ! -s "$in" ]]; then
        log_warn "No subdomains to probe, skipping this phase."
        return
    fi

    local proxy_flag=""
    if $BURP_PASSIVE; then
        if check_tcp_port "$BURP_PROXY_HOST" "$BURP_PROXY_PORT"; then
            proxy_flag="-http-proxy http://${BURP_PROXY_HOST}:${BURP_PROXY_PORT}"
            log_burp "Traffic will be mirrored to Burp proxy ${BURP_PROXY_HOST}:${BURP_PROXY_PORT} → Site Map populated automatically"
        else
            log_warn "Burp proxy not reachable, continuing without mirroring to Burp"
        fi
    fi

    if $DRY_RUN; then
        log "[DRY-RUN] httpx -l $in -status-code -title -tech-detect -cdn $proxy_flag -json -o $out/httpx_full.json"
        return
    fi

    log "Probing $(wc -l < "$in" | tr -d ' ') hosts with httpx..."
    # shellcheck disable=SC2086
    httpx -l "$in" \
        -silent -threads "$THREADS" \
        -status-code -title -tech-detect -content-length \
        -follow-redirects -ip -cdn \
        $proxy_flag \
        -json -o "$out/httpx_full.json" 2>/dev/null

    jq -r '.url' "$out/httpx_full.json" 2>/dev/null | sort -u > "$out/live_hosts.txt"
    jq -r 'select(.cdn == true) | .url' "$out/httpx_full.json" 2>/dev/null | sort -u > "$out/cdn_hosts.txt"

    local count cdn_count
    count=$(wc -l < "$out/live_hosts.txt" | tr -d ' ')
    cdn_count=$(wc -l < "$out/cdn_hosts.txt" 2>/dev/null | tr -d ' ')
    log_ok "$count live hosts detected → $out/live_hosts.txt"
    [[ "${cdn_count:-0}" -gt 0 ]] && log "Found $cdn_count hosts behind CDN/WAF"
    notify "Live host probing completed: $count live hosts"
}

# ─────────────────────────────── Phase 3: Port Scanning (CDN-aware) ───────────────────────────────
prepare_port_targets() {
    local default_file="$OUTDIR/subdomains/all_subdomains.txt"
    local out="$OUTDIR/ports"

    if ! $SKIP_CDN || [[ ! -s "$OUTDIR/httpx/httpx_full.json" ]]; then
        echo "$default_file"
        return
    fi

    jq -r 'select(.cdn != true) | (.input // .host // .url)' "$OUTDIR/httpx/httpx_full.json" 2>/dev/null \
        | sed -E 's#^https?://##' | cut -d'/' -f1 | sort -u > "$out/targets_noncdn.txt"

    if [[ -s "$out/targets_noncdn.txt" ]]; then
        echo "$out/targets_noncdn.txt"
    else
        echo "$default_file"
    fi
}

phase_port_scan() {
    section "Phase 3: Port Scanning (naabu)"
    local out="$OUTDIR/ports"
    should_skip_phase "$out/open_ports.txt" && return

    local in
    in=$(prepare_port_targets)
    if [[ ! -s "$in" ]]; then
        log_warn "No targets for port scan, skipping."
        return
    fi

    if $SKIP_CDN && [[ "$in" == *"targets_noncdn.txt" ]]; then
        local total noncdn skipped
        total=$(wc -l < "$OUTDIR/subdomains/all_subdomains.txt" | tr -d ' ')
        noncdn=$(wc -l < "$in" | tr -d ' ')
        skipped=$((total - noncdn))
        [[ $skipped -gt 0 ]] && log "Skipping $skipped hosts behind CDN/WAF for port scan (--skip-cdn)"
    fi

    local port_range="top-1000"
    local port_flag="-top-ports 1000"
    if $FULL_SCAN; then
        port_flag="-p -"
        port_range="1-65535 (full)"
    fi

    if $DRY_RUN; then
        log "[DRY-RUN] naabu -l $in $port_flag -silent -rate 1000 -o $out/open_ports.txt"
        return
    fi

    log "Running naabu (range: $port_range)..."
    # shellcheck disable=SC2086
    naabu -l "$in" $port_flag -silent -rate 1000 \
        -o "$out/open_ports.txt" 2>/dev/null

    local count
    count=$(wc -l < "$out/open_ports.txt" 2>/dev/null | tr -d ' ')
    log_ok "$count open host:port combinations → $out/open_ports.txt"
}

# ─────────────────────────────── Phase 4: URL / Endpoint Discovery ───────────────────────────────
# Multi-tier URL normalization + dedup: templating path segments (uuid/hex-id/numeric-id
# turned into placeholders) + sorting parameter keys into a "signature", so URLs
# that share the same scope (differing only in value) aren't counted repeatedly. Adapted from
# the awk logic in yublueflower.
normalize_and_dedupe_urls() {
    local infile="$1" outfile="$2"
    gawk -F'?' '
    {
        path = $1
        nseg = split(path, seg, "/")
        path = ""
        for (i = 1; i <= nseg; i++) {
            if (seg[i] ~ /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/) {
                seg[i] = ":uuid"
            } else if (seg[i] ~ /^[0-9a-fA-F]{24,}$/) {
                seg[i] = ":rid"
            } else if (length(seg[i]) >= 14 && seg[i] ~ /^[A-Za-z0-9_-]+$/ && seg[i] ~ /[A-Za-z]/ && seg[i] ~ /[0-9]/) {
                seg[i] = ":rid"
            } else if (seg[i] ~ /^[0-9]+$/) {
                seg[i] = ":id"
            }
            path = (path == "" ? seg[i] : path "/" seg[i])
        }
        sig = path
        if ($2) {
            delete ordered; delete keys; c = 0
            n = split($2, p, "&")
            for (i = 1; i <= n; i++) {
                split(p[i], kv, "=")
                if (kv[1] != "" && !keys[kv[1]]++) { ordered[++c] = kv[1] }
            }
            for (i = 1; i <= c; i++) {
                for (j = i + 1; j <= c; j++) {
                    if (ordered[i] > ordered[j]) { tmp = ordered[i]; ordered[i] = ordered[j]; ordered[j] = tmp }
                }
            }
            for (i = 1; i <= c; i++) { sig = sig "&" ordered[i] }
        }
        if (!seen[sig]++) { print }
    }' "$infile" | sort -u > "$outfile"
}

# Tracking-parameter patterns discarded during active crawling (from yublueflower), so
# URLs with utm_source/fbclid/etc. don't flood the dedup results.
TRACKING_PARAM_REGEX='(\?|&)(utm_(source|medium|campaign|term|content)|fbclid|gclid|yclid|msclkid|ga(_cid|id)?|mc_(cid|eid)|ref(_src|_url|id)?|src|source(Name)?|from|via|tracking|track(id)?|click|pixel|_gl|twclid)='
STATIC_ASSET_REGEX='\.(jpg|jpeg|png|gif|svg|ico|css|woff2?|ttf|eot|mp4|mp3)(\?|$)'

# Sensitive endpoint patterns for --extended-workflows (admin/auth/cloud-config/secrets),
# adapted from yublueflower.
SENSITIVE_ENDPOINT_REGEX='(\.(env|git)(\?|$)|/(config|auth|oauth|sso|admin|graphql|swagger|openapi|internal|private|debug|staging|firebase|aws|gcp|azure|payment|billing|webhook|settings)[^/]*(\?|$)|\.(yml|yaml)(\?|$)|/(api(/v[0-9]+)?|rest|restapi|graphql|graphiql|swagger(-ui)?|openapi|api[-_]?docs|redoc|oauth2?|oidc|saml|authorize|authorization|authentication|login|logout|signin|signup|register|token|tokens|access[-_]?token|refresh[-_]?token|session|sessions|jwt|jwks?|webhook(s)?|callback(s)?|internal|private|admin(istrator)?|management|credential(s)?)(/|\?|$)'

phase_url_discovery() {
    section "Phase 4: URL & Endpoint Discovery"
    local out="$OUTDIR/urls"
    should_skip_phase "$out/all_urls.txt" && return

    local -a header_args=()
    [[ -n "$SESSION_HEADERS_FILE" ]] && header_args=(-H "$SESSION_HEADERS_FILE")

    : > "$out/.sources_raw.txt"

    # --- Passive source: gau (historical URLs / Wayback) ---
    if command -v gau &>/dev/null; then
        if $DRY_RUN; then
            log "[DRY-RUN] echo $DOMAIN | gau --threads $THREADS --subs"
        else
            log "Collecting historical URLs from gau..."
            echo "$DOMAIN" | gau --threads "$THREADS" --subs 2>/dev/null >> "$out/.sources_raw.txt"
        fi
    else
        log_warn "gau is not installed, skipping this passive source."
    fi

    # --- Alternative passive source: urlfinder (--web-archives) ---
    if $USE_WEB_ARCHIVES; then
        if ! command -v urlfinder &>/dev/null; then
            log_warn "--web-archives requested but urlfinder is missing, skipping."
        elif $DRY_RUN; then
            log "[DRY-RUN] urlfinder -d $DOMAIN -silent"
        else
            log "Collecting historical URLs via urlfinder (--web-archives)..."
            timeout --foreground -k 5s 10m urlfinder -d "$DOMAIN" -silent 2>/dev/null >> "$out/.sources_raw.txt"
        fi
    fi

    # --- Active source: katana (JS-aware crawl, --katana) ---
    if $USE_KATANA; then
        if ! command -v katana &>/dev/null; then
            log_warn "--katana requested but katana is missing, skipping."
        elif [[ ! -s "$OUTDIR/httpx/live_hosts.txt" ]]; then
            log_warn "No live hosts for katana crawl, skipping."
        elif $DRY_RUN; then
            log "[DRY-RUN] katana -u <live_hosts> -js-crawl -silent"
        else
            log "Running katana (active JS-aware crawling)..."
            while IFS= read -r target; do
                [[ -z "$target" ]] && continue
                timeout --foreground -k 5s 5m katana "${header_args[@]}" -u "$target" \
                    -js-crawl -silent 2>/dev/null
            done < "$OUTDIR/httpx/live_hosts.txt" | perl -pe 's/[^[:print:]\t\r\n]//g' \
                | grep -Ev "$STATIC_ASSET_REGEX" \
                | grep -Ev "$TRACKING_PARAM_REGEX" \
                >> "$out/.sources_raw.txt"
        fi
    fi

    if [[ ! -s "$out/.sources_raw.txt" ]]; then
        log_warn "No URL sources were successfully collected, skipping the rest of this phase."
        rm -f "$out/.sources_raw.txt"
        return
    fi

    log "Normalizing & deduplicating URLs (path templating + parameter signature)..."
    sort -u "$out/.sources_raw.txt" > "$out/all_urls_raw.txt"
    normalize_and_dedupe_urls "$out/all_urls_raw.txt" "$out/all_urls.txt"
    rm -f "$out/.sources_raw.txt"

    grep -E '\.(js)(\?|$)' "$out/all_urls.txt" > "$out/js_files.txt" 2>/dev/null
    grep -E '\?.+=' "$out/all_urls.txt" > "$out/urls_with_params.txt" 2>/dev/null
    grep -Ei '(admin|api|backup|config|\.env|swagger|graphql|internal|debug)' \
        "$out/all_urls.txt" > "$out/interesting_urls.txt" 2>/dev/null

    log_ok "$(wc -l < "$out/all_urls_raw.txt" | tr -d ' ') raw URLs → $(wc -l < "$out/all_urls.txt" | tr -d ' ') after dedup"
    log_ok "$(wc -l < "$out/interesting_urls.txt" 2>/dev/null | tr -d ' ') 'interesting' URLs (admin/api/config/etc.)"

    # --- Extended workflows: specifically search for sensitive endpoints, verify they're live (200) ---
    if $EXTENDED_WORKFLOWS; then
        log_ext "Searching for sensitive endpoints (auth/admin/cloud-config/secrets)..."
        if $DRY_RUN; then
            log "[DRY-RUN] grep -E \$SENSITIVE_ENDPOINT_REGEX all_urls.txt | httpx -match-code 200"
        else
            grep -Ei "$SENSITIVE_ENDPOINT_REGEX" "$out/all_urls.txt" 2>/dev/null \
                | sort -u > "$out/.extended_candidates.txt"

            if [[ -s "$out/.extended_candidates.txt" ]]; then
                httpx "${header_args[@]}" -l "$out/.extended_candidates.txt" \
                    -silent -match-code 200 -status-code -title \
                    -json -o "$out/extended_sensitive_endpoints.json" 2>/dev/null
                jq -r '.url' "$out/extended_sensitive_endpoints.json" 2>/dev/null \
                    | sort -u > "$out/extended_sensitive_endpoints.txt"

                local ext_count
                ext_count=$(wc -l < "$out/extended_sensitive_endpoints.txt" 2>/dev/null | tr -d ' ')
                if [[ "${ext_count:-0}" -gt 0 ]]; then
                    log_warn "$ext_count live sensitive endpoints detected → $out/extended_sensitive_endpoints.txt"
                    notify "🔑 $ext_count sensitive endpoints (extended-workflows) live on $DOMAIN"
                else
                    log_ok "No candidate sensitive endpoints are live (200)"
                fi
            else
                log_ok "No sensitive endpoint candidates found from crawl results"
            fi
            rm -f "$out/.extended_candidates.txt"
        fi
    fi
}

# ─────────────────────────────── Phase 5: Subdomain Takeover Check ───────────────────────────────
phase_takeover_check() {
    section "Phase 5: Subdomain Takeover Check"
    local in="$OUTDIR/subdomains/all_subdomains.txt"
    local out="$OUTDIR/vulns/takeover_results.jsonl"
    should_skip_phase "$out" && return

    if [[ ! -s "$in" ]]; then
        log_warn "No subdomains, skipping takeover check."
        return
    fi

    if $DRY_RUN; then
        log "[DRY-RUN] nuclei -l $in -t http/takeovers/ -silent -jsonl -o $out"
        return
    fi

    log "Running nuclei takeover templates..."
    nuclei -l "$in" -t http/takeovers/ -silent -jsonl -o "$out" 2>/dev/null

    local count
    count=$(wc -l < "$out" 2>/dev/null | tr -d ' ')
    if [[ "${count:-0}" -gt 0 ]]; then
        log_warn "$count possible subdomain takeover(s) detected!"
        notify "🚨 $count possible subdomain takeover(s) on $DOMAIN"
    else
        log_ok "No indication of subdomain takeover"
    fi
}

# ─────────────────────────────── Phase 6: Screenshots ───────────────────────────────
phase_screenshots() {
    section "Phase 6: Screenshotting (optional)"
    local in="$OUTDIR/httpx/live_hosts.txt"
    local out="$OUTDIR/screenshots"
    should_skip_phase "$out/.done" && return

    if ! command -v gowitness &>/dev/null; then
        log_warn "gowitness is not installed, skipping this phase."
        return
    fi
    if [[ ! -s "$in" ]]; then
        log_warn "No live hosts, skipping screenshots."
        return
    fi

    if $DRY_RUN; then
        log "[DRY-RUN] gowitness file -f $in -P $out --no-http"
        return
    fi

    log "Taking screenshots of live hosts..."
    gowitness file -f "$in" -P "$out" --no-http 2>/dev/null || log_warn "gowitness failed on some targets"
    touch "$out/.done"
    log_ok "Screenshots saved to $out"
}

# ─────────────────────────────── Phase 7: Vulnerability Scanning ───────────────────────────────
phase_nuclei_scan() {
    section "Phase 7: Vulnerability Scanning (nuclei)"
    local in="$OUTDIR/httpx/live_hosts.txt"
    local out="$OUTDIR/vulns"
    should_skip_phase "$out/nuclei_results.jsonl" && return

    if [[ ! -s "$in" ]]; then
        log_warn "No live hosts for nuclei, skipping."
        return
    fi

    local severity="$NUCLEI_SEVERITY"
    $FULL_SCAN && severity="info,low,medium,high,critical"

    if $DRY_RUN; then
        log "[DRY-RUN] nuclei -l $in -severity $severity -jsonl -o $out/nuclei_results.jsonl"
        return
    fi

    log "Running nuclei (severity: $severity)..."
    log_warn "Update templates first if it's been a while: nuclei -update-templates"

    nuclei -l "$in" \
        -severity "$severity" \
        -silent -rate-limit "$THREADS" \
        -jsonl -o "$out/nuclei_results.jsonl" 2>/dev/null

    local count
    count=$(wc -l < "$out/nuclei_results.jsonl" 2>/dev/null | tr -d ' ')
    if [[ "${count:-0}" -gt 0 ]]; then
        log_warn "$count finding(s) detected! Check $out/nuclei_results.jsonl"
        notify "⚠️ nuclei found $count potential vulnerabilities on $DOMAIN"
    else
        log_ok "No significant findings from nuclei"
    fi
}

# ─────────────────────────────── Phase 8: Burp Suite Active Scan (optional, INTRUSIVE) ───────────────────────────────
phase_burp_active_scan() {
    section "Phase 8: Burp Suite Active Scan Trigger (REST API)"
    local live="$OUTDIR/httpx/live_hosts.txt"
    local out="$OUTDIR/report/burp_scan_response.json"

    if ! $BURP_ACTIVE_SCAN; then
        return
    fi
    if [[ -z "$BURP_API_KEY" ]]; then
        log_warn "BURP_API_KEY is not set, skipping active scan trigger."
        return
    fi
    if [[ ! -s "$live" ]]; then
        log_warn "No live hosts to send to Burp, skipping."
        return
    fi

    if $DRY_RUN; then
        log "[DRY-RUN] POST ${BURP_API_URL}/${BURP_API_KEY}/v0.1/scan with $(wc -l < "$live" | tr -d ' ') URLs"
        return
    fi

    log_burp "Sending $(wc -l < "$live" | tr -d ' ') URLs to the Burp Suite REST API for active scan..."
    log_warn "Note: the REST API endpoint format may vary between Burp Suite versions."
    log_warn "If this request fails, check the Swagger docs at ${BURP_API_URL}/swagger.json or Burp > Settings > Suite > REST API."

    local endpoint="${BURP_API_URL%/}/${BURP_API_KEY}/v0.1/scan"
    local urls_json payload
    urls_json=$(jq -R -s -c 'split("\n") | map(select(length > 0))' "$live")
    payload=$(jq -n --argjson urls "$urls_json" '{urls: $urls}')

    send_to_burp() {
        curl -s -w '\n%{http_code}' -X POST \
            -H 'Content-Type: application/json' \
            -d "$payload" \
            "$endpoint" > "$OUTDIR/.burp_response_tmp"
        local code
        code=$(tail -n1 "$OUTDIR/.burp_response_tmp")
        [[ "$code" =~ ^2 ]]
    }

    if retry 2 5 send_to_burp; then
        head -n -1 "$OUTDIR/.burp_response_tmp" > "$out"
        log_ok "Active scan successfully triggered. Response saved to $out"
        notify "🎯 Burp active scan triggered for $DOMAIN"
    else
        log_err "Failed to trigger active scan after several attempts. Check $OUTDIR/.burp_response_tmp"
    fi
    rm -f "$OUTDIR/.burp_response_tmp"
}

# ─────────────────────────────── Report Summary ───────────────────────────────
generate_summary() {
    section "Summary"
    local elapsed=$(( $(date +%s) - START_TIME ))
    cat <<EOF | tee "$OUTDIR/report/summary.txt"

${BOLD}目付 (metsuke) — Recon Summary — $DOMAIN${NC}
Duration          : ${elapsed}s
Output            : $OUTDIR
Subdomains        : $(wc -l < "$OUTDIR/subdomains/all_subdomains.txt" 2>/dev/null | tr -d ' ')
Live hosts        : $(wc -l < "$OUTDIR/httpx/live_hosts.txt" 2>/dev/null | tr -d ' ')
Unique URLs       : $(wc -l < "$OUTDIR/urls/all_urls.txt" 2>/dev/null | tr -d ' ')
Sensitive endpoints: $(wc -l < "$OUTDIR/urls/extended_sensitive_endpoints.txt" 2>/dev/null | tr -d ' ')
Takeover findings : $(wc -l < "$OUTDIR/vulns/takeover_results.jsonl" 2>/dev/null | tr -d ' ')
Nuclei findings   : $(wc -l < "$OUTDIR/vulns/nuclei_results.jsonl" 2>/dev/null | tr -d ' ')
EOF
    log_ok "Done. All results saved to: $OUTDIR"
}

# ─────────────────────────────── Argument Parsing ───────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        -d) DOMAIN="$2"; shift 2 ;;
        -o) OUTDIR="$2"; shift 2 ;;
        -t) THREADS="$2"; shift 2 ;;
        --full) FULL_SCAN=true; shift ;;
        --config) CONFIG_FILE="$2"; shift 2 ;;
        --sequential) PARALLEL=false; shift ;;
        --resume) RESUME=true; shift ;;
        --skip-cdn) SKIP_CDN=true; shift ;;
        --dry-run) DRY_RUN=true; shift ;;
        --katana) USE_KATANA=true; shift ;;
        --web-archives) USE_WEB_ARCHIVES=true; shift ;;
        --extended-workflows) EXTENDED_WORKFLOWS=true; shift ;;
        --session-header) SESSION_HEADERS+=("$2"); shift 2 ;;
        --burp) BURP_PASSIVE=true; shift ;;
        --burp-proxy) BURP_PROXY_HOST="${2%%:*}"; BURP_PROXY_PORT="${2##*:}"; shift 2 ;;
        --burp-active-scan) BURP_ACTIVE_SCAN=true; shift ;;
        --burp-api-url) BURP_API_URL="$2"; shift 2 ;;
        --burp-api-key) BURP_API_KEY="$2"; shift 2 ;;
        -h|--help) usage ;;
        *) log_err "Unrecognized argument: $1"; usage ;;
    esac
done

[[ -n "$CONFIG_FILE" && -f "$CONFIG_FILE" ]] && source "$CONFIG_FILE"
[[ -z "$DOMAIN" ]] && { log_err "Domain is required (-d)"; usage; }

# ─────────────────────────────── Main ───────────────────────────────
main() {
    print_banner
    confirm_authorization
    check_dependencies
    setup_workspace

    phase_subdomain_enum
    phase_httpx_probe
    phase_port_scan
    phase_url_discovery
    phase_takeover_check
    phase_screenshots
    phase_nuclei_scan
    phase_burp_active_scan

    generate_summary
}

main
