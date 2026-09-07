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
#   cloud config, token/session endpoints), and fetches JS files to look for
#   hardcoded secrets. These remain passive GET requests (not exploits), but make
#   sure your scope allows this kind of sensitive information search.
#
# Required dependencies : subfinder, httpx, naabu, nuclei, curl, jq, (g)awk
# Optional dependencies : assetfinder, gau, gowitness, katana, urlfinder, perl,
#                         GNU coreutils timeout(1)
# Burp Suite (optional) : Burp Pro/Community running locally for passive proxy
#                         mirroring; Burp Pro + REST API for active scan triggering


set -uo pipefail
IFS=$'\n\t'

# ─────────────────────────────── Config & Globals ───────────────────────────────
SCRIPT_VERSION="4.0.0"
RAW_ARGS=("$@")                 # kept for the (redacted) audit record
DOMAIN=""
DOMAIN_ESCAPED=""               # regex-escaped, used in anchored scope filter
OUTDIR=""
THREADS=50
FULL_SCAN=false
RESUME=false
SKIP_CDN=false
DRY_RUN=false
NUCLEI_SEVERITY="low,medium,high,critical"
NUCLEI_TAGS=""                  # optional: restrict nuclei to specific tags
UPDATE_TEMPLATES=false          # --update-templates : run nuclei -update-templates first
WEBHOOK_URL="${RECON_WEBHOOK_URL:-}"
NO_NOTIFY=false
RATE_LIMIT=0                    # 0 = no explicit limit; >0 = requests/second where supported
HTTP_TIMEOUT=10                 # per-request timeout for httpx / curl
PARALLEL_MODE=false             # default sequential (safest); --parallel to enable

# Katana / active crawling
USE_KATANA=false
EXTENDED_WORKFLOWS=false
USE_WEB_ARCHIVES=false
PASSIVE_ONLY=false              # --passive-only : zero-contact OSINT mode
NO_INTERACTSH=false             # --no-interactsh : disable nuclei OOB callbacks
declare -a SESSION_HEADERS=()   # --session-header "Cookie: ..." (visible in ps — prefer file)
SESSION_HEADERS_FILE=""         # --session-header-file <file> (secret stays out of argv)
SESSION_HEADERS_INTERNAL=""     # where CLI headers get stored (mode 600)
declare -a EXCLUDE_REGEXES=()   # --exclude-sub <regex> (repeatable)

# Burp Suite integration (all optional, default off)
BURP_PASSIVE=false
BURP_ACTIVE_SCAN=false
BURP_PROXY_HOST="127.0.0.1"
BURP_PROXY_PORT="8080"
BURP_API_URL="http://127.0.0.1:1337"
BURP_API_KEY="${BURP_API_KEY:-}"
CLI_API_KEY=false

CONFIG_FILE=""
START_TIME=$(date +%s)
START_ISO=$(date '+%Y-%m-%dT%H:%M:%S%z')
LOGFILE=""
AUDITLOG=""
LOCKDIR=""
TEE_PID=""
AWK_BIN=""
TIMEOUT_BIN=""

# JS secret scan tuning (config-file overridable)
MAX_JS_FILES=500
JS_CONCURRENCY=10

declare -a HEADER_ARGS=()       # built once from CLI headers + header file

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
die()      { log_err "$*"; exit 1; }

count_lines() {
    if [[ -f "$1" && -s "$1" ]]; then
        wc -l < "$1" | tr -d '[:space:]'
    else
        echo 0
    fi
}

audit() {
    local line="[$(date '+%Y-%m-%dT%H:%M:%S%z')] $*"
    if [[ -n "${AUDITLOG:-}" ]]; then
        echo "$line" >> "$AUDITLOG" 2>/dev/null || true
    fi
    echo -e "${MAGENTA}[AUDIT]${NC} $*" >&2
}

# Rebuild the CLI arguments with secret values redacted, for the audit log.
redact_args() {
    local -a out=()
    local a prev=""
    for a in "$@"; do
        case "$prev" in
            --session-header|--burp-api-key) out+=("REDACTED") ;;
            *) out+=("$a") ;;
        esac
        prev="$a"
    done
    printf '%s ' ${out[@]+"${out[@]}"}
}

# take_arg <flag> <value> — exits via usage() if the value is missing.
take_arg() {
    if [[ $# -lt 2 ]]; then
        log_err "Option '$1' requires a value."
        usage
    fi
    ARG_VALUE="$2"
}

print_banner() {
    echo -e "${CYAN}"
    cat << "EOF"
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣤⣤⣤⣤⣤⣤⣤⣤⣤⣄⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⠖⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠉⠉⠉⠓⠒⣲⠶⠦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⠞⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡤⠖⠋⠀⠀⠀⠘⢧⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣠⠾⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⠴⠚⠉⠀⠀⠀⠀⠀⠀⠀⠈⢷⡀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣠⠞⠁⠸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⠴⠚⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢷⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣼⠃⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣤⣤⠴⠶⠚⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣧⠀⠀⠀⠀⠀
⠀⠀⢰⡇⠀⠀⠀⠳⠤⠤⠤⠤⠶⠒⠛⠛⠉⠉⠉⠀⠀⠀⣀⣤⡔⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣤⠿⠂⠀⠀⠀⠀
⠀⠀⠈⢧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡤⠖⠉⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢈⡿⠃⠀⠀⠀⠀⠀
⠀⠀⠀⠈⢣⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⠴⠾⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⡠⠤⢄⣖⠞⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠙⢦⡀⠀⠀⢀⣠⠤⠲⡍⠀⠀⠀⠈⠻⣷⢤⡀⠀⠀⠀⢀⣀⣤⢤⣶⣲⣯⠭⠵⠓⠒⢘⠏⢹⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠈⠓⠚⠉⢹⡀⠀⢸⠀⠀⠀⠀⠀⠀⠙⠯⣖⣲⠬⠿⠒⠛⠉⠉⠀⠀⠀⠀⠀⢀⠏⠀⢸⠀⣀⠴⠚⠉⢻⣦⠀⠀
⠀⣠⠖⢦⣄⡀⠀⠀⠀⠀⠀⠀⢧⠀⢸⣀⠀⠀⠀⠀⠀⢀⠆⠀⠀⠀⠐⡆⠀⠀⠀⠀⠀⠀⠀⠀⢸⣀⣠⠟⠉⠀⠀⠀⠀⠀⢋⡆⠀
⠸⠁⠀⠀⠀⠈⠑⠢⢄⣀⣀⡤⠞⠛⣉⠁⠀⠀⠀⠀⠀⢸⡀⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠳⣦⡀⠀⠀⣀⠞⠉⠁⠀
⠱⣤⣄⠀⠀⠀⠀⠀⠸⣿⡄⠀⠐⢻⣿⣿⣿⣦⡀⠀⠀⠀⠳⡀⠀⣠⠞⠁⠀⠀⠀⣀⣀⣀⣀⠀⠀⠀⠀⠀⠈⣧⠤⠊⠁⠀⠀⠀⠀
⠀⠀⠈⠳⢤⣀⠀⠀⠀⠈⢻⡄⠀⠈⢿⣿⣿⣿⣿⣆⠀⠀⠀⡼⢸⡁⢀⣠⣤⣶⣿⢿⣿⡟⠋⠉⠀⠀⠀⢀⡼⠁⠀⠀⠀⠀⠀⠀⠀           ⠀
⠀⠀⠀⠀⠀⠈⠙⠲⠤⣀⣸⡟⠀⠙⠺⢿⣿⣿⣿⣿⡷⠶⢻⣥⣼⡛⠿⣿⣯⣿⣿⣿⣿⣁⣤⠄⠀⠀⠀⢸⡁⠀⠀⠀⠀⠀⠀⠀⠀        M E T S U K E
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡟⠁⠀⠐⠚⢉⡵⠟⠋⠁⠀⠀⣿⣿⣿⡇⠀⠈⢻⣿⡿⢿⣿⡯⠷⠀⠀⠀⠀⠈⢧⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠟⠋⠉⠉⠈⠉⢹⠦⣄⠀⠀⠀⠀⠻⠛⠛⠃⠀⠀⠀⠀⠉⠀⠀⠀⢀⣤⠒⡟⠉⠒⠺⠃⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⠼⡆⠈⢣⠀⡀⢀⠀⠀⠀⡤⡄⢠⡄⠀⡄⢠⠀⣴⠏⠁⡼⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡤⠒⠉⠀⠀⢣⢰⣉⡖⢣⡜⣿⣠⣄⣧⣀⣨⣧⢤⣵⡾⡔⢁⡴⠊⠀⠀⠀⠉⢳⡄⠀⠀⠀⠀⠀⠀⠀⠀
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
  -d <domain>        Target domain (required), e.g.: example.com
  -o <dir>           Output directory (default: ./recon_<domain>_<timestamp>)
  -t <threads>       Number of concurrent threads (default: 50)
  --full             Aggressive mode: full port scan (1-65535) + all nuclei severities
  --config <file>    Load DEFAULT options from a config file (sourced before CLI
                     parsing, so CLI flags always win). Bash syntax, chmod 600.
                     Recognized keys: THREADS, NUCLEI_SEVERITY, NUCLEI_TAGS,
                     RATE_LIMIT, HTTP_TIMEOUT, WEBHOOK_URL, BURP_*, MAX_JS_FILES...
  --timeout <sec>    Per-request HTTP timeout (default: 10, range 3-300)
  --rate-limit <rps> Requests/second cap for httpx/naabu/nuclei (default: off)
  -V | --version     Print version and exit
  -h                 Show this help

Scope & safety options:
  --exclude-sub <regex>  ERE matched per line; matching subdomains are pruned
                         BEFORE any request is sent (repeatable). Recommended for
                         known out-of-scope assets.
  --passive-only     Zero-contact mode: only third-party OSINT sources
                     (subfinder / crt.sh / gau). No direct requests to the target.
  --no-interactsh    Disable nuclei OOB (interact.sh) callbacks — use when your
                     scope forbids outbound DNS/HTTP callbacks.
  --no-notify        Disable webhook notifications for this run.
  --resume           Skip phases whose output already exists from a previous run
  --dry-run          Show the commands that would run without executing them
  --skip-cdn         Skip port scanning for hosts detected behind a CDN/WAF

Performance options:
  --sequential       Run all phases sequentially (default, safest)
  --parallel         Run port scan & URL discovery concurrently (higher request rate)

Advanced URL discovery options:
  --katana                    Active crawling with katana (JS-aware) in addition to gau
  --web-archives              Use urlfinder (wayback/CT etc.) in addition to gau
  --extended-workflows        Sensitive endpoint detection (admin/auth/cloud/.env/.git)
                              + JS hardcoded-secret scanning (passive GETs only)
  --session-header "H: V"     Extra header for crawling (e.g. Cookie), repeatable.
                              WARNING: visible in 'ps' — prefer --session-header-file.
  --session-header-file <f>   File with one "Header: value" per line (chmod 600).

Nuclei options:
  --nuclei-severity <list>    Comma list (default: low,medium,high,critical)
  --nuclei-tags <tags>        Restrict nuclei to specific tags (default: all)
  --update-templates          Run 'nuclei -update-templates' before scanning

Burp Suite integration (optional, default OFF):
  --burp                    Mirror httpx traffic to Burp proxy (populates Site Map)
  --burp-proxy <host:port>  Burp proxy address (default: 127.0.0.1:8080)
  --burp-active-scan        Trigger an ACTIVE SCAN via Burp REST API (INTRUSIVE!)
  --burp-api-url <url>      Burp REST API address (default: http://127.0.0.1:1337)
  --burp-api-key <key>      Burp REST API key (visible in 'ps' — prefer the
                            BURP_API_KEY env var or a chmod-600 config file)

Examples:
  $0 -d example.com
  $0 -d example.com -o ./results -t 100 --full --resume
  $0 -d example.com --passive-only
  $0 -d example.com --exclude-sub '^(dev|internal|vpn)\.' --katana
  $0 -d example.com --session-header-file ./cookies.txt --katana
  $0 -d example.com --extended-workflows --no-interactsh
  $0 -d example.com --burp --burp-proxy 127.0.0.1:8080
  $0 -d example.com --burp-active-scan --burp-api-key abcd1234

 ${YELLOW}IMPORTANT: Only use this against targets for which you already have explicit permission.${NC}
EOF
    exit 1
}

confirm_authorization() {
    if $DRY_RUN; then
        log "DRY-RUN mode: no requests will be sent; skipping interactive prompt."
        audit "event=authorization mode=dry-run target=$DOMAIN"
        return 0
    fi

    echo -e "${YELLOW}${BOLD}"
    echo "════════════════════════════════════════════════════════════"
    echo " AUTHORIZATION CONFIRMATION"
    echo "════════════════════════════════════════════════════════════${NC}"
    echo "Target : ${BOLD}${DOMAIN}${NC}"
    echo "Make sure you have explicit permission to perform security"
    echo "testing against this target (bug bounty scope / pentest contract /"
    echo "your own asset)."

    if $PASSIVE_ONLY; then
        echo ""
        echo -e "${CYAN}${BOLD}NOTE:${NC}${YELLOW} --passive-only is enabled: no direct requests will"
        echo "be sent to the target — only third-party OSINT sources are queried."
    fi

    if $EXTENDED_WORKFLOWS; then
        echo ""
        echo -e "${MAGENTA}${BOLD}NOTE:${NC}${YELLOW} --extended-workflows is enabled."
        echo "This phase specifically searches for endpoints that could"
        echo "potentially leak credentials/configuration (.env, .git, admin panel,"
        echo "cloud config, token/session endpoints), and fetches JS files to look"
        echo "for hardcoded secrets. These remain passive GET requests, but make"
        echo "sure your scope allows searching for this kind of sensitive information."
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
        audit "event=authorization result=REFUSED target=$DOMAIN"
        die "Confirmation did not match. Exiting."
    fi
    audit "event=authorization result=confirmed user=$(id -un) target=$DOMAIN"
    log_ok "Authorization confirmed. Continuing pipeline..."
}

check_dependencies() {
    section "Dependency Check"
    local -a required=(subfinder curl jq)
    $PASSIVE_ONLY || required+=(httpx naabu nuclei)
    local -a optional=("assetfinder" "gau" "gowitness" "katana" "urlfinder" "perl")
    local -a missing_required=()
    local tool

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
            log_warn "$tool not found (optional — related features will be skipped)"
        fi
    done

    # awk is required by URL normalization
    if command -v gawk &>/dev/null; then
        AWK_BIN="gawk"; log_ok "gawk detected"
    elif command -v awk &>/dev/null; then
        AWK_BIN="awk"; log_ok "awk detected"
    else
        log_err "awk/gawk NOT found"
        missing_required+=("awk")
    fi

    # GNU coreutils timeout (optional — per-phase timeouts degrade gracefully)
    TIMEOUT_BIN="$(command -v timeout || command -v gtimeout || true)"
    if [[ -z "$TIMEOUT_BIN" ]]; then
        log_warn "timeout(1) not found — per-phase timeouts disabled"
    fi

    if $USE_KATANA && ! command -v katana &>/dev/null; then
        log_warn "--katana requested but katana is not installed. Active crawl phase will be skipped."
    fi
    if $USE_WEB_ARCHIVES && ! command -v urlfinder &>/dev/null; then
        log_warn "--web-archives requested but urlfinder is not installed. This phase will be skipped."
    fi
    if $PASSIVE_ONLY && ! command -v gau &>/dev/null && ! $USE_WEB_ARCHIVES; then
        log_warn "passive-only mode without gau/urlfinder — URL discovery will be empty."
    fi

    if [[ ${#missing_required[@]} -gt 0 ]]; then
        log_err "The following required tools are not installed: ${missing_required[*]}"
        cat <<EOF

Quick install (ProjectDiscovery toolkit + gau + awk):
  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
  go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
  go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  go install -v github.com/projectdiscovery/katana/cmd/katana@latest
  go install -v github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest
  go install -v github.com/lc/gau/v2/cmd/gau@latest
  go install -v github.com/tomnomnom/assetfinder@latest
  sudo apt install jq curl gawk -y

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
            log_warn "Burp proxy NOT reachable at ${BURP_PROXY_HOST}:${BURP_PROXY_PORT} (is the listener active?)"
        fi
    fi
    if $BURP_ACTIVE_SCAN && [[ -z "$BURP_API_KEY" ]]; then
        log_warn "--burp-active-scan is enabled but BURP_API_KEY is not set. This phase will be skipped later."
    fi
    if $CLI_API_KEY; then
        log_warn "Burp API key passed on the command line is visible in 'ps aux' — prefer the BURP_API_KEY env var or a chmod-600 config file."
    fi
}

check_tcp_port() {
    local host="$1" port="$2"
    # host/port are validated against strict character classes before use
    if [[ -n "$TIMEOUT_BIN" ]]; then
        "$TIMEOUT_BIN" 3 bash -c "cat < /dev/null > /dev/tcp/${host}/${port}" 2>/dev/null
    else
        bash -c "cat < /dev/null > /dev/tcp/${host}/${port}" 2>/dev/null
    fi
}

# run_with_timeout <seconds> <command...> — uses GNU timeout when available.
run_with_timeout() {
    local secs="$1"; shift
    if [[ -n "$TIMEOUT_BIN" ]]; then
        "$TIMEOUT_BIN" --foreground -k 5s "$secs" "$@"
    else
        "$@"
    fi
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

notify() {
    if [[ -z "$WEBHOOK_URL" ]] || $NO_NOTIFY; then return 0; fi
    local payload
    payload=$(jq -n --arg t "[metsuke] $1" '{text: $t}') || return 0
    curl -s --max-time 10 -X POST -H 'Content-Type: application/json' \
        -d "$payload" "$WEBHOOK_URL" &>/dev/null || true
}

# Build -H "K: V" arguments from both the internal (CLI-derived) file and the
# user-provided --session-header-file. FIX: v3 passed a file PATH to -H.
build_header_args() {
    HEADER_ARGS=()
    local src h
    for src in "$SESSION_HEADERS_INTERNAL" "$SESSION_HEADERS_FILE"; do
        [[ -n "$src" && -s "$src" ]] || continue
        while IFS= read -r h; do
            [[ -n "$h" ]] && HEADER_ARGS+=(-H "$h")
        done < "$src"
    done
    if [[ ${#HEADER_ARGS[@]} -gt 0 ]]; then
        log "Using ${#HEADER_ARGS[@]} session header(s) for authenticated crawling"
    fi
}

# ─────────────────────────────── Input Validation ───────────────────────────────
validate_inputs() {
    DOMAIN=$(printf '%s' "$DOMAIN" | tr '[:upper:]' '[:lower:]')

    local domain_re='^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$'
    [[ "$DOMAIN" =~ $domain_re ]] || die "Invalid or unsafe domain value: '$DOMAIN' (must be a plain DNS name)"
    DOMAIN_ESCAPED="${DOMAIN//./\\.}"   # for the anchored scope regex

    [[ "$THREADS" =~ ^[0-9]+$ ]] || die "Threads must be numeric (got '$THREADS')"
    (( THREADS >= 1 && THREADS <= 500 )) || die "Threads must be between 1 and 500"

    if [[ "$RATE_LIMIT" != "0" ]]; then
        [[ "$RATE_LIMIT" =~ ^[0-9]+$ ]] || die "--rate-limit must be numeric"
    fi
    [[ "$HTTP_TIMEOUT" =~ ^[0-9]+$ ]] || die "--timeout must be numeric"
    (( HTTP_TIMEOUT >= 3 && HTTP_TIMEOUT <= 300 )) || die "--timeout must be 3-300 seconds"

    local _sev _tok _ok=1
    IFS=',' read -r -a _sev <<< "$NUCLEI_SEVERITY"
    for _tok in "${_sev[@]}"; do
        case "$_tok" in
            info|low|medium|high|critical|unknown) ;;
            *) _ok=0 ;;
        esac
    done
    (( _ok )) || die "Invalid --nuclei-severity value: '$NUCLEI_SEVERITY'"

    if $BURP_ACTIVE_SCAN || $BURP_PASSIVE; then
        [[ "$BURP_PROXY_HOST" =~ ^[a-zA-Z0-9.-]+$ ]] || die "Invalid Burp proxy host: '$BURP_PROXY_HOST'"
        [[ "$BURP_PROXY_PORT" =~ ^[0-9]+$ ]] || die "Invalid Burp proxy port: '$BURP_PROXY_PORT'"
    fi
    if $BURP_ACTIVE_SCAN; then
        [[ "$BURP_API_URL" =~ ^https?://[a-zA-Z0-9.:/-]+$ ]] || die "Invalid --burp-api-url: '$BURP_API_URL'"
    fi

    if [[ -n "$SESSION_HEADERS_FILE" ]]; then
        [[ -f "$SESSION_HEADERS_FILE" ]] || die "--session-header-file not found: $SESSION_HEADERS_FILE"
        local perms
        perms=$(stat -c '%a' "$SESSION_HEADERS_FILE" 2>/dev/null || stat -f '%Lp' "$SESSION_HEADERS_FILE" 2>/dev/null || echo "?")
        [[ "$perms" == "600" || "$perms" == "400" ]] || log_warn "Session header file permissions are $perms — recommend chmod 600"
    fi

    # --exclude-sub regexes must compile before we trust them in a pipeline
    local _rx _rc
    for _rx in ${EXCLUDE_REGEXES[@]+"${EXCLUDE_REGEXES[@]}"}; do
        echo "" | grep -Eq "$_rx" 2>/dev/null
        _rc=$?
        [[ $_rc -ne 2 ]] || die "Invalid --exclude-sub regex: $_rx"
    done
}

# ─────────────────────────────── Workspace & Lifecycle ───────────────────────────────
setup_workspace() {
    section "Setup Workspace"
    OUTDIR="${OUTDIR:-./recon_${DOMAIN}_$(date +%Y%m%d_%H%M%S)}"

    if [[ -e "$OUTDIR" ]] && ! $RESUME; then
        if [[ -n "$(ls -A "$OUTDIR" 2>/dev/null)" ]]; then
            log_warn "Output directory '$OUTDIR' already exists and is not empty."
            log_warn "Results from a previous run may be mixed in — use --resume to continue an interrupted run."
        fi
    fi

    umask 077   # recon output (incl. findings & session headers) stays private
    mkdir -p "$OUTDIR"/{subdomains,httpx,ports,urls,screenshots,vulns,report} \
        || die "Cannot create output directory: $OUTDIR"
    echo "$DOMAIN" > "$OUTDIR/scope.txt"

    LOGFILE="$OUTDIR/pipeline.log"
    AUDITLOG="$OUTDIR/audit.log"

    exec > >(tee -a "$LOGFILE") 2>&1
    TEE_PID=$!

    trap on_exit EXIT
    trap on_interrupt INT TERM

    # single-instance lock on the output directory
    LOCKDIR="$OUTDIR/.lock"
    if [[ -e "$LOCKDIR" ]]; then
        local old_pid
        old_pid=$(cat "$LOCKDIR/pid" 2>/dev/null || true)
        if [[ -n "$old_pid" ]] && kill -0 "$old_pid" 2>/dev/null; then
            die "Another metsuke instance (PID $old_pid) is running on this output directory."
        fi
        log_warn "Removing stale lock (PID ${old_pid:-unknown} is no longer running)."
        rm -rf "$LOCKDIR"
    fi
    mkdir "$LOCKDIR" && echo $$ > "$LOCKDIR/pid"

    # store CLI-provided session headers in a private file (mode 600)
    if [[ ${#SESSION_HEADERS[@]} -gt 0 ]]; then
        SESSION_HEADERS_INTERNAL="$OUTDIR/.session_headers.txt"
        printf '%s\n' ${SESSION_HEADERS[@]+"${SESSION_HEADERS[@]}"} > "$SESSION_HEADERS_INTERNAL"
        chmod 600 "$SESSION_HEADERS_INTERNAL"
        log_ok "Session headers written to $SESSION_HEADERS_INTERNAL (mode 600)"
        log_warn "Headers passed via --session-header were briefly visible in 'ps' — prefer --session-header-file for long-lived secrets."
    fi

    build_header_args

    log_ok "Workspace ready: $OUTDIR"
    log_ok "Full log   : $LOGFILE"
    log_ok "Audit trail: $AUDITLOG"
    audit "event=workspace-created output=$OUTDIR"
}

on_exit() {
    local ec=$?
    if [[ -n "${AUDITLOG:-}" ]]; then
        audit "event=exit code=$ec duration=$(( $(date +%s) - START_TIME ))s output=${OUTDIR:-?}"
    fi
    [[ -n "${LOCKDIR:-}" && -d "${LOCKDIR:-}" ]] && rm -rf "${LOCKDIR}"
    # close the pipe to tee so it flushes and exits, then reap it
    exec 1>&- 2>&- 2>/dev/null
    [[ -n "${TEE_PID:-}" ]] && wait "${TEE_PID}" 2>/dev/null
    exit "$ec"
}

on_interrupt() {
    log_warn "Interrupt received — stopping child processes and cleaning up..."
    local pids
    pids=$(jobs -p 2>/dev/null)
    # shellcheck disable=SC2086
    [[ -n "$pids" ]] && kill $pids 2>/dev/null
    audit "event=interrupted"
    exit 130
}

# ─────────────────────────────── Phase 1: Subdomain Enumeration ───────────────────────────────
phase_subdomain_enum() {
    section "Phase 1: Subdomain Enumeration"
    local out="$OUTDIR/subdomains"
    should_skip_phase "$out/all_subdomains.txt" && return

    if $DRY_RUN; then
        log "[DRY-RUN] subfinder -d $DOMAIN -all -silent -o $out/subfinder.txt"
        log "[DRY-RUN] assetfinder --subs-only $DOMAIN"
        log "[DRY-RUN] curl 'https://crt.sh/?q=%25.$DOMAIN&output=json'"
        log "[DRY-RUN] filter: lowercase + anchored scope match (^|\\.)${DOMAIN}\$ + --exclude-sub"
        return
    fi

    log "Running subfinder..."
    run_with_timeout 1800 subfinder -d "$DOMAIN" -all -silent -o "$out/subfinder.txt" 2>/dev/null

    if command -v assetfinder &>/dev/null; then
        log "Running assetfinder..."
        run_with_timeout 300 assetfinder --subs-only "$DOMAIN" > "$out/assetfinder.txt" 2>/dev/null
    fi

    log "Querying crt.sh (Certificate Transparency logs, with retry)..."
    fetch_crtsh() {
        curl -s --max-time 30 "https://crt.sh/?q=%25.${DOMAIN}&output=json" -o "$out/.crtsh_raw.json"
    }
    if retry 3 5 fetch_crtsh; then
        jq -r '.[].name_value' "$out/.crtsh_raw.json" 2>/dev/null \
            | tr '[:upper:]' '[:lower:]' | sed 's/\*\.//g' | sort -u > "$out/crtsh.txt"
    else
        log_warn "crt.sh query failed after several attempts, skipping this source"
    fi
    rm -f "$out/.crtsh_raw.json"

    log "Merging, normalizing case, and enforcing scope..."
    # FIX v3: grep -F ".$DOMAIN" was a SUBSTRING match — hosts like
    # evil.example.net.attacker.io passed the filter. Anchored regex below.
    cat "$out"/*.txt 2>/dev/null | tr '[:upper:]' '[:lower:]' \
        | sed 's/^\*\.//; s/[[:space:]]//g; s/\.$//' \
        | grep -E "(^|\.)${DOMAIN_ESCAPED}$" \
        | sort -u > "$out/all_subdomains.txt"

    if [[ ${#EXCLUDE_REGEXES[@]} -gt 0 ]]; then
        local rx before excluded=0
        for rx in "${EXCLUDE_REGEXES[@]}"; do
            before=$(count_lines "$out/all_subdomains.txt")
            grep -Ev "$rx" "$out/all_subdomains.txt" > "$out/.tmp_filtered" || true
            mv "$out/.tmp_filtered" "$out/all_subdomains.txt"
            excluded=$(( excluded + before - $(count_lines "$out/all_subdomains.txt") ))
        done
        log "Excluded $excluded subdomain(s) matching --exclude-sub patterns (out of scope)"
    fi

    local count
    count=$(count_lines "$out/all_subdomains.txt")
    log_ok "Found $count unique in-scope subdomains → $out/all_subdomains.txt"
    notify "Subdomain enum completed: $count subdomains found for $DOMAIN"
}

# ─────────────────────────────── Phase 2: Live Host Probing (+ Burp passive mirror) ───────────────────────────────
phase_httpx_probe() {
    section "Phase 2: Live Host Probing (httpx)"
    if $PASSIVE_ONLY; then
        log "passive-only mode: skipping live host probing (sends requests to targets)"
        return
    fi
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
        log "[DRY-RUN] httpx -l $in -threads $THREADS -timeout $HTTP_TIMEOUT -status-code -title -tech-detect -cdn $proxy_flag -json -o $out/httpx_full.json"
        [[ ${#HEADER_ARGS[@]} -gt 0 ]] && log "[DRY-RUN] (+ ${#HEADER_ARGS[@]} session headers)"
        return
    fi

    log "Probing $(count_lines "$in") hosts with httpx..."
    local -a extra=()
    [[ "$RATE_LIMIT" -gt 0 ]] && extra+=(-rl "$RATE_LIMIT")
    # shellcheck disable=SC2086
    httpx -l "$in" \
        -silent -threads "$THREADS" -timeout "$HTTP_TIMEOUT" -retries 2 \
        -status-code -title -tech-detect -content-length \
        -follow-redirects -ip -cdn \
        ${extra[@]+"${extra[@]}"} \
        $proxy_flag \
        -json -o "$out/httpx_full.json" 2>/dev/null

    jq -r '.url' "$out/httpx_full.json" 2>/dev/null | sort -u > "$out/live_hosts.txt"
    jq -r 'select(.cdn == true) | .url' "$out/httpx_full.json" 2>/dev/null | sort -u > "$out/cdn_hosts.txt"

    local count cdn_count
    count=$(count_lines "$out/live_hosts.txt")
    cdn_count=$(count_lines "$out/cdn_hosts.txt")
    log_ok "$count live hosts detected → $out/live_hosts.txt"
    [[ "$cdn_count" -gt 0 ]] && log "Found $cdn_count hosts behind CDN/WAF"
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
    if $PASSIVE_ONLY; then
        log "passive-only mode: skipping port scan"
        return
    fi
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
        total=$(count_lines "$OUTDIR/subdomains/all_subdomains.txt")
        noncdn=$(count_lines "$in")
        skipped=$((total - noncdn))
        [[ $skipped -gt 0 ]] && log "Skipping $skipped hosts behind CDN/WAF for port scan (--skip-cdn)"
    fi

    local port_flag="-top-ports 1000" port_range="top-1000"
    if $FULL_SCAN; then
        port_flag="-p -"
        port_range="1-65535 (full)"
    fi

    local -a scan_flags=()
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        scan_flags+=(-scan-type c)
        log "Not running as root — naabu will use TCP connect scan (SYN scan requires root)."
    fi
    if [[ "$RATE_LIMIT" -gt 0 ]]; then
        scan_flags+=(-rate "$RATE_LIMIT")
    else
        scan_flags+=(-rate 1000)
    fi

    if $DRY_RUN; then
        log "[DRY-RUN] naabu -l $in $port_flag ${scan_flags[*]} -silent -o $out/open_ports.txt"
        return
    fi

    log "Running naabu (range: $port_range)..."
    # shellcheck disable=SC2086
    naabu -l "$in" $port_flag ${scan_flags[@]+"${scan_flags[@]}"} -silent \
        -o "$out/open_ports.txt" 2>/dev/null

    local count
    count=$(count_lines "$out/open_ports.txt")
    log_ok "$count open host:port combinations → $out/open_ports.txt"
}

# ─────────────────────────────── Phase 4: URL / Endpoint Discovery ───────────────────────────────
# Multi-tier URL normalization + dedup: templating path segments (uuid/hex-id/numeric-id
# turned into placeholders) + sorting parameter keys into a "signature", so URLs
# that share the same scope (differing only in value) aren't counted repeatedly.
normalize_and_dedupe_urls() {
    local infile="$1" outfile="$2"
    "$AWK_BIN" -F'?' '
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

# Tracking-parameter patterns discarded during active crawling, so URLs with
# utm_source/fbclid/etc. don't flood the dedup results.
TRACKING_PARAM_REGEX='(\?|&)(utm_(source|medium|campaign|term|content)|fbclid|gclid|yclid|msclkid|ga(_cid|id)?|mc_(cid|eid)|ref(_src|_url|id)?|src|source(Name)?|from|via|tracking|track(id)?|click|pixel|_gl|twclid)='
STATIC_ASSET_REGEX='\.(jpg|jpeg|png|gif|svg|ico|css|woff2?|ttf|eot|mp4|mp3)(\?|$)'

# Sensitive endpoint patterns for --extended-workflows (admin/auth/cloud-config/secrets).
SENSITIVE_ENDPOINT_REGEX='(\.(env|git)(\?|$)|/(config|auth|oauth|sso|admin|graphql|swagger|openapi|internal|private|debug|staging|firebase|aws|gcp|azure|payment|billing|webhook|settings)[^/]*(\?|$)|\.(yml|yaml)(\?|$)|/(api(/v[0-9]+)?|rest|restapi|graphql|graphiql|swagger(-ui)?|openapi|api[-_]?docs|redoc|oauth2?|oidc|saml|authorize|authorization|authentication|login|logout|signin|signup|register|token|tokens|access[-_]?token|refresh[-_]?token|session|sessions|jwt|jwks?|webhook(s)?|callback(s)?|internal|private|admin(istrator)?|management|credential(s)?)(/|\?|$)'

phase_url_discovery() {
    section "Phase 4: URL & Endpoint Discovery"
    local out="$OUTDIR/urls"
    should_skip_phase "$out/all_urls.txt" && return

    : > "$out/.sources_raw.txt"

    # --- Passive source: gau (historical URLs / Wayback) ---
    if command -v gau &>/dev/null; then
        if $DRY_RUN; then
            log "[DRY-RUN] printf '%s\\n' $DOMAIN | gau --threads $THREADS --subs"
        else
            log "Collecting historical URLs from gau (passive source)..."
            printf '%s\n' "$DOMAIN" \
                | run_with_timeout 900 gau --threads "$THREADS" --subs 2>/dev/null \
                >> "$out/.sources_raw.txt"
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
            run_with_timeout 600 urlfinder -d "$DOMAIN" -silent 2>/dev/null >> "$out/.sources_raw.txt"
        fi
    fi

    # --- Active source: katana (JS-aware crawl, --katana) ---
    if $USE_KATANA; then
        if $PASSIVE_ONLY; then
            log "passive-only mode: --katana skipped (it is an active crawl)"
        elif ! command -v katana &>/dev/null; then
            log_warn "--katana requested but katana is missing, skipping."
        elif [[ ! -s "$OUTDIR/httpx/live_hosts.txt" ]]; then
            log_warn "No live hosts for katana crawl, skipping."
        elif $DRY_RUN; then
            log "[DRY-RUN] katana -list live_hosts.txt ${HEADER_ARGS[*]:+with headers} -js-crawl -silent"
        else
            log "Running katana (active JS-aware crawling)..."
            local -a sanitizer=(perl -pe 's/[^[:print:]\t\r\n]//g')
            command -v perl &>/dev/null || sanitizer=(tr -cd '\11\12\15\40-\176')
            run_with_timeout 1800 katana -list "$OUTDIR/httpx/live_hosts.txt" \
                ${HEADER_ARGS[@]+"${HEADER_ARGS[@]}"} \
                -js-crawl -silent 2>/dev/null \
                | "${sanitizer[@]}" \
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

    grep -E '\.(js)(\?|$)' "$out/all_urls.txt" > "$out/js_files.txt" 2>/dev/null || true
    grep -E '\?.=' "$out/all_urls.txt" > "$out/urls_with_params.txt" 2>/dev/null || true
    grep -Ei '(admin|api|backup|config|\.env|swagger|graphql|internal|debug)' \
        "$out/all_urls.txt" > "$out/interesting_urls.txt" 2>/dev/null || true

    log_ok "$(count_lines "$out/all_urls_raw.txt") raw URLs → $(count_lines "$out/all_urls.txt") after dedup"
    log_ok "$(count_lines "$out/interesting_urls.txt") 'interesting' URLs (admin/api/config/etc.)"

    # --- Extended workflows: sensitive endpoints, verified live via passive GETs ---
    if $EXTENDED_WORKFLOWS; then
        if $PASSIVE_ONLY; then
            log "passive-only mode: skipping sensitive endpoint probing (requires live requests)"
        elif $DRY_RUN; then
            log "[DRY-RUN] grep sensitive patterns | httpx -status-code | jq status-filter → $out/extended_sensitive_endpoints.txt"
        else
            log_ext "Searching for sensitive endpoints (auth/admin/cloud-config/secrets)..."
            grep -Ei "$SENSITIVE_ENDPOINT_REGEX" "$out/all_urls.txt" 2>/dev/null \
                | sort -u > "$out/.extended_candidates.txt"

            if [[ -s "$out/.extended_candidates.txt" ]]; then
                httpx ${HEADER_ARGS[@]+"${HEADER_ARGS[@]}"} -l "$out/.extended_candidates.txt" \
                    -silent -status-code -title -tech-detect -timeout "$HTTP_TIMEOUT" \
                    -json -o "$out/extended_sensitive_endpoints.json" 2>/dev/null

                # existence disclosure counts too: 200/204/301/302/401/403
                jq -r 'select(.status_code==200 or .status_code==204 or .status_code==301 or .status_code==302 or .status_code==401 or .status_code==403) | .url' \
                    "$out/extended_sensitive_endpoints.json" 2>/dev/null \
                    | sort -u > "$out/extended_sensitive_endpoints.txt"

                local ext_count
                ext_count=$(count_lines "$out/extended_sensitive_endpoints.txt")
                if [[ "$ext_count" -gt 0 ]]; then
                    log_warn "$ext_count live sensitive endpoint(s) detected → $out/extended_sensitive_endpoints.txt"
                    notify "🔑 $ext_count sensitive endpoint(s) live on $DOMAIN (extended workflows)"
                else
                    log_ok "No candidate sensitive endpoints are live/interesting"
                fi
            else
                log_ok "No sensitive endpoint candidates found from crawl results"
            fi
            rm -f "$out/.extended_candidates.txt"
        fi
    fi
}

# ─────────────────────────────── Phase 5: JS Hardcoded-Secret Scan (extended) ───────────────────────────────
METSUKE_SECRET_PATTERNS='(AKIA|ASIA)[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}|xox[baprs]-[0-9A-Za-z-]{10,}|[0-9]{8,10}:AA[A-Za-z0-9_-]{33}|-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,}|sk_live_[0-9a-zA-Z]{20,}|hooks\.slack\.com/services/T[A-Za-z0-9_/]{8,}'

# Runs in an xargs-spawned child bash — keep it self-contained.
js_fetch_one() {
    local url="$1" tmp hit
    tmp=$(mktemp) || return 0
    curl -s --max-time 20 --max-filesize 5000000 "$url" -o "$tmp" 2>/dev/null || { rm -f "$tmp"; return 0; }
    grep -aoE "$METSUKE_SECRET_PATTERNS" "$tmp" 2>/dev/null | sort -u | while IFS= read -r hit; do
        printf '%s\t%s\n' "$url" "$hit" >> "$METSUKE_JS_SECRETS_OUT"
    done
    rm -f "$tmp"
}

phase_js_secret_scan() {
    if ! $EXTENDED_WORKFLOWS; then return; fi
    if $PASSIVE_ONLY; then return; fi

    section "Phase 5: JS Hardcoded-Secret Detection"
    local in="$OUTDIR/urls/js_files.txt"
    local out="$OUTDIR/vulns/js_secrets.txt"
    should_skip_phase "$out" && return

    if [[ ! -s "$in" ]]; then
        log "No JS files collected, skipping."
        return
    fi

    if $DRY_RUN; then
        log "[DRY-RUN] fetch ≤ $MAX_JS_FILES JS files (concurrency $JS_CONCURRENCY) → grep -aoE <secret patterns> → $out"
        return
    fi

    log_ext "Fetching JS files and scanning for hardcoded credential patterns (passive GETs)..."
    : > "$out"
    export METSUKE_SECRET_PATTERNS
    export METSUKE_JS_SECRETS_OUT="$out"
    export -f js_fetch_one

    # xargs -I{} performs literal whole-line replacement (no shell word-splitting on URLs)
    head -n "$MAX_JS_FILES" "$in" \
        | xargs -P "$JS_CONCURRENCY" -I{} bash -c 'js_fetch_one "$1"' _ {}

    local count
    count=$(count_lines "$out")
    if [[ "$count" -gt 0 ]]; then
        log_warn "$count hardcoded secret candidate(s) → $out (verify manually — patterns only)"
        notify "🔑 $count JS secret candidate(s) on $DOMAIN"
    else
        log_ok "No hardcoded secret candidates found in sampled JS files"
    fi
}

# ─────────────────────────────── Phase 6: Subdomain Takeover Check ───────────────────────────────
phase_takeover_check() {
    section "Phase 6: Subdomain Takeover Check"
    if $PASSIVE_ONLY; then
        log "passive-only mode: skipping takeover check"
        return
    fi
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
    local -a flags=()
    $NO_INTERACTSH && flags+=(-ni)
    [[ "$RATE_LIMIT" -gt 0 ]] && flags+=(-rl "$RATE_LIMIT")
    # shellcheck disable=SC2086
    nuclei -l "$in" -t http/takeovers/ -silent -jsonl ${flags[@]+"${flags[@]}"} \
        -o "$out" 2>/dev/null

    local count
    count=$(count_lines "$out")
    if [[ "$count" -gt 0 ]]; then
        log_warn "$count possible subdomain takeover(s) detected!"
        notify "🚨 $count possible subdomain takeover(s) on $DOMAIN"
    else
        log_ok "No indication of subdomain takeover"
    fi
}

# ─────────────────────────────── Phase 7: Screenshots ───────────────────────────────
phase_screenshots() {
    section "Phase 7: Screenshotting (optional)"
    if $PASSIVE_ONLY; then
        log "passive-only mode: skipping screenshots"
        return
    fi
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

# ─────────────────────────────── Phase 8: Vulnerability Scanning ───────────────────────────────
phase_nuclei_scan() {
    section "Phase 8: Vulnerability Scanning (nuclei)"
    if $PASSIVE_ONLY; then
        log "passive-only mode: skipping nuclei (sends requests to targets)"
        return
    fi
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
        log "[DRY-RUN] nuclei -l $in -severity $severity ${NUCLEI_TAGS:+-tags $NUCLEI_TAGS} -jsonl -o $out/nuclei_results.jsonl"
        return
    fi

    if $UPDATE_TEMPLATES; then
        log "Updating nuclei templates..."
        nuclei -update-templates 2>/dev/null || log_warn "Template update failed (check connectivity)"
    else
        log_warn "Templates not updated this run — use --update-templates or run 'nuclei -update-templates' periodically."
    fi

    local -a flags=()
    $NO_INTERACTSH && flags+=(-ni)
    [[ "$RATE_LIMIT" -gt 0 ]] && flags+=(-rl "$RATE_LIMIT")
    [[ -n "$NUCLEI_TAGS" ]] && flags+=(-tags "$NUCLEI_TAGS")

    log "Running nuclei (severity: $severity)..."
    # shellcheck disable=SC2086
    nuclei -l "$in" -severity "$severity" -silent ${flags[@]+"${flags[@]}"} \
        -jsonl -o "$out/nuclei_results.jsonl" 2>/dev/null

    local count
    count=$(count_lines "$out/nuclei_results.jsonl")
    if [[ "$count" -gt 0 ]]; then
        log_warn "$count finding(s) detected! Check $out/nuclei_results.jsonl"
        notify "⚠️ nuclei found $count potential vulnerabilities on $DOMAIN"
    else
        log_ok "No significant findings from nuclei"
    fi
}

# ─────────────────────────────── Phase 9: Burp Suite Active Scan (optional, INTRUSIVE) ───────────────────────────────
phase_burp_active_scan() {
    if ! $BURP_ACTIVE_SCAN; then return; fi
    if $PASSIVE_ONLY; then
        log "passive-only mode: Burp active scan skipped"
        return
    fi

    section "Phase 9: Burp Suite Active Scan Trigger (REST API)"

    if [[ -z "$BURP_API_KEY" ]]; then
        log_warn "BURP_API_KEY is not set, skipping active scan trigger."
        return
    fi
    local live="$OUTDIR/httpx/live_hosts.txt"
    if [[ ! -s "$live" ]]; then
        log_warn "No live hosts to send to Burp, skipping."
        return
    fi

    if $DRY_RUN; then
        log "[DRY-RUN] POST ${BURP_API_URL}/<REDACTED_KEY>/v0.1/scan with $(count_lines "$live") URLs"
        return
    fi

    log_burp "Sending $(count_lines "$live") URLs to the Burp Suite REST API for active scan..."
    log_warn "REST API endpoint format may vary between Burp versions — check ${BURP_API_URL%/}/swagger.json if this fails."

    local endpoint="${BURP_API_URL%/}/${BURP_API_KEY}/v0.1/scan"
    local out="$OUTDIR/report/burp_scan_response.json"
    local urls_json payload
    urls_json=$(jq -R -s -c 'split("\n") | map(select(length > 0))' "$live")
    payload=$(jq -n --argjson urls "$urls_json" '{urls: $urls}')

    send_to_burp() {
        local code
        code=$(curl -s --max-time 30 -o "$out" -w '%{http_code}' \
            -X POST -H 'Content-Type: application/json' \
            -d "$payload" "$endpoint") || return 1
        [[ "$code" =~ ^2 ]]
    }

    if retry 2 5 send_to_burp; then
        log_ok "Active scan successfully triggered. Response saved to $out"
        notify "🎯 Burp active scan triggered for $DOMAIN"
    else
        log_err "Failed to trigger active scan after several attempts (check API URL/key)."
    fi
}

# ─────────────────────────────── Report Summary ───────────────────────────────
generate_summary() {
    section "Summary"
    local elapsed=$(( $(date +%s) - START_TIME ))
    local subs lives cdns urls raws js secrets sens take nuc
    subs=$(count_lines "$OUTDIR/subdomains/all_subdomains.txt")
    lives=$(count_lines "$OUTDIR/httpx/live_hosts.txt")
    cdns=$(count_lines "$OUTDIR/httpx/cdn_hosts.txt")
    raws=$(count_lines "$OUTDIR/urls/all_urls_raw.txt")
    urls=$(count_lines "$OUTDIR/urls/all_urls.txt")
    js=$(count_lines "$OUTDIR/urls/js_files.txt")
    secrets=$(count_lines "$OUTDIR/vulns/js_secrets.txt")
    sens=$(count_lines "$OUTDIR/urls/extended_sensitive_endpoints.txt")
    take=$(count_lines "$OUTDIR/vulns/takeover_results.jsonl")
    nuc=$(count_lines "$OUTDIR/vulns/nuclei_results.jsonl")

    cat > "$OUTDIR/report/summary.txt" <<EOF

 ${BOLD}目付 (metsuke) — Recon Summary — $DOMAIN${NC}
Started           : $START_ISO
Duration          : ${elapsed}s
Output            : $OUTDIR
Subdomains        : $subs
Live hosts        : $lives (CDN/WAF: $cdns)
Raw URLs          : $raws
Unique URLs       : $urls
JS files          : $js
JS secret candidates     : $secrets
Sensitive endpoints      : $sens
Takeover findings : $take
Nuclei findings   : $nuc
EOF
    cat "$OUTDIR/report/summary.txt"

    jq -n \
        --arg domain "$DOMAIN" --arg version "$SCRIPT_VERSION" \
        --arg started "$START_ISO" --arg output "$OUTDIR" \
        --argjson duration "$elapsed" \
        --argjson subdomains "$subs" --argjson live_hosts "$lives" \
        --argjson cdn_hosts "$cdns" --argjson unique_urls "$urls" \
        --argjson js_secret_candidates "$secrets" \
        --argjson sensitive_endpoints "$sens" \
        --argjson takeover_findings "$take" --argjson nuclei_findings "$nuc" \
        '{domain: $domain, version: $version, started_at: $started,
          duration_seconds: $duration, output_dir: $output,
          counts: {subdomains: $subdomains, live_hosts: $live_hosts, cdn_hosts: $cdn_hosts,
                   unique_urls: $unique_urls, js_secret_candidates: $js_secret_candidates,
                   sensitive_endpoints: $sensitive_endpoints, takeover_findings: $takeover_findings,
                   nuclei_findings: $nuclei_findings}}' \
        > "$OUTDIR/report/summary.json"

    log_ok "Done. All results saved to: $OUTDIR (summary.txt / summary.json)"
    notify "metsuke finished: $DOMAIN in ${elapsed}s — subdomains=$subs live=$lives nuclei=$nuc takeover=$take"
}

# ─────────────────────────────── Argument Parsing ───────────────────────────────
# Pre-scan for --config FIRST so the config file provides defaults and CLI flags win
# (v3 sourced it after parsing — config silently overrode the command line).
_pre_args=("$@")
for (( _i=0; _i<${#_pre_args[@]}; _i++ )); do
    if [[ "${_pre_args[$_i]}" == "--config" ]]; then
        _cfg="${_pre_args[$((_i+1))]:-}"
        [[ -n "$_cfg" ]] || { echo "[!] --config requires a file path" >&2; exit 1; }
        [[ -f "$_cfg" ]] || { echo "[!] Config file not found: $_cfg" >&2; exit 1; }
        # shellcheck disable=SC1090
        source "$_cfg"
        CONFIG_FILE="$_cfg"
        break
    fi
done
unset _pre_args _cfg _i 2>/dev/null || true

while [[ $# -gt 0 ]]; do
    case "$1" in
        -d) take_arg "$@"; DOMAIN="$ARG_VALUE"; shift 2 ;;
        -o) take_arg "$@"; OUTDIR="$ARG_VALUE"; shift 2 ;;
        -t) take_arg "$@"; THREADS="$ARG_VALUE"; shift 2 ;;
        --timeout) take_arg "$@"; HTTP_TIMEOUT="$ARG_VALUE"; shift 2 ;;
        --rate-limit) take_arg "$@"; RATE_LIMIT="$ARG_VALUE"; shift 2 ;;
        --nuclei-severity) take_arg "$@"; NUCLEI_SEVERITY="$ARG_VALUE"; shift 2 ;;
        --nuclei-tags) take_arg "$@"; NUCLEI_TAGS="$ARG_VALUE"; shift 2 ;;
        --full) FULL_SCAN=true; shift ;;
        --config) take_arg "$@"; CONFIG_FILE="$ARG_VALUE"; shift 2 ;;   # already sourced above
        --sequential) PARALLEL_MODE=false; shift ;;
        --parallel) PARALLEL_MODE=true; shift ;;
        --resume) RESUME=true; shift ;;
        --skip-cdn) SKIP_CDN=true; shift ;;
        --dry-run) DRY_RUN=true; shift ;;
        --katana) USE_KATANA=true; shift ;;
        --web-archives) USE_WEB_ARCHIVES=true; shift ;;
        --extended-workflows) EXTENDED_WORKFLOWS=true; shift ;;
        --session-header) take_arg "$@"; SESSION_HEADERS+=("$ARG_VALUE"); shift 2 ;;
        --session-header-file) take_arg "$@"; SESSION_HEADERS_FILE="$ARG_VALUE"; shift 2 ;;
        --exclude-sub) take_arg "$@"; EXCLUDE_REGEXES+=("$ARG_VALUE"); shift 2 ;;
        --passive-only) PASSIVE_ONLY=true; shift ;;
        --no-interactsh) NO_INTERACTSH=true; shift ;;
        --no-notify) NO_NOTIFY=true; shift ;;
        --update-templates) UPDATE_TEMPLATES=true; shift ;;
        --burp) BURP_PASSIVE=true; shift ;;
        --burp-proxy) take_arg "$@"; BURP_PROXY_HOST="${ARG_VALUE%%:*}"; BURP_PROXY_PORT="${ARG_VALUE##*:}"; shift 2 ;;
        --burp-active-scan) BURP_ACTIVE_SCAN=true; shift ;;
        --burp-api-url) take_arg "$@"; BURP_API_URL="$ARG_VALUE"; shift 2 ;;
        --burp-api-key) take_arg "$@"; BURP_API_KEY="$ARG_VALUE"; CLI_API_KEY=true; shift 2 ;;
        -V|--version) echo "metsuke v${SCRIPT_VERSION}"; exit 0 ;;
        -h|--help) usage ;;
        *) log_err "Unrecognized argument: $1"; usage ;;
    esac
done

[[ -z "$DOMAIN" ]] && { log_err "Domain is required (-d)"; usage; }
validate_inputs

if (( BASH_VERSINFO[0] < 4 )); then
    log_warn "bash 4+ recommended (detected ${BASH_VERSION}); script will still try its best."
fi

# ─────────────────────────────── Main ───────────────────────────────
main() {
    print_banner
    setup_workspace
    confirm_authorization
    check_dependencies

    local args_str="(none)"
    [[ ${#RAW_ARGS[@]} -gt 0 ]] && args_str=$(redact_args "${RAW_ARGS[@]}")
    audit "event=pipeline-start user=$(id -un) target=$DOMAIN version=$SCRIPT_VERSION config=${CONFIG_FILE:-none} args=$args_str"

    phase_subdomain_enum
    phase_httpx_probe

    if $PARALLEL_MODE; then
        log "Parallel mode: port scan & URL discovery run concurrently (combined request rate is higher)."
        phase_port_scan & local port_pid=$!
        phase_url_discovery & local url_pid=$!
        wait "$port_pid" 2>/dev/null || log_warn "Port scan phase exited with errors"
        wait "$url_pid" 2>/dev/null || log_warn "URL discovery phase exited with errors"
    else
        phase_port_scan
        phase_url_discovery
    fi

    phase_js_secret_scan
    phase_takeover_check
    phase_screenshots
    phase_nuclei_scan
    phase_burp_active_scan

    generate_summary
    audit "event=pipeline-end duration=$(( $(date +%s) - START_TIME ))s target=$DOMAIN"
}

main
