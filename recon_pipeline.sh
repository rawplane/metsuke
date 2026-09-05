#!/usr/bin/env bash
#
# recon_pipeline.sh — Modular reconnaissance pipeline for authorized security assessments
# v2.0.0 — + Burp Suite integration (optional), parallel execution, resume, CDN-aware scanning
#
# PERINGATAN LEGAL:
#   Script ini HANYA boleh dijalankan terhadap target yang sudah diberi izin
#   eksplisit (bug bounty scope, kontrak pentest, atau aset milik sendiri).
#   Scanning tanpa izin adalah tindakan ilegal di sebagian besar yurisdiksi.
#   Opsi --burp-active-scan bersifat INTRUSIF (menyerang endpoint) — pastikan
#   scope otorisasi Anda eksplisit mengizinkan active scanning, bukan cuma recon pasif.
#
# Requirements wajib   : subfinder, httpx, naabu, nuclei, curl, jq
# Requirements opsional: assetfinder, gau, gowitness
# Burp Suite (opsional): Burp Pro/Community berjalan lokal untuk passive proxy mirroring,
#                        Burp Pro + REST API enabled untuk active scan trigger
#
set -uo pipefail
IFS=$'\n\t'

# ─────────────────────────────── Config & Globals ───────────────────────────────
SCRIPT_VERSION="2.0.0"
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

# Burp Suite integration (semua opsional, default mati)
BURP_PASSIVE=false                       # --burp : mirror traffic httpx ke Burp proxy
BURP_ACTIVE_SCAN=false                   # --burp-active-scan : trigger active scan via REST API
BURP_PROXY_HOST="127.0.0.1"
BURP_PROXY_PORT="8080"
BURP_API_URL="http://127.0.0.1:1337"
BURP_API_KEY="${BURP_API_KEY:-}"

CONFIG_FILE=""
START_TIME=$(date +%s)
LOGFILE=""

# Warna terminal (ANSI-C quoting $'...' agar ESC byte asli, jadi tampil benar
# baik lewat `echo -e` maupun heredoc `cat` di usage()/report)
RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'
BLUE=$'\033[0;34m'; CYAN=$'\033[0;36m'; MAGENTA=$'\033[0;35m'; BOLD=$'\033[1m'; NC=$'\033[0m'

# ─────────────────────────────── Helper Functions ───────────────────────────────
log()      { echo -e "${CYAN}[$(date +'%H:%M:%S')]${NC} $*"; }
log_ok()   { echo -e "${GREEN}[$(date +'%H:%M:%S')] [OK]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[$(date +'%H:%M:%S')] [WARN]${NC} $*"; }
log_err()  { echo -e "${RED}[$(date +'%H:%M:%S')] [ERROR]${NC} $*" >&2; }
log_burp() { echo -e "${MAGENTA}[$(date +'%H:%M:%S')] [BURP]${NC} $*"; }
section()  { echo -e "\n${BOLD}${BLUE}══════════ $* ══════════${NC}"; }

usage() {
    cat <<EOF
${BOLD}recon_pipeline.sh v${SCRIPT_VERSION}${NC}

Penggunaan:
  $0 -d <domain> [opsi]

Opsi dasar:
  -d <domain>       Target domain (wajib), contoh: example.com
  -o <dir>          Direktori output (default: ./recon_<domain>_<timestamp>)
  -t <threads>      Jumlah concurrent threads (default: 50)
  --full            Mode agresif: full port scan (1-65535) + semua severity nuclei
  --config <file>   Load default opsi dari config file (bash source)
  -h                Tampilkan bantuan ini

Opsi performa:
  --sequential      Jalankan semua fase berurutan (default: paralel)
  --resume          Skip fase yang output-nya sudah ada dari run sebelumnya
  --skip-cdn        Skip port scanning untuk host yang terdeteksi di belakang CDN/WAF
  --dry-run         Tampilkan command yang akan dijalankan tanpa eksekusi

Integrasi Burp Suite (opsional, default MATI):
  --burp                    Mirror traffic httpx ke Burp proxy (isi Site Map otomatis)
  --burp-proxy <host:port>  Alamat Burp proxy (default: 127.0.0.1:8080)
  --burp-active-scan        Trigger ACTIVE SCAN via Burp REST API (INTRUSIF!)
  --burp-api-url <url>      Alamat Burp REST API (default: http://127.0.0.1:1337)
  --burp-api-key <key>      API key Burp REST API (atau set env BURP_API_KEY)

Contoh:
  $0 -d example.com
  $0 -d example.com -o ./hasil -t 100 --full --resume
  $0 -d example.com --burp --burp-proxy 127.0.0.1:8080
  $0 -d example.com --burp-active-scan --burp-api-key abcd1234

${YELLOW}PENTING: Hanya gunakan pada target yang sudah punya izin eksplisit.${NC}
EOF
    exit 1
}

confirm_authorization() {
    echo -e "${YELLOW}${BOLD}"
    echo "════════════════════════════════════════════════════════════"
    echo " KONFIRMASI OTORISASI"
    echo "════════════════════════════════════════════════════════════${NC}"
    echo "Target : ${BOLD}${DOMAIN}${NC}"
    echo "Pastikan Anda memiliki izin eksplisit untuk melakukan security"
    echo "testing terhadap target ini (bug bounty scope / kontrak pentest /"
    echo "aset milik sendiri)."

    if $BURP_ACTIVE_SCAN; then
        echo ""
        echo -e "${RED}${BOLD}PERHATIAN TAMBAHAN:${NC}${YELLOW} --burp-active-scan aktif."
        echo "Ini akan memicu ACTIVE SCAN (bersifat intrusif/menyerang endpoint"
        echo "secara aktif) melalui Burp Suite REST API. Pastikan scope otorisasi"
        echo "Anda eksplisit mengizinkan active scanning, bukan hanya recon pasif."
    fi
    echo ""
    read -r -p "Ketik 'YA SAYA PUNYA IZIN' untuk melanjutkan: " confirmation
    if [[ "$confirmation" != "YA SAYA PUNYA IZIN" ]]; then
        log_err "Konfirmasi tidak sesuai. Keluar."
        exit 1
    fi
    log_ok "Otorisasi dikonfirmasi. Melanjutkan pipeline..."
}

check_dependencies() {
    section "Dependency Check"
    local required=("subfinder" "httpx" "naabu" "nuclei" "curl" "jq")
    local optional=("assetfinder" "gau" "gowitness")
    local missing_required=()

    for tool in "${required[@]}"; do
        if command -v "$tool" &>/dev/null; then
            log_ok "$tool terdeteksi"
        else
            log_err "$tool TIDAK ditemukan"
            missing_required+=("$tool")
        fi
    done

    for tool in "${optional[@]}"; do
        if command -v "$tool" &>/dev/null; then
            log_ok "$tool terdeteksi (opsional)"
        else
            log_warn "$tool tidak ditemukan (opsional, fitur terkait akan di-skip)"
        fi
    done

    if [[ ${#missing_required[@]} -gt 0 ]]; then
        log_err "Tools wajib berikut belum terinstall: ${missing_required[*]}"
        cat <<EOF

Install cepat (ProjectDiscovery toolkit + gau):
  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
  go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
  go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  go install -v github.com/lc/gau/v2/cmd/gau@latest
  go install -v github.com/tomnomnom/assetfinder@latest
  sudo apt install jq curl -y

Pastikan \$GOPATH/bin ada di \$PATH.
EOF
        exit 1
    fi

    # Cek konektivitas Burp jika integrasi diaktifkan (non-fatal, hanya info awal)
    if $BURP_PASSIVE; then
        if check_tcp_port "$BURP_PROXY_HOST" "$BURP_PROXY_PORT"; then
            log_ok "Burp proxy reachable di ${BURP_PROXY_HOST}:${BURP_PROXY_PORT}"
        else
            log_warn "Burp proxy TIDAK reachable di ${BURP_PROXY_HOST}:${BURP_PROXY_PORT} (pastikan Burp berjalan & proxy listener aktif)"
        fi
    fi
    if $BURP_ACTIVE_SCAN && [[ -z "$BURP_API_KEY" ]]; then
        log_warn "--burp-active-scan aktif tapi BURP_API_KEY belum diset. Fase ini akan di-skip nanti."
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
        log_warn "Percobaan $n/$max gagal, retry dalam ${delay}s..."
        sleep "$delay"
    done
    return 0
}

should_skip_phase() {
    # should_skip_phase <marker_file>
    local marker="$1"
    if $RESUME && [[ -s "$marker" ]]; then
        log_ok "Resume aktif: '$marker' sudah ada, skip fase ini."
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

    log_ok "Workspace dibuat di: $OUTDIR"
    log_ok "Log lengkap disimpan di: $LOGFILE"
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

    log "Menjalankan subfinder..."
    subfinder -d "$DOMAIN" -all -silent -o "$out/subfinder.txt" 2>/dev/null

    if command -v assetfinder &>/dev/null; then
        log "Menjalankan assetfinder..."
        assetfinder --subs-only "$DOMAIN" > "$out/assetfinder.txt" 2>/dev/null
    fi

    log "Query crt.sh (Certificate Transparency logs, dengan retry)..."
    fetch_crtsh() {
        curl -s --max-time 15 "https://crt.sh/?q=%25.${DOMAIN}&output=json" -o "$out/.crtsh_raw.json"
    }
    if retry 3 5 fetch_crtsh; then
        jq -r '.[].name_value' "$out/.crtsh_raw.json" 2>/dev/null \
            | sed 's/\*\.//g' | sort -u > "$out/crtsh.txt"
    else
        log_warn "crt.sh query gagal setelah beberapa percobaan, skip sumber ini"
    fi

    log "Menggabungkan dan deduplikasi hasil..."
    cat "$out"/*.txt 2>/dev/null | sed 's/^\*\.//' | grep -F ".$DOMAIN" \
        | sort -u > "$out/all_subdomains.txt"

    local count
    count=$(wc -l < "$out/all_subdomains.txt" | tr -d ' ')
    log_ok "Ditemukan $count subdomain unik → $out/all_subdomains.txt"
    notify "Subdomain enum selesai: $count subdomain ditemukan untuk $DOMAIN"
}

# ─────────────────────────────── Phase 2: Live Host Probing (+ Burp passive mirror) ───────────────────────────────
phase_httpx_probe() {
    section "Phase 2: Live Host Probing (httpx)"
    local in="$OUTDIR/subdomains/all_subdomains.txt"
    local out="$OUTDIR/httpx"
    should_skip_phase "$out/httpx_full.json" && return

    if [[ ! -s "$in" ]]; then
        log_warn "Tidak ada subdomain untuk di-probe, skip phase ini."
        return
    fi

    local proxy_flag=""
    if $BURP_PASSIVE; then
        if check_tcp_port "$BURP_PROXY_HOST" "$BURP_PROXY_PORT"; then
            proxy_flag="-http-proxy http://${BURP_PROXY_HOST}:${BURP_PROXY_PORT}"
            log_burp "Traffic akan di-mirror ke Burp proxy ${BURP_PROXY_HOST}:${BURP_PROXY_PORT} → Site Map terisi otomatis"
        else
            log_warn "Burp proxy tidak reachable, lanjut tanpa mirroring ke Burp"
        fi
    fi

    if $DRY_RUN; then
        log "[DRY-RUN] httpx -l $in -status-code -title -tech-detect -cdn $proxy_flag -json -o $out/httpx_full.json"
        return
    fi

    log "Probing $(wc -l < "$in" | tr -d ' ') host dengan httpx..."
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
    log_ok "$count host live terdeteksi → $out/live_hosts.txt"
    [[ "${cdn_count:-0}" -gt 0 ]] && log "Ditemukan $cdn_count host di belakang CDN/WAF"
    notify "Live host probing selesai: $count host live"
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
        log_warn "Tidak ada target untuk port scan, skip."
        return
    fi

    if $SKIP_CDN && [[ "$in" == *"targets_noncdn.txt" ]]; then
        local total noncdn skipped
        total=$(wc -l < "$OUTDIR/subdomains/all_subdomains.txt" | tr -d ' ')
        noncdn=$(wc -l < "$in" | tr -d ' ')
        skipped=$((total - noncdn))
        [[ $skipped -gt 0 ]] && log "Skip $skipped host di belakang CDN/WAF untuk port scan (--skip-cdn)"
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

    log "Menjalankan naabu (range: $port_range)..."
    # shellcheck disable=SC2086
    naabu -l "$in" $port_flag -silent -rate 1000 \
        -o "$out/open_ports.txt" 2>/dev/null

    local count
    count=$(wc -l < "$out/open_ports.txt" 2>/dev/null | tr -d ' ')
    log_ok "$count host:port kombinasi terbuka → $out/open_ports.txt"
}

# ─────────────────────────────── Phase 4: URL / Endpoint Discovery ───────────────────────────────
phase_url_discovery() {
    section "Phase 4: URL Discovery (gau / Wayback)"
    local out="$OUTDIR/urls"
    should_skip_phase "$out/all_urls.txt" && return

    if ! command -v gau &>/dev/null; then
        log_warn "gau tidak terinstall, skip phase ini."
        return
    fi

    if $DRY_RUN; then
        log "[DRY-RUN] echo $DOMAIN | gau --threads $THREADS --subs"
        return
    fi

    log "Mengumpulkan historical URLs dari gau..."
    echo "$DOMAIN" | gau --threads "$THREADS" --subs 2>/dev/null | sort -u > "$out/all_urls.txt"

    grep -E '\.(js)(\?|$)' "$out/all_urls.txt" > "$out/js_files.txt" 2>/dev/null
    grep -E '\?.+=' "$out/all_urls.txt" > "$out/urls_with_params.txt" 2>/dev/null
    grep -Ei '(admin|api|backup|config|\.env|swagger|graphql|internal|debug)' \
        "$out/all_urls.txt" > "$out/interesting_urls.txt" 2>/dev/null

    log_ok "$(wc -l < "$out/all_urls.txt" | tr -d ' ') URL ditemukan"
    log_ok "$(wc -l < "$out/interesting_urls.txt" 2>/dev/null | tr -d ' ') URL 'menarik' (admin/api/config/dll)"
}

# ─────────────────────────────── Phase 5: Subdomain Takeover Check ───────────────────────────────
phase_takeover_check() {
    section "Phase 5: Subdomain Takeover Check"
    local in="$OUTDIR/subdomains/all_subdomains.txt"
    local out="$OUTDIR/vulns/takeover_results.jsonl"
    should_skip_phase "$out" && return

    if [[ ! -s "$in" ]]; then
        log_warn "Tidak ada subdomain, skip takeover check."
        return
    fi

    if $DRY_RUN; then
        log "[DRY-RUN] nuclei -l $in -t http/takeovers/ -silent -jsonl -o $out"
        return
    fi

    log "Menjalankan nuclei takeover templates..."
    nuclei -l "$in" -t http/takeovers/ -silent -jsonl -o "$out" 2>/dev/null

    local count
    count=$(wc -l < "$out" 2>/dev/null | tr -d ' ')
    if [[ "${count:-0}" -gt 0 ]]; then
        log_warn "$count kemungkinan subdomain takeover terdeteksi!"
        notify "🚨 $count kemungkinan subdomain takeover pada $DOMAIN"
    else
        log_ok "Tidak ada indikasi subdomain takeover"
    fi
}

# ─────────────────────────────── Phase 6: Screenshots ───────────────────────────────
phase_screenshots() {
    section "Phase 6: Screenshotting (opsional)"
    local in="$OUTDIR/httpx/live_hosts.txt"
    local out="$OUTDIR/screenshots"
    should_skip_phase "$out/.done" && return

    if ! command -v gowitness &>/dev/null; then
        log_warn "gowitness tidak terinstall, skip phase ini."
        return
    fi
    if [[ ! -s "$in" ]]; then
        log_warn "Tidak ada live host, skip screenshot."
        return
    fi

    if $DRY_RUN; then
        log "[DRY-RUN] gowitness file -f $in -P $out --no-http"
        return
    fi

    log "Mengambil screenshot dari live hosts..."
    gowitness file -f "$in" -P "$out" --no-http 2>/dev/null || log_warn "gowitness gagal pada beberapa target"
    touch "$out/.done"
    log_ok "Screenshot disimpan di $out"
}

# ─────────────────────────────── Phase 7: Vulnerability Scanning ───────────────────────────────
phase_nuclei_scan() {
    section "Phase 7: Vulnerability Scanning (nuclei)"
    local in="$OUTDIR/httpx/live_hosts.txt"
    local out="$OUTDIR/vulns"
    should_skip_phase "$out/nuclei_results.jsonl" && return

    if [[ ! -s "$in" ]]; then
        log_warn "Tidak ada live host untuk nuclei, skip."
        return
    fi

    local severity="$NUCLEI_SEVERITY"
    $FULL_SCAN && severity="info,low,medium,high,critical"

    if $DRY_RUN; then
        log "[DRY-RUN] nuclei -l $in -severity $severity -jsonl -o $out/nuclei_results.jsonl"
        return
    fi

    log "Menjalankan nuclei (severity: $severity)..."
    log_warn "Update templates terlebih dahulu jika lama tidak dijalankan: nuclei -update-templates"

    nuclei -l "$in" \
        -severity "$severity" \
        -silent -rate-limit "$THREADS" \
        -jsonl -o "$out/nuclei_results.jsonl" 2>/dev/null

    local count
    count=$(wc -l < "$out/nuclei_results.jsonl" 2>/dev/null | tr -d ' ')
    if [[ "${count:-0}" -gt 0 ]]; then
        log_warn "$count temuan terdeteksi! Cek $out/nuclei_results.jsonl"
        notify "⚠️ nuclei menemukan $count potensi kerentanan pada $DOMAIN"
    else
        log_ok "Tidak ada temuan signifikan dari nuclei"
    fi
}

# ─────────────────────────────── Phase 8: Burp Suite Active Scan (opsional, INTRUSIF) ───────────────────────────────
phase_burp_active_scan() {
    section "Phase 8: Burp Suite Active Scan Trigger (REST API)"
    local live="$OUTDIR/httpx/live_hosts.txt"
    local out="$OUTDIR/report/burp_scan_response.json"

    if ! $BURP_ACTIVE_SCAN; then
        return
    fi
    if [[ -z "$BURP_API_KEY" ]]; then
        log_warn "BURP_API_KEY tidak diset, skip active scan trigger."
        return
    fi
    if [[ ! -s "$live" ]]; then
        log_warn "Tidak ada live host untuk dikirim ke Burp, skip."
        return
    fi

    if $DRY_RUN; then
        log "[DRY-RUN] POST ${BURP_API_URL}/${BURP_API_KEY}/v0.1/scan dengan $(wc -l < "$live" | tr -d ' ') URL"
        return
    fi

    log_burp "Mengirim $(wc -l < "$live" | tr -d ' ') URL ke Burp Suite REST API untuk active scan..."
    log_warn "Catatan: format endpoint REST API bisa berbeda antar versi Burp Suite."
    log_warn "Jika request ini gagal, cek Swagger docs di ${BURP_API_URL}/swagger.json atau menu Burp > Settings > Suite > REST API."

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
        [[ "$code" == "201" || "$code" == "200" ]]
    }

    if retry 2 5 send_to_burp; then
        sed '$d' "$OUTDIR/.burp_response_tmp" > "$out"
        rm -f "$OUTDIR/.burp_response_tmp"
        log_ok "Active scan berhasil di-queue di Burp Suite. Response tersimpan di $out"
        notify "🎯 Active scan di-trigger di Burp Suite untuk $DOMAIN"
    else
        log_warn "Gagal trigger active scan Burp setelah beberapa percobaan. Cek endpoint/API key/versi Burp."
        rm -f "$OUTDIR/.burp_response_tmp"
    fi
}

# ─────────────────────────────── Parallel / Sequential Orchestration ───────────────────────────────
run_independent_phases() {
    if $PARALLEL; then
        section "Menjalankan fase independen secara PARALEL"
        local pids=()
        phase_port_scan        & pids+=($!)
        phase_url_discovery    & pids+=($!)
        phase_takeover_check   & pids+=($!)
        phase_screenshots      & pids+=($!)
        phase_nuclei_scan      & pids+=($!)
        phase_burp_active_scan & pids+=($!)

        local fail=0
        for pid in "${pids[@]}"; do
            wait "$pid" || fail=1
        done
        [[ $fail -eq 1 ]] && log_warn "Beberapa fase paralel selesai dengan warning (cek log di atas)."
    else
        section "Menjalankan fase independen secara SEQUENTIAL"
        phase_port_scan
        phase_url_discovery
        phase_takeover_check
        phase_screenshots
        phase_nuclei_scan
        phase_burp_active_scan
    fi
}

# ─────────────────────────────── Report Generation ───────────────────────────────
generate_report() {
    section "Report Generation"
    local report="$OUTDIR/report/summary.md"
    local json_report="$OUTDIR/report/results.json"
    local elapsed=$(( $(date +%s) - START_TIME ))

    local sub_count host_count cdn_count port_count url_count vuln_count takeover_count
    sub_count=$(wc -l < "$OUTDIR/subdomains/all_subdomains.txt" 2>/dev/null | tr -d ' ')
    host_count=$(wc -l < "$OUTDIR/httpx/live_hosts.txt" 2>/dev/null | tr -d ' ')
    cdn_count=$(wc -l < "$OUTDIR/httpx/cdn_hosts.txt" 2>/dev/null | tr -d ' ')
    port_count=$(wc -l < "$OUTDIR/ports/open_ports.txt" 2>/dev/null | tr -d ' ')
    url_count=$(wc -l < "$OUTDIR/urls/all_urls.txt" 2>/dev/null | tr -d ' ')
    vuln_count=$(wc -l < "$OUTDIR/vulns/nuclei_results.jsonl" 2>/dev/null | tr -d ' ')
    takeover_count=$(wc -l < "$OUTDIR/vulns/takeover_results.jsonl" 2>/dev/null | tr -d ' ')

    local burp_status="tidak aktif"
    $BURP_PASSIVE && burp_status="passive mirroring aktif"
    $BURP_ACTIVE_SCAN && burp_status="$burp_status + active scan triggered"

    cat > "$report" <<EOF
# Recon Report: ${DOMAIN}

**Tanggal**: $(date '+%Y-%m-%d %H:%M:%S')
**Durasi**: ${elapsed}s
**Mode**: $($FULL_SCAN && echo "Full/Agresif" || echo "Standard") | Eksekusi: $($PARALLEL && echo "Paralel" || echo "Sequential")
**Burp Suite**: ${burp_status}

## Ringkasan

| Metrik                        | Jumlah |
|--------------------------------|--------|
| Subdomain ditemukan            | ${sub_count:-0} |
| Host live                      | ${host_count:-0} |
| Host di belakang CDN/WAF       | ${cdn_count:-0} |
| Kombinasi host:port terbuka    | ${port_count:-0} |
| URL historis                   | ${url_count:-0} |
| Temuan nuclei                  | ${vuln_count:-0} |
| Indikasi subdomain takeover    | ${takeover_count:-0} |

## Struktur Output

\`\`\`
${OUTDIR}/
├── pipeline.log                    # log lengkap eksekusi
├── subdomains/all_subdomains.txt   # semua subdomain unik
├── httpx/httpx_full.json           # detail live host (status, title, tech, cdn)
├── httpx/live_hosts.txt            # daftar URL live
├── httpx/cdn_hosts.txt             # host yang terdeteksi di belakang CDN/WAF
├── ports/open_ports.txt            # host:port terbuka
├── urls/interesting_urls.txt       # URL admin/api/config/dll
├── vulns/nuclei_results.jsonl      # temuan kerentanan
├── vulns/takeover_results.jsonl    # indikasi subdomain takeover
├── report/results.json             # ringkasan format JSON (untuk integrasi tool lain)
└── report/summary.md               # laporan ini
\`\`\`

## Langkah Selanjutnya (rekomendasi)

1. Review \`vulns/nuclei_results.jsonl\` dan \`vulns/takeover_results.jsonl\` untuk temuan prioritas tinggi.
2. Manual review terhadap \`urls/interesting_urls.txt\`.
$($BURP_PASSIVE && echo "3. Buka Burp Suite Site Map — traffic recon sudah ter-mirror di sana untuk analisis manual lanjutan.")
$($BURP_ACTIVE_SCAN && echo "4. Cek progress active scan di Burp Suite Dashboard/Scanner tab.")
5. Verifikasi manual setiap temuan sebelum dilaporkan sebagai valid.

---
*Generated by recon_pipeline.sh v${SCRIPT_VERSION}*
EOF

    jq -n \
        --arg domain "$DOMAIN" \
        --arg date "$(date -Iseconds)" \
        --argjson elapsed "$elapsed" \
        --argjson subdomains "${sub_count:-0}" \
        --argjson live_hosts "${host_count:-0}" \
        --argjson cdn_hosts "${cdn_count:-0}" \
        --argjson open_ports "${port_count:-0}" \
        --argjson urls "${url_count:-0}" \
        --argjson vulnerabilities "${vuln_count:-0}" \
        --argjson takeovers "${takeover_count:-0}" \
        --arg burp_status "$burp_status" \
        '{domain: $domain, scan_date: $date, duration_seconds: $elapsed,
          counts: {subdomains: $subdomains, live_hosts: $live_hosts, cdn_hosts: $cdn_hosts,
                   open_ports: $open_ports, urls: $urls, vulnerabilities: $vulnerabilities,
                   takeovers: $takeovers},
          burp_integration: $burp_status}' > "$json_report"

    log_ok "Report tersimpan di: $report"
    log_ok "JSON summary tersimpan di: $json_report"
    echo -e "\n${BOLD}${GREEN}════════════════════════════════════════${NC}"
    cat "$report"
}

# ─────────────────────────────── Main ───────────────────────────────
main() {
    # Pre-scan argumen untuk --config (biar bisa di-source sebelum parsing utama)
    local args=("$@")
    for ((i = 0; i < ${#args[@]}; i++)); do
        if [[ "${args[$i]}" == "--config" ]]; then
            CONFIG_FILE="${args[$((i + 1))]:-}"
        fi
    done
    if [[ -n "$CONFIG_FILE" && -f "$CONFIG_FILE" ]]; then
        log "Memuat konfigurasi dari $CONFIG_FILE"
        # shellcheck disable=SC1090
        source "$CONFIG_FILE"
    fi

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -d) DOMAIN="$2"; shift 2 ;;
            -o) OUTDIR="$2"; shift 2 ;;
            -t) THREADS="$2"; shift 2 ;;
            --full) FULL_SCAN=true; shift ;;
            --resume) RESUME=true; shift ;;
            --skip-cdn) SKIP_CDN=true; shift ;;
            --sequential) PARALLEL=false; shift ;;
            --dry-run) DRY_RUN=true; shift ;;
            --config) shift 2 ;;
            --burp) BURP_PASSIVE=true; shift ;;
            --burp-proxy) IFS=':' read -r BURP_PROXY_HOST BURP_PROXY_PORT <<< "$2"; shift 2 ;;
            --burp-active-scan) BURP_ACTIVE_SCAN=true; shift ;;
            --burp-api-url) BURP_API_URL="$2"; shift 2 ;;
            --burp-api-key) BURP_API_KEY="$2"; shift 2 ;;
            -h|--help) usage ;;
            *) log_err "Argumen tidak dikenal: $1"; usage ;;
        esac
    done

    [[ -z "$DOMAIN" ]] && { log_err "Domain wajib diisi (-d)"; usage; }

    echo -e "${BOLD}${CYAN}"
    cat <<'BANNER'
  ____                       ____  _            _ _
 |  _ \ ___  ___ ___  _ __  |  _ \(_)_ __   ___| (_)_ __   ___
 | |_) / _ \/ __/ _ \| '_ \ | |_) | | '_ \ / _ \ | | '_ \ / _ \
 |  _ <  __/ (_| (_) | | | ||  __/| | |_) |  __/ | | | | |  __/
 |_| \_\___|\___\___/|_| |_||_|   |_| .__/ \___|_|_|_| |_|\___|
                                     |_|
BANNER
    echo -e "${NC}v${SCRIPT_VERSION} — for authorized security testing only\n"

    confirm_authorization
    check_dependencies
    setup_workspace
    notify "🚀 Recon pipeline dimulai untuk $DOMAIN"

    phase_subdomain_enum
    phase_httpx_probe
    run_independent_phases
    generate_report

    local elapsed=$(( $(date +%s) - START_TIME ))
    log_ok "Pipeline selesai dalam ${elapsed}s. Semua hasil ada di: $OUTDIR"
    notify "✅ Recon pipeline selesai untuk $DOMAIN (${elapsed}s)"
}

main "$@"
