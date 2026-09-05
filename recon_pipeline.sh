#!/usr/bin/env bash
#
# recon_pipeline.sh — Modular reconnaissance pipeline for authorized security assessments
#
# PERINGATAN LEGAL:
#   Script ini HANYA boleh dijalankan terhadap target yang sudah diberi izin
#   eksplisit (bug bounty scope, kontrak pentest, atau aset milik sendiri).
#   Scanning tanpa izin adalah tindakan ilegal di sebagian besar yurisdiksi.
#
# Author style: security engineer workflow, 10y experience
# Requirements: subfinder, httpx, naabu, nuclei, gau (opsional: assetfinder, gowitness, jq)
#
# Usage:
#   ./recon_pipeline.sh -d target.com [-o output_dir] [-t threads] [--full]
#
set -uo pipefail
IFS=$'\n\t'

# ─────────────────────────────── Config & Globals ───────────────────────────────
SCRIPT_VERSION="1.0.0"
DOMAIN=""
OUTDIR=""
THREADS=50
FULL_SCAN=false
NUCLEI_SEVERITY="low,medium,high,critical"
WEBHOOK_URL="${RECON_WEBHOOK_URL:-}"   # opsional: export RECON_WEBHOOK_URL=<slack/discord webhook>
START_TIME=$(date +%s)

# Warna terminal
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

# ─────────────────────────────── Helper Functions ───────────────────────────────
log()      { echo -e "${CYAN}[$(date +'%H:%M:%S')]${NC} $*"; }
log_ok()   { echo -e "${GREEN}[$(date +'%H:%M:%S')] [OK]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[$(date +'%H:%M:%S')] [WARN]${NC} $*"; }
log_err()  { echo -e "${RED}[$(date +'%H:%M:%S')] [ERROR]${NC} $*" >&2; }
section()  { echo -e "\n${BOLD}${BLUE}══════════ $* ══════════${NC}"; }

usage() {
    cat <<EOF
${BOLD}recon_pipeline.sh v${SCRIPT_VERSION}${NC}

Penggunaan:
  $0 -d <domain> [opsi]

Opsi:
  -d <domain>     Target domain (wajib), contoh: example.com
  -o <dir>        Direktori output (default: ./recon_<domain>_<timestamp>)
  -t <threads>    Jumlah concurrent threads (default: 50)
  --full          Mode agresif: tambah port scan full 65535 + nuclei severity semua level
  -h              Tampilkan bantuan ini

Contoh:
  $0 -d example.com
  $0 -d example.com -o ./hasil_recon -t 100 --full

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
    local optional=("assetfinder" "gau" "gowitness" "notify")
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
}

setup_workspace() {
    section "Setup Workspace"
    OUTDIR="${OUTDIR:-./recon_${DOMAIN}_$(date +%Y%m%d_%H%M%S)}"
    mkdir -p "$OUTDIR"/{subdomains,httpx,ports,urls,screenshots,vulns,report}
    log_ok "Workspace dibuat di: $OUTDIR"
    echo "$DOMAIN" > "$OUTDIR/scope.txt"
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

    log "Menjalankan subfinder..."
    subfinder -d "$DOMAIN" -all -silent -o "$out/subfinder.txt" 2>/dev/null

    if command -v assetfinder &>/dev/null; then
        log "Menjalankan assetfinder..."
        assetfinder --subs-only "$DOMAIN" > "$out/assetfinder.txt" 2>/dev/null
    fi

    log "Query crt.sh (Certificate Transparency logs)..."
    curl -s "https://crt.sh/?q=%25.${DOMAIN}&output=json" \
        | jq -r '.[].name_value' 2>/dev/null \
        | sed 's/\*\.//g' | sort -u > "$out/crtsh.txt" || log_warn "crt.sh query gagal/timeout, skip"

    log "Menggabungkan dan deduplikasi hasil..."
    cat "$out"/*.txt 2>/dev/null | sed 's/^\*\.//' | grep -F ".$DOMAIN" \
        | sort -u > "$out/all_subdomains.txt"

    local count
    count=$(wc -l < "$out/all_subdomains.txt" | tr -d ' ')
    log_ok "Ditemukan $count subdomain unik → $out/all_subdomains.txt"
    notify "Subdomain enum selesai: $count subdomain ditemukan untuk $DOMAIN"
}

# ─────────────────────────────── Phase 2: Live Host Probing ───────────────────────────────
phase_httpx_probe() {
    section "Phase 2: Live Host Probing (httpx)"
    local in="$OUTDIR/subdomains/all_subdomains.txt"
    local out="$OUTDIR/httpx"

    if [[ ! -s "$in" ]]; then
        log_warn "Tidak ada subdomain untuk di-probe, skip phase ini."
        return
    fi

    log "Probing $(wc -l < "$in" | tr -d ' ') host dengan httpx..."
    httpx -l "$in" \
        -silent -threads "$THREADS" \
        -status-code -title -tech-detect -content-length \
        -follow-redirects -ip \
        -json -o "$out/httpx_full.json" 2>/dev/null

    # Ekstrak daftar URL live saja untuk phase berikutnya
    jq -r '.url' "$out/httpx_full.json" 2>/dev/null | sort -u > "$out/live_hosts.txt"

    local count
    count=$(wc -l < "$out/live_hosts.txt" | tr -d ' ')
    log_ok "$count host live terdeteksi → $out/live_hosts.txt"
    notify "Live host probing selesai: $count host live"
}

# ─────────────────────────────── Phase 3: Port Scanning ───────────────────────────────
phase_port_scan() {
    section "Phase 3: Port Scanning (naabu)"
    local in="$OUTDIR/subdomains/all_subdomains.txt"
    local out="$OUTDIR/ports"

    if [[ ! -s "$in" ]]; then
        log_warn "Tidak ada target untuk port scan, skip."
        return
    fi

    local port_range="top-1000"
    local port_flag="-top-ports 1000"
    if $FULL_SCAN; then
        port_flag="-p -"
        port_range="1-65535 (full)"
    fi

    log "Menjalankan naabu (range: $port_range)..."
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

    if ! command -v gau &>/dev/null; then
        log_warn "gau tidak terinstall, skip phase ini."
        return
    fi

    log "Mengumpulkan historical URLs dari gau..."
    echo "$DOMAIN" | gau --threads "$THREADS" --subs 2>/dev/null | sort -u > "$out/all_urls.txt"

    # Kategorisasi cepat: file menarik, parameter, JS
    grep -E '\.(js)(\?|$)' "$out/all_urls.txt" > "$out/js_files.txt" 2>/dev/null
    grep -E '\?.+=' "$out/all_urls.txt" > "$out/urls_with_params.txt" 2>/dev/null
    grep -Ei '(admin|api|backup|config|\.env|swagger|graphql|internal|debug)' \
        "$out/all_urls.txt" > "$out/interesting_urls.txt" 2>/dev/null

    log_ok "$(wc -l < "$out/all_urls.txt" | tr -d ' ') URL ditemukan"
    log_ok "$(wc -l < "$out/interesting_urls.txt" 2>/dev/null | tr -d ' ') URL 'menarik' (admin/api/config/dll)"
}

# ─────────────────────────────── Phase 5: Screenshots ───────────────────────────────
phase_screenshots() {
    section "Phase 5: Screenshotting (opsional)"
    local in="$OUTDIR/httpx/live_hosts.txt"
    local out="$OUTDIR/screenshots"

    if ! command -v gowitness &>/dev/null; then
        log_warn "gowitness tidak terinstall, skip phase ini."
        return
    fi
    if [[ ! -s "$in" ]]; then
        log_warn "Tidak ada live host, skip screenshot."
        return
    fi

    log "Mengambil screenshot dari live hosts..."
    gowitness file -f "$in" -P "$out" --no-http 2>/dev/null || log_warn "gowitness gagal pada beberapa target"
    log_ok "Screenshot disimpan di $out"
}

# ─────────────────────────────── Phase 6: Vulnerability Scanning ───────────────────────────────
phase_nuclei_scan() {
    section "Phase 6: Vulnerability Scanning (nuclei)"
    local in="$OUTDIR/httpx/live_hosts.txt"
    local out="$OUTDIR/vulns"

    if [[ ! -s "$in" ]]; then
        log_warn "Tidak ada live host untuk nuclei, skip."
        return
    fi

    local severity="$NUCLEI_SEVERITY"
    $FULL_SCAN && severity="info,low,medium,high,critical"

    log "Menjalankan nuclei (severity: $severity)..."
    log_warn "Update templates terlebih dahulu jika lama tidak dijalankan: nuclei -update-templates"

    nuclei -l "$in" \
        -severity "$severity" \
        -silent -rate-limit "$THREADS" \
        -jsonl -o "$out/nuclei_results.jsonl" 2>/dev/null

    local count
    count=$(wc -l < "$out/nuclei_results.jsonl" 2>/dev/null | tr -d ' ')
    if [[ "$count" -gt 0 ]]; then
        log_warn "$count temuan terdeteksi! Cek $out/nuclei_results.jsonl"
        notify "⚠️ nuclei menemukan $count potensi kerentanan pada $DOMAIN"
    else
        log_ok "Tidak ada temuan signifikan dari nuclei"
    fi
}

# ─────────────────────────────── Phase 7: Report Generation ───────────────────────────────
generate_report() {
    section "Phase 7: Generating Report"
    local report="$OUTDIR/report/summary.md"
    local elapsed=$(( $(date +%s) - START_TIME ))

    local sub_count host_count port_count url_count vuln_count
    sub_count=$(wc -l < "$OUTDIR/subdomains/all_subdomains.txt" 2>/dev/null | tr -d ' ')
    host_count=$(wc -l < "$OUTDIR/httpx/live_hosts.txt" 2>/dev/null | tr -d ' ')
    port_count=$(wc -l < "$OUTDIR/ports/open_ports.txt" 2>/dev/null | tr -d ' ')
    url_count=$(wc -l < "$OUTDIR/urls/all_urls.txt" 2>/dev/null | tr -d ' ')
    vuln_count=$(wc -l < "$OUTDIR/vulns/nuclei_results.jsonl" 2>/dev/null | tr -d ' ')

    cat > "$report" <<EOF
# Recon Report: ${DOMAIN}

**Tanggal**: $(date '+%Y-%m-%d %H:%M:%S')
**Durasi**: ${elapsed}s
**Mode**: $($FULL_SCAN && echo "Full/Agresif" || echo "Standard")

## Ringkasan

| Metrik              | Jumlah |
|----------------------|--------|
| Subdomain ditemukan  | ${sub_count:-0} |
| Host live            | ${host_count:-0} |
| Kombinasi host:port terbuka | ${port_count:-0} |
| URL historis         | ${url_count:-0} |
| Temuan nuclei         | ${vuln_count:-0} |

## Struktur Output

\`\`\`
${OUTDIR}/
├── subdomains/all_subdomains.txt   # semua subdomain unik
├── httpx/httpx_full.json           # detail live host (status, title, tech)
├── httpx/live_hosts.txt            # daftar URL live
├── ports/open_ports.txt            # host:port terbuka
├── urls/interesting_urls.txt       # URL admin/api/config/dll
├── urls/js_files.txt               # file JS ditemukan
├── screenshots/                    # screenshot tiap host (jika gowitness ada)
├── vulns/nuclei_results.jsonl      # temuan kerentanan
└── report/summary.md               # laporan ini
\`\`\`

## Langkah Selanjutnya (rekomendasi)

1. Review \`vulns/nuclei_results.jsonl\` untuk temuan severity high/critical dulu.
2. Manual review terhadap \`urls/interesting_urls.txt\` (kemungkinan expose config/admin panel).
3. Content discovery lanjutan (ffuf/gobuster) pada host-host prioritas.
4. Verifikasi manual (bukan otomatis) sebelum melaporkan temuan apapun sebagai valid.

---
*Generated by recon_pipeline.sh v${SCRIPT_VERSION}*
EOF

    log_ok "Report tersimpan di: $report"
    echo -e "\n${BOLD}${GREEN}════════════════════════════════════════${NC}"
    cat "$report"
}

# ─────────────────────────────── Main ───────────────────────────────
main() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -d) DOMAIN="$2"; shift 2 ;;
            -o) OUTDIR="$2"; shift 2 ;;
            -t) THREADS="$2"; shift 2 ;;
            --full) FULL_SCAN=true; shift ;;
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
    phase_port_scan
    phase_url_discovery
    phase_screenshots
    phase_nuclei_scan
    generate_report

    local elapsed=$(( $(date +%s) - START_TIME ))
    log_ok "Pipeline selesai dalam ${elapsed}s. Semua hasil ada di: $OUTDIR"
    notify "✅ Recon pipeline selesai untuk $DOMAIN (${elapsed}s)"
}

main "$@"
