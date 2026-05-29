#!/usr/bin/env bash
# ============================================================
#  01_recon_scan_v2.sh — Recon + Fuzz + Scan Pipeline v2
#  Improvements: parallel execution, progress bar, checkpoint
#  resume, rate limiting, scope validation, HTML report
#  LEGAL USE ONLY: Lab, CTF, atau sistem dengan izin tertulis
# ============================================================

set -uo pipefail

# ─── WARNA ───────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BLUE='\033[0;34m'; BOLD='\033[1m'
MAGENTA='\033[0;35m'; RESET='\033[0m'

# ─── KONFIGURASI DEFAULT ─────────────────────────────────────
THREADS="${THREADS:-40}"
RATE_LIMIT="${RATE_LIMIT:-100}"        # max requests/detik nuclei
FFUF_RATE="${FFUF_RATE:-50}"           # max req/s ffuf
TIMEOUT="${TIMEOUT:-10}"              # detik per request curl
NMAP_TIMING="${NMAP_TIMING:-T3}"      # T1=slow/stealth T3=normal T4=fast
WORDLIST="${WORDLIST:-$HOME/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt}"
SCOPE_FILE="${SCOPE_FILE:-}"          # file whitelist domain/IP (opsional)

# ─── HELPER ──────────────────────────────────────────────────
log()     { echo -e "${CYAN}[$(date +%H:%M:%S)]${RESET} ${CYAN}[*]${RESET} $1"; }
ok()      { echo -e "${CYAN}[$(date +%H:%M:%S)]${RESET} ${GREEN}[✓]${RESET} $1"; }
warn()    { echo -e "${CYAN}[$(date +%H:%M:%S)]${RESET} ${YELLOW}[!]${RESET} $1"; }
err()     { echo -e "${CYAN}[$(date +%H:%M:%S)]${RESET} ${RED}[✗]${RESET} $1"; }
section() {
  echo -e "\n${BOLD}${BLUE}╔══════════════════════════════════════╗${RESET}"
  echo -e "${BOLD}${BLUE}║${RESET}  ${BOLD}$1${RESET}"
  echo -e "${BOLD}${BLUE}╚══════════════════════════════════════╝${RESET}"
}

# ─── PROGRESS BAR ────────────────────────────────────────────
progress() {
  local label="$1"
  local pid="$2"
  local delay=0.3
  local spinstr='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
  local i=0
  local elapsed=0
  tput civis 2>/dev/null || true
  while kill -0 "$pid" 2>/dev/null; do
    local spin="${spinstr:$((i % ${#spinstr})):1}"
    printf "\r  ${CYAN}${spin}${RESET} ${label} ${YELLOW}[${elapsed}s]${RESET}   "
    sleep "$delay"
    elapsed=$(echo "$elapsed + $delay" | bc 2>/dev/null || echo "$elapsed")
    ((i++)) || true
  done
  printf "\r  ${GREEN}✓${RESET} ${label} ${GREEN}[done ${elapsed}s]${RESET}   \n"
  tput cnorm 2>/dev/null || true
}

# ─── CHECKPOINT ──────────────────────────────────────────────
CHECKPOINT_FILE=""

checkpoint_save() {
  local phase="$1"
  echo "$phase" >> "$CHECKPOINT_FILE"
  log "Checkpoint saved: $phase"
}

checkpoint_done() {
  local phase="$1"
  [[ -f "$CHECKPOINT_FILE" ]] && grep -qx "$phase" "$CHECKPOINT_FILE"
}

# ─── SCOPE VALIDATION ────────────────────────────────────────
in_scope() {
  local host="$1"
  if [[ -z "$SCOPE_FILE" ]] || [[ ! -f "$SCOPE_FILE" ]]; then
    return 0  # no scope file = semua in scope
  fi
  while IFS= read -r scope; do
    [[ -z "$scope" || "$scope" == \#* ]] && continue
    if [[ "$host" == *"$scope"* ]]; then
      return 0
    fi
  done < "$SCOPE_FILE"
  warn "OUT OF SCOPE: $host — diskip"
  return 1
}

# ─── BANNER ──────────────────────────────────────────────────
clear
echo -e "${RED}"
cat << 'EOF'
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗  ██╗  ██╗   ██╗██████╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗ ██║  ██║   ██║╚════██╗
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗██║  ██║   ██║ █████╔╝
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚████║  ╚██╗ ██╔╝██╔═══╝
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚███║   ╚████╔╝ ███████╗
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚══╝   ╚═══╝  ╚══════╝
EOF
echo -e "${YELLOW}  Recon + Fuzz + Scan Pipeline — v2.0${RESET}"
echo -e "${RED}  ⚠  LEGAL USE ONLY — lab / CTF / izin tertulis${RESET}"
echo -e "${BLUE}  Improvements: parallel · progress · checkpoint · rate-limit · scope${RESET}\n"

# ─── ARGUMEN ─────────────────────────────────────────────────
if [[ $# -lt 1 ]]; then
  echo -e "${RED}Usage:${RESET} $0 <target> [wordlist]"
  echo ""
  echo -e "  ${BOLD}Environment variables:${RESET}"
  echo -e "  THREADS=40          Thread count untuk ffuf"
  echo -e "  RATE_LIMIT=100      Max req/s untuk nuclei"
  echo -e "  FFUF_RATE=50        Max req/s untuk ffuf"
  echo -e "  TIMEOUT=10          Timeout per request (detik)"
  echo -e "  NMAP_TIMING=T3      T1=stealth T3=normal T4=agresif"
  echo -e "  SCOPE_FILE=scope.txt Whitelist domain/IP (1 per baris)"
  echo -e "  WORDLIST=path.txt   Custom wordlist untuk ffuf"
  echo ""
  echo -e "  ${BOLD}Contoh:${RESET}"
  echo -e "  $0 target.com"
  echo -e "  NMAP_TIMING=T1 RATE_LIMIT=20 $0 target.com   # stealth mode"
  exit 1
fi

TARGET="$1"
WORDLIST="${2:-$WORDLIST}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTDIR="./pentest_${TARGET}_${TIMESTAMP}"
CHECKPOINT_FILE="$OUTDIR/.checkpoint"
LOG_FILE=""
mkdir -p "$OUTDIR"
LOG_FILE="$OUTDIR/pipeline.log"

# Redirect semua output ke log juga
exec > >(tee -a "$LOG_FILE") 2>&1

log "Target    : $TARGET"
log "Output    : $OUTDIR"
log "Threads   : $THREADS | Rate: ${RATE_LIMIT}r/s | Timeout: ${TIMEOUT}s"
[[ -n "$SCOPE_FILE" ]] && log "Scope file: $SCOPE_FILE" || warn "Tidak ada scope file — semua host dianggap in-scope"

# ─── SCOPE CHECK TARGET UTAMA ────────────────────────────────
if ! in_scope "$TARGET"; then
  err "Target utama $TARGET OUT OF SCOPE. Hentikan."
  exit 1
fi

# ─── CEK RESUME ──────────────────────────────────────────────
if [[ -f "$CHECKPOINT_FILE" ]]; then
  warn "Checkpoint ditemukan! Resume dari sesi sebelumnya."
  echo -e "  Fase yang sudah selesai:"
  cat "$CHECKPOINT_FILE" | sed 's/^/    ✓ /'
  echo ""
  read -rp "$(echo -e ${YELLOW}"Resume? [Y/n]: "${RESET})" RESUME_ANS
  if [[ "${RESUME_ANS:-Y}" =~ ^[Nn]$ ]]; then
    rm -f "$CHECKPOINT_FILE"
    log "Mulai ulang dari awal"
  fi
else
  touch "$CHECKPOINT_FILE"
fi

# ─── CEK TOOLS ───────────────────────────────────────────────
section "CEK DEPENDENSI"
AVAILABLE_TOOLS=()
TOOLS=(nmap subfinder httpx whatweb ffuf nuclei nikto)
for tool in "${TOOLS[@]}"; do
  if command -v "$tool" &>/dev/null; then
    ok "$tool"
    AVAILABLE_TOOLS+=("$tool")
  else
    warn "$tool tidak ditemukan — fase terkait di-skip"
  fi
done

# ─── FASE 1: PORT SCAN ───────────────────────────────────────
section "FASE 1 — PORT SCAN"
if checkpoint_done "nmap"; then
  ok "Nmap sudah selesai (dari checkpoint), skip"
elif command -v nmap &>/dev/null; then
  log "Scanning $TARGET dengan timing $NMAP_TIMING ..."
  nmap -sV -"$NMAP_TIMING" --open \
       --host-timeout 300s \
       -oN "$OUTDIR/nmap.txt" \
       "$TARGET" > /dev/null 2>&1 &
  progress "nmap port scan" $!
  wait $!
  OPEN_PORTS=$(grep "^[0-9]" "$OUTDIR/nmap.txt" 2>/dev/null | awk '{print $1}' | tr '\n' ' ' || echo "")
  ok "Port terbuka: ${OPEN_PORTS:-tidak ada}"
  checkpoint_save "nmap"
else
  err "nmap tidak tersedia"
fi

# Tentukan HTTP target dari hasil nmap
HTTP_TARGETS=()
if [[ -f "$OUTDIR/nmap.txt" ]]; then
  grep -qE "443|8443" "$OUTDIR/nmap.txt" && HTTP_TARGETS+=("https://$TARGET")
  grep -qE "^80|^8080" "$OUTDIR/nmap.txt" && HTTP_TARGETS+=("http://$TARGET")
fi
[[ ${#HTTP_TARGETS[@]} -eq 0 ]] && HTTP_TARGETS=("https://$TARGET" "http://$TARGET")

# ─── FASE 2 + 3: PARALEL — FINGERPRINT & SUBDOMAIN ──────────
section "FASE 2+3 — FINGERPRINT & SUBDOMAIN (PARALEL)"

FINGERPRINT_PID=""
SUBDOMAIN_PID=""

# Fingerprint di background
if ! checkpoint_done "fingerprint"; then
  (
    for url in "${HTTP_TARGETS[@]}"; do
      command -v whatweb &>/dev/null && \
        whatweb -a 3 "$url" 2>/dev/null >> "$OUTDIR/whatweb.txt" || true
      command -v httpx &>/dev/null && \
        echo "$url" | httpx -silent -status-code -title -tech-detect \
        2>/dev/null >> "$OUTDIR/httpx.txt" || true
    done
  ) &
  FINGERPRINT_PID=$!
  log "Fingerprint berjalan di background (PID: $FINGERPRINT_PID)"
fi

# Subdomain enum di background
if ! checkpoint_done "subdomain"; then
  (
    if command -v subfinder &>/dev/null; then
      subfinder -d "$TARGET" -silent -o "$OUTDIR/subdomains_all.txt" 2>/dev/null || true
      if command -v httpx &>/dev/null && [[ -s "$OUTDIR/subdomains_all.txt" ]]; then
        # Filter scope sebelum probe
        if [[ -n "$SCOPE_FILE" ]] && [[ -f "$SCOPE_FILE" ]]; then
          grep -f "$SCOPE_FILE" "$OUTDIR/subdomains_all.txt" > "$OUTDIR/subdomains_inscope.txt" 2>/dev/null || \
            cp "$OUTDIR/subdomains_all.txt" "$OUTDIR/subdomains_inscope.txt"
        else
          cp "$OUTDIR/subdomains_all.txt" "$OUTDIR/subdomains_inscope.txt"
        fi
        httpx -l "$OUTDIR/subdomains_inscope.txt" -silent -status-code -title \
          -o "$OUTDIR/subdomains_live.txt" 2>/dev/null || true
      fi
    fi
  ) &
  SUBDOMAIN_PID=$!
  log "Subdomain enum berjalan di background (PID: $SUBDOMAIN_PID)"
fi

# Tunggu kedua proses selesai dengan progress bar
if [[ -n "$FINGERPRINT_PID" ]] && kill -0 "$FINGERPRINT_PID" 2>/dev/null; then
  progress "Web fingerprinting" "$FINGERPRINT_PID"
  wait "$FINGERPRINT_PID" || true
  checkpoint_save "fingerprint"
fi

if [[ -n "$SUBDOMAIN_PID" ]] && kill -0 "$SUBDOMAIN_PID" 2>/dev/null; then
  progress "Subdomain enumeration" "$SUBDOMAIN_PID"
  wait "$SUBDOMAIN_PID" || true
  SUB_COUNT=$(wc -l < "$OUTDIR/subdomains_all.txt" 2>/dev/null || echo 0)
  LIVE_COUNT=$(wc -l < "$OUTDIR/subdomains_live.txt" 2>/dev/null || echo 0)
  ok "$SUB_COUNT subdomain ditemukan, $LIVE_COUNT aktif"
  checkpoint_save "subdomain"
fi

# ─── FASE 4: DIRECTORY FUZZING ───────────────────────────────
section "FASE 4 — DIRECTORY FUZZING"
if checkpoint_done "ffuf"; then
  ok "Ffuf sudah selesai (dari checkpoint), skip"
elif command -v ffuf &>/dev/null; then
  if [[ ! -f "$WORDLIST" ]]; then
    warn "Wordlist tidak ditemukan: $WORDLIST"
    warn "Install: git clone --depth=1 https://github.com/danielmiessler/SecLists ~/SecLists"
  else
    FUZZ_TARGET="${HTTP_TARGETS[0]}"
    log "Fuzzing: $FUZZ_TARGET (rate: ${FFUF_RATE}r/s, threads: $THREADS)"

    ffuf -u "$FUZZ_TARGET/FUZZ" \
         -w "$WORDLIST" \
         -mc 200,201,301,302,401,403 \
         -t "$THREADS" \
         -rate "$FFUF_RATE" \
         -timeout "$TIMEOUT" \
         -ac \
         -o "$OUTDIR/ffuf_dirs.json" \
         -of json \
         -s 2>/dev/null &
    progress "Directory fuzzing" $!
    wait $!

    if command -v jq &>/dev/null && [[ -f "$OUTDIR/ffuf_dirs.json" ]]; then
      jq -r '.results[] | "\(.status) \(.url)"' "$OUTDIR/ffuf_dirs.json" \
        > "$OUTDIR/ffuf_dirs.txt" 2>/dev/null || true
      DIR_COUNT=$(jq '.results | length' "$OUTDIR/ffuf_dirs.json" 2>/dev/null || echo 0)
      ok "$DIR_COUNT direktori/endpoint ditemukan"
    fi
    checkpoint_save "ffuf"
  fi
else
  warn "ffuf tidak tersedia, skip"
fi

# ─── FASE 5: PARALEL — NUCLEI + NIKTO ───────────────────────
section "FASE 5 — VULNERABILITY SCAN (PARALEL)"
SCAN_TARGET="${HTTP_TARGETS[0]}"

NUCLEI_PID=""
NIKTO_PID=""

if ! checkpoint_done "nuclei" && command -v nuclei &>/dev/null; then
  log "Nuclei scan dimulai di background (rate: ${RATE_LIMIT}r/s) ..."
  nuclei -u "$SCAN_TARGET" \
         -severity medium,high,critical \
         -rate-limit "$RATE_LIMIT" \
         -bulk-size 25 \
         -concurrency 10 \
         -silent \
         -o "$OUTDIR/nuclei.txt" 2>/dev/null &
  NUCLEI_PID=$!
fi

if ! checkpoint_done "nikto" && command -v nikto &>/dev/null; then
  log "Nikto scan dimulai di background ..."
  nikto -h "$SCAN_TARGET" \
        -o "$OUTDIR/nikto.txt" \
        -Format txt \
        -maxtime 180 2>/dev/null &
  NIKTO_PID=$!
fi

# Tunggu keduanya
if [[ -n "$NUCLEI_PID" ]] && kill -0 "$NUCLEI_PID" 2>/dev/null; then
  progress "Nuclei vulnerability scan" "$NUCLEI_PID"
  wait "$NUCLEI_PID" || true
  VULN_COUNT=$(wc -l < "$OUTDIR/nuclei.txt" 2>/dev/null || echo 0)
  if [[ "$VULN_COUNT" -gt 0 ]]; then
    echo -e "${RED}"; cat "$OUTDIR/nuclei.txt"; echo -e "${RESET}"
    warn "$VULN_COUNT temuan dari nuclei!"
  else
    ok "Nuclei: tidak ada temuan signifikan"
  fi
  checkpoint_save "nuclei"
fi

if [[ -n "$NIKTO_PID" ]] && kill -0 "$NIKTO_PID" 2>/dev/null; then
  progress "Nikto web server scan" "$NIKTO_PID"
  wait "$NIKTO_PID" || true
  ok "Nikto selesai"
  checkpoint_save "nikto"
fi

# ─── FASE 6: HTML REPORT GENERATOR ──────────────────────────
section "FASE 6 — GENERATE HTML REPORT"
REPORT_FILE="$OUTDIR/report.html"

generate_report() {
  local target="$1"
  local outdir="$2"
  local ts
  ts=$(date "+%Y-%m-%d %H:%M:%S")

  # Ambil data
  local open_ports=""
  [[ -f "$outdir/nmap.txt" ]] && \
    open_ports=$(grep "^[0-9]" "$outdir/nmap.txt" 2>/dev/null | \
    awk '{printf "<tr><td>%s</td><td>%s</td><td>%s</td></tr>", $1, $3, $NF}' || echo "")

  local tech_info=""
  [[ -f "$outdir/httpx.txt" ]] && \
    tech_info=$(cat "$outdir/httpx.txt" 2>/dev/null | \
    while IFS= read -r line; do echo "<li>$line</li>"; done || echo "")

  local sub_count=0
  local live_count=0
  [[ -f "$outdir/subdomains_all.txt" ]] && sub_count=$(wc -l < "$outdir/subdomains_all.txt")
  [[ -f "$outdir/subdomains_live.txt" ]] && live_count=$(wc -l < "$outdir/subdomains_live.txt")

  local vuln_count=0
  local vuln_list=""
  if [[ -f "$outdir/nuclei.txt" ]]; then
    vuln_count=$(wc -l < "$outdir/nuclei.txt")
    vuln_list=$(cat "$outdir/nuclei.txt" 2>/dev/null | \
    while IFS= read -r line; do
      if echo "$line" | grep -qi "critical"; then COLOR="#ff4757"
      elif echo "$line" | grep -qi "high"; then COLOR="#ff6b35"
      elif echo "$line" | grep -qi "medium"; then COLOR="#ffcc00"
      else COLOR="#38bdf8"; fi
      echo "<li style='color:$COLOR;margin:4px 0'>$line</li>"
    done || echo "")
  fi

  local dir_count=0
  local dir_list=""
  if [[ -f "$outdir/ffuf_dirs.txt" ]]; then
    dir_count=$(wc -l < "$outdir/ffuf_dirs.txt")
    dir_list=$(cat "$outdir/ffuf_dirs.txt" 2>/dev/null | \
    while IFS= read -r line; do echo "<li>$line</li>"; done | head -50 || echo "")
  fi

  cat > "$REPORT_FILE" << HTMLEOF
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Pentest Report — $target</title>
<style>
  :root { --bg:#080c0f; --bg2:#0b1018; --bg3:#0d1520; --border:#1a2535;
          --text:#cdd9e5; --muted:#445566; --green:#00ff88; --yellow:#ffcc00;
          --red:#ff4757; --blue:#38bdf8; --orange:#ff6b35; }
  * { box-sizing:border-box; margin:0; padding:0; }
  body { background:var(--bg); color:var(--text); font-family:'Courier New',monospace;
         font-size:13px; line-height:1.6; }
  .header { background:var(--bg2); border-bottom:1px solid var(--border);
            padding:24px 32px; }
  .header h1 { font-size:20px; color:#e8f0fe; letter-spacing:2px; }
  .header .meta { color:var(--muted); font-size:11px; margin-top:6px; }
  .warning { background:#ff475718; border:1px solid #ff475744;
             margin:16px 32px; padding:10px 16px; border-radius:6px;
             color:var(--red); font-size:11px; }
  .container { padding:20px 32px; max-width:1100px; }
  .stats { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr));
           gap:12px; margin-bottom:24px; }
  .stat { background:var(--bg2); border:1px solid var(--border); border-radius:8px;
          padding:16px; text-align:center; }
  .stat .num { font-size:28px; font-weight:bold; margin-bottom:4px; }
  .stat .lbl { font-size:10px; color:var(--muted); letter-spacing:2px; }
  .section { background:var(--bg2); border:1px solid var(--border);
             border-radius:8px; margin-bottom:16px; overflow:hidden; }
  .section-title { padding:12px 16px; border-bottom:1px solid var(--border);
                   font-weight:bold; font-size:12px; letter-spacing:2px;
                   display:flex; justify-content:space-between; align-items:center; }
  .section-body { padding:16px; }
  table { width:100%; border-collapse:collapse; }
  th,td { padding:8px 12px; text-align:left; border-bottom:1px solid var(--border);
          font-size:12px; }
  th { color:var(--muted); font-size:10px; letter-spacing:1px; }
  ul { list-style:none; padding:0; }
  ul li { padding:4px 0; border-bottom:1px solid var(--border); font-size:12px; }
  ul li:last-child { border-bottom:none; }
  .badge { padding:2px 8px; border-radius:4px; font-size:10px; }
  .badge-red { background:#ff475718; color:var(--red); border:1px solid #ff475744; }
  .badge-green { background:#00ff8818; color:var(--green); border:1px solid #00ff8844; }
  .badge-yellow { background:#ffcc0018; color:var(--yellow); border:1px solid #ffcc0044; }
  .footer { border-top:1px solid var(--border); padding:16px 32px;
            color:var(--muted); font-size:10px; letter-spacing:1px; }
</style>
</head>
<body>
<div class="header">
  <h1>⬡ PENTEST REPORT</h1>
  <div class="meta">Target: $target &nbsp;|&nbsp; Generated: $ts &nbsp;|&nbsp; Tool: recon_scan_v2</div>
</div>
<div class="warning">⚠ CONFIDENTIAL — Dokumen ini berisi informasi keamanan sensitif. Distribusi tanpa izin adalah ilegal.</div>
<div class="container">

  <!-- Stats Overview -->
  <div class="stats">
    <div class="stat">
      <div class="num" style="color:var(--blue)">$(echo "$open_ports" | grep -c "tr" 2>/dev/null || echo 0)</div>
      <div class="lbl">OPEN PORTS</div>
    </div>
    <div class="stat">
      <div class="num" style="color:var(--green)">$sub_count</div>
      <div class="lbl">SUBDOMAINS</div>
    </div>
    <div class="stat">
      <div class="num" style="color:var(--yellow)">$live_count</div>
      <div class="lbl">LIVE HOSTS</div>
    </div>
    <div class="stat">
      <div class="num" style="color:var(--orange)">$dir_count</div>
      <div class="lbl">DIRS FOUND</div>
    </div>
    <div class="stat">
      <div class="num" style="color:var(--red)">$vuln_count</div>
      <div class="lbl">VULNS FOUND</div>
    </div>
  </div>

  <!-- Port Scan -->
  <div class="section">
    <div class="section-title">
      <span>◉ PORT SCAN (nmap)</span>
      <span class="badge badge-blue">nmap</span>
    </div>
    <div class="section-body">
      <table>
        <tr><th>PORT</th><th>STATE</th><th>SERVICE</th></tr>
        $open_ports
      </table>
    </div>
  </div>

  <!-- Web Technology -->
  <div class="section">
    <div class="section-title">
      <span>◈ WEB TECHNOLOGY</span>
      <span class="badge badge-green">httpx</span>
    </div>
    <div class="section-body"><ul>$tech_info</ul></div>
  </div>

  <!-- Vulnerabilities -->
  <div class="section">
    <div class="section-title">
      <span>⬢ VULNERABILITIES</span>
      <span class="badge badge-red">nuclei · $vuln_count findings</span>
    </div>
    <div class="section-body">
      $([ "$vuln_count" -eq 0 ] && echo '<p style="color:var(--green)">✓ Tidak ada temuan signifikan</p>' || echo "<ul>$vuln_list</ul>")
    </div>
  </div>

  <!-- Directories -->
  <div class="section">
    <div class="section-title">
      <span>◆ DISCOVERED ENDPOINTS</span>
      <span class="badge badge-yellow">ffuf · $dir_count found</span>
    </div>
    <div class="section-body">
      $([ "$dir_count" -eq 0 ] && echo '<p style="color:var(--muted)">Tidak ada hasil</p>' || echo "<ul>$dir_list</ul>")
      $([ "$dir_count" -gt 50 ] && echo '<p style="color:var(--muted);margin-top:8px">... dan $((dir_count-50)) lainnya. Lihat ffuf_dirs.txt</p>')
    </div>
  </div>

  <!-- Files List -->
  <div class="section">
    <div class="section-title"><span>◎ OUTPUT FILES</span></div>
    <div class="section-body">
      <table>
        <tr><th>FILE</th><th>SIZE</th><th>KETERANGAN</th></tr>
        $(ls -lh "$outdir"/*.txt "$outdir"/*.json 2>/dev/null | \
          awk '{printf "<tr><td>%s</td><td>%s</td><td></td></tr>", $NF, $5}' || echo "")
      </table>
    </div>
  </div>

</div>
<div class="footer">RECON_SCAN_V2 · $ts · Target: $target · ⚠ LEGAL USE ONLY</div>
</body>
</html>
HTMLEOF
}

log "Generating HTML report ..."
generate_report "$TARGET" "$OUTDIR"
ok "Report: $REPORT_FILE"

# ─── RINGKASAN TERMINAL ──────────────────────────────────────
section "RINGKASAN AKHIR"
END_TIME=$(date +%s)

echo -e "\n${BOLD}╔══════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║          HASIL PIPELINE v2               ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════════╝${RESET}\n"

echo -e "  ${CYAN}Target    :${RESET} $TARGET"
echo -e "  ${CYAN}Output    :${RESET} $OUTDIR/"
echo -e "  ${CYAN}Log       :${RESET} $LOG_FILE"
echo -e "  ${CYAN}Report    :${RESET} $REPORT_FILE"
echo ""

# Stats
[[ -f "$OUTDIR/nmap.txt" ]] && \
  echo -e "  ${GREEN}►${RESET} Open ports  : $(grep -c "^[0-9]" "$OUTDIR/nmap.txt" 2>/dev/null || echo 0)"
[[ -f "$OUTDIR/subdomains_all.txt" ]] && \
  echo -e "  ${GREEN}►${RESET} Subdomains  : $(wc -l < "$OUTDIR/subdomains_all.txt" 2>/dev/null || echo 0) total, $(wc -l < "$OUTDIR/subdomains_live.txt" 2>/dev/null || echo 0) live"
[[ -f "$OUTDIR/ffuf_dirs.txt" ]] && \
  echo -e "  ${YELLOW}►${RESET} Directories : $(wc -l < "$OUTDIR/ffuf_dirs.txt" 2>/dev/null || echo 0) ditemukan"
[[ -f "$OUTDIR/nuclei.txt" ]] && {
  VC=$(wc -l < "$OUTDIR/nuclei.txt" 2>/dev/null || echo 0)
  [[ "$VC" -gt 0 ]] && \
    echo -e "  ${RED}►${RESET} Nuclei vulns: $VC temuan!" || \
    echo -e "  ${GREEN}►${RESET} Nuclei vulns: clean"
}

echo ""
echo -e "${YELLOW}Langkah selanjutnya:${RESET}"
echo -e "  → Buka report  : firefox $REPORT_FILE &"
echo -e "  → Lihat vulns  : cat $OUTDIR/nuclei.txt"
echo -e "  → Exploit      : ./02_exploit_v2.sh $TARGET"
echo ""
ok "Pipeline v2 selesai!"
