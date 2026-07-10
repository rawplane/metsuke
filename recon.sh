#!/usr/bin/env bash
#
# ==============================================================================
#  Pragmatic Bug Hunter — Pipeline Recon & Vulnerability Scanning Otomatis
#  Berdasarkan: Bug_Hunter_Pragmatic.md (ProjectDiscovery stack)
#  Profil target: Linux Mint XFCE, RAM 4GB — concurrency dijaga tetap rendah.
#
#  PENTING: Jalankan hanya terhadap domain/aset yang Anda punya izin untuk
#  diuji (target in-scope dari program Bug Bounty / VDP yang Anda ikuti).
#  sqlmap & Caido SENGAJA tidak diotomasi — sesuai filosofi doc: PoC manual,
#  bukan blind-attack otomatis.
#
#  Tools yang dibutuhkan:
#    subfinder, dnsx, httpx, katana   -> go install (lihat contoh di bawah)
#    gau, anew, notify, unfurl, ffuf  -> go install
#    arjun                            -> pip install arjun --break-system-packages
#    trufflehog                       -> github.com/trufflesecurity/trufflehog
#    jq, curl, rg (ripgrep)           -> apt install jq curl ripgrep
#
#  Contoh go install (path modul bisa berubah seiring versi major — cek repo
#  GitHub masing-masing tool kalau perintah di bawah gagal):
#    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
#    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
#    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
#    go install -v github.com/projectdiscovery/katana/cmd/katana@latest
#    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
#    go install -v github.com/projectdiscovery/notify/cmd/notify@latest
#    go install -v github.com/tomnomnom/anew@latest
#    go install -v github.com/tomnomnom/unfurl@latest
#    go install -v github.com/lc/gau/v2/cmd/gau@latest
#    go install -v github.com/ffuf/ffuf/v2@latest
#
#  Pemakaian:
#    ./bugbounty_pipeline.sh -d target.com [-o outdir] [-t threads] [-f] [-n] [-q]
#
#  Disarankan jalankan di dalam tmux supaya tidak putus saat disconnect:
#    tmux new -s recon './bugbounty_pipeline.sh -d target.com -n'
#
#  Untuk recon harian otomatis (anew memastikan hanya asset BARU yang dicatat
#  ulang), tinggal taruh di crontab, mis.:
#    0 3 * * * cd /path/to/folder && ./bugbounty_pipeline.sh -d target.com -n
# ==============================================================================

set -uo pipefail

# ---------- nilai default ----------
DOMAIN=""
OUTDIR=""
THREADS=25
DO_FUZZ=false
DO_NOTIFY=false
QUICK=false
WORDLIST="/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt"

# ---------- warna terminal ----------
C_GREEN="\033[0;32m"; C_YELLOW="\033[1;33m"; C_RED="\033[0;31m"; C_BLUE="\033[0;34m"; C_RESET="\033[0m"

usage() {
  cat <<EOF
Pragmatic Bug Hunter — Pipeline Recon & Vulnerability Scanning Otomatis

Pemakaian: $0 -d target.com [opsi]

  -d DOMAIN   domain target utama (wajib)
  -o OUTDIR   folder output          (default: ./recon/<domain>)
  -t THREADS  batas concurrency      (default: 25 — aman untuk RAM 4GB)
  -w PATH     wordlist untuk ffuf    (default: SecLists raft-large-directories.txt)
  -f          jalankan juga directory fuzzing via ffuf (lambat, default off)
  -n          kirim ringkasan lewat 'notify' (Telegram/Discord) saat selesai
  -q          mode cepat: subdomain -> dns -> http saja
  -h          tampilkan bantuan ini

Contoh:
  tmux new -s recon '$0 -d target.com -n'
EOF
  exit 1
}

while getopts "d:o:t:w:fnqh" opt; do
  case $opt in
    d) DOMAIN="$OPTARG" ;;
    o) OUTDIR="$OPTARG" ;;
    t) THREADS="$OPTARG" ;;
    w) WORDLIST="$OPTARG" ;;
    f) DO_FUZZ=true ;;
    n) DO_NOTIFY=true ;;
    q) QUICK=true ;;
    h) usage ;;
    *) usage ;;
  esac
done

[[ -z "$DOMAIN" ]] && { echo "Error: -d target.com wajib diisi."; usage; }
OUTDIR="${OUTDIR:-./recon/$DOMAIN}"
mkdir -p "$OUTDIR"/{subdomains,http,urls,params,secrets,vulns,fuzz,js}
LOGFILE="$OUTDIR/pipeline.log"
touch "$LOGFILE"

log()   { echo -e "${C_BLUE}[$(date '+%H:%M:%S')]${C_RESET} $*" | tee -a "$LOGFILE"; }
ok()    { echo -e "${C_GREEN}[+]${C_RESET} $*" | tee -a "$LOGFILE"; }
warn()  { echo -e "${C_YELLOW}[!]${C_RESET} $*" | tee -a "$LOGFILE"; }
err()   { echo -e "${C_RED}[x]${C_RESET} $*" | tee -a "$LOGFILE"; }
has()   { command -v "$1" &>/dev/null; }
count() { [[ -f "$1" ]] && wc -l < "$1" || echo 0; }

# ---------- cek dependency ----------
REQUIRED_CORE=(subfinder dnsx httpx anew)
REQUIRED_OPT=(gau katana arjun trufflehog nuclei ffuf notify unfurl jq curl rg)

missing_core=()
for t in "${REQUIRED_CORE[@]}"; do has "$t" || missing_core+=("$t"); done
if (( ${#missing_core[@]} > 0 )); then
  err "Tool wajib belum terpasang: ${missing_core[*]}. Pasang dulu (lihat komentar di atas skrip)."
  exit 1
fi
for t in "${REQUIRED_OPT[@]}"; do
  has "$t" || warn "Tool opsional '$t' tidak ditemukan — tahap terkait akan dilewati."
done

# ---------- tahapan pipeline ----------

stage_subdomains() {
  log "Tahap 1/7: Enumerasi subdomain (subfinder)"
  subfinder -d "$DOMAIN" -silent -all 2>>"$LOGFILE" | anew "$OUTDIR/subdomains/subs.txt" >/dev/null
  echo "$DOMAIN" | anew "$OUTDIR/subdomains/subs.txt" >/dev/null   # sertakan apex domain
  ok "$(count "$OUTDIR/subdomains/subs.txt") subdomain terekam (kumulatif)."
}

stage_dns() {
  log "Tahap 2/7: Resolusi DNS (dnsx)"
  dnsx -l "$OUTDIR/subdomains/subs.txt" -silent -threads "$THREADS" 2>>"$LOGFILE" \
    | anew "$OUTDIR/subdomains/alive.txt" >/dev/null
  ok "$(count "$OUTDIR/subdomains/alive.txt") subdomain aktif (resolve)."
}

stage_http() {
  log "Tahap 3/7: Probing HTTP (httpx)"
  httpx -l "$OUTDIR/subdomains/alive.txt" -silent -threads "$THREADS" \
    -title -status-code -tech-detect -follow-redirects 2>>"$LOGFILE" \
    > "$OUTDIR/http/web_details.txt"
  awk '{print $1}' "$OUTDIR/http/web_details.txt" | anew "$OUTDIR/http/web_urls.txt" >/dev/null
  ok "$(count "$OUTDIR/http/web_urls.txt") web server hidup. Detail: http/web_details.txt"
}

stage_urls() {
  log "Tahap 4/7: Pengambilan endpoint (gau + katana + unfurl)"
  if has gau; then
    cat "$OUTDIR/http/web_urls.txt" | gau --threads 5 2>>"$LOGFILE" \
      | anew "$OUTDIR/urls/urls.txt" >/dev/null
  fi
  if has katana; then
    katana -list "$OUTDIR/http/web_urls.txt" -silent -jc \
      -kf robotstxt,sitemapxml -c "$THREADS" -d 2 2>>"$LOGFILE" \
      | anew "$OUTDIR/urls/urls.txt" >/dev/null
  fi
  ok "$(count "$OUTDIR/urls/urls.txt") URL/endpoint unik terkumpul."
  if has unfurl; then
    cat "$OUTDIR/urls/urls.txt" | unfurl keys 2>/dev/null | sort -u \
      > "$OUTDIR/params/param_names_seen.txt"
    ok "$(count "$OUTDIR/params/param_names_seen.txt") nama parameter unik terlihat di URL."
  fi
}

stage_params() {
  has arjun || { warn "arjun tidak ditemukan, lewati parameter discovery."; return; }
  log "Tahap 5/7: Parameter discovery (arjun)"
  head -n 50 "$OUTDIR/http/web_urls.txt" > "$OUTDIR/params/_sample.txt"  # batasi runtime
  arjun -i "$OUTDIR/params/_sample.txt" -t "$THREADS" -oT "$OUTDIR/params/params.txt" \
    &>>"$LOGFILE" || warn "arjun keluar dengan error, cek pipeline.log."
  rm -f "$OUTDIR/params/_sample.txt"
  ok "Parameter discovery selesai -> params/params.txt (dibatasi 50 host/run)."
}

stage_secrets() {
  log "Tahap 6/7: Perburuan secret di file JS (ripgrep + trufflehog)"
  grep -Ei '\.js(\?|$)' "$OUTDIR/urls/urls.txt" 2>/dev/null | sort -u > "$OUTDIR/js/js_urls.txt"
  local n=0
  while IFS= read -r url; do
    (( n >= 300 )) && break   # batas wajar biar tidak jalan semalaman
    fname=$(echo "$url" | md5sum | cut -d' ' -f1)
    curl -s -m 10 -o "$OUTDIR/js/$fname.js" "$url" 2>>"$LOGFILE"
    ((n++))
  done < "$OUTDIR/js/js_urls.txt"
  ok "$n file JS diunduh untuk diperiksa."

  if has rg; then
    rg -i -o \
      "(api[_-]?key|secret|token|bearer|aws_(access|secret)_key)[\"']?\s*[:=]\s*[\"'][A-Za-z0-9_-]{10,}[\"']" \
      "$OUTDIR/js" > "$OUTDIR/secrets/rg_hits.txt" 2>/dev/null
    ok "$(count "$OUTDIR/secrets/rg_hits.txt") kandidat key/secret via ripgrep (banyak false positive, cek manual)."
  fi
  if has trufflehog; then
    trufflehog filesystem "$OUTDIR/js" --json 2>>"$LOGFILE" > "$OUTDIR/secrets/trufflehog.jsonl"
    ok "Scan trufflehog selesai -> secrets/trufflehog.jsonl"
  fi
}

stage_vulns() {
  has nuclei || { warn "nuclei tidak ditemukan, lewati vulnerability scan."; return; }
  log "Tahap 7/7: Vulnerability scanning (nuclei)"
  nuclei -l "$OUTDIR/http/web_urls.txt" -silent -rl 60 -c "$THREADS" \
    -o "$OUTDIR/vulns/vulns.txt" 2>>"$LOGFILE"
  local n; n=$(count "$OUTDIR/vulns/vulns.txt")
  if (( n > 0 )); then
    ok "nuclei menemukan $n finding -> vulns/vulns.txt"
  else
    ok "nuclei tidak menemukan match pada run ini."
  fi
}

stage_fuzz() {
  $DO_FUZZ || return
  if [[ ! -f "$WORDLIST" ]]; then
    warn "Wordlist tidak ditemukan di $WORDLIST — lewati ffuf. Pakai -w untuk path lain."
    return
  fi
  has ffuf || { warn "ffuf tidak ditemukan, lewati directory fuzzing."; return; }
  log "Tahap tambahan: Directory fuzzing (ffuf) pada beberapa host teratas"
  local i=0
  while IFS= read -r url; do
    (( i >= 5 )) && break   # hanya fuzz beberapa host per run, tetap ringan di RAM
    safe=$(echo "$url" | sed 's~[^A-Za-z0-9]~_~g')
    ffuf -w "$WORDLIST" -u "${url%/}/FUZZ" -mc 200,204,301,302,307,401,403 \
      -t "$THREADS" -silent -o "$OUTDIR/fuzz/$safe.json" -of json 2>>"$LOGFILE"
    ((i++))
  done < "$OUTDIR/http/web_urls.txt"
  ok "ffuf selesai fuzzing $i host -> folder fuzz/"
}

send_notify() {
  $DO_NOTIFY || return
  has notify || { warn "notify belum dikonfigurasi, lewati alert."; return; }
  local vulns_n subs_n web_n
  vulns_n=$(count "$OUTDIR/vulns/vulns.txt")
  subs_n=$(count "$OUTDIR/subdomains/subs.txt")
  web_n=$(count "$OUTDIR/http/web_urls.txt")
  { echo "Bug Hunter run selesai: $DOMAIN"
    echo "Subdomain: $subs_n | Web hidup: $web_n | Nuclei findings: $vulns_n"
  } | notify -silent 2>>"$LOGFILE"
  [[ "$vulns_n" -gt 0 ]] && cat "$OUTDIR/vulns/vulns.txt" | notify -silent 2>>"$LOGFILE"
  ok "Notifikasi terkirim."
}

summary() {
  echo
  echo "================= RINGKASAN: $DOMAIN ================="
  printf "%-24s %s\n" "Subdomain terekam:" "$(count "$OUTDIR/subdomains/subs.txt")"
  printf "%-24s %s\n" "Resolve (aktif):"   "$(count "$OUTDIR/subdomains/alive.txt")"
  printf "%-24s %s\n" "Web server hidup:"  "$(count "$OUTDIR/http/web_urls.txt")"
  printf "%-24s %s\n" "URL/endpoint:"      "$(count "$OUTDIR/urls/urls.txt")"
  printf "%-24s %s\n" "File JS diunduh:"   "$(count "$OUTDIR/js/js_urls.txt")"
  printf "%-24s %s\n" "Nuclei findings:"   "$(count "$OUTDIR/vulns/vulns.txt")"
  echo "========================================================"
  echo "Hasil lengkap ada di: $OUTDIR"
  echo
  warn "Lanjutan manual (sengaja TIDAK diotomasi):"
  warn "  1. Buka Caido pada host live di atas, tes alur registrasi/login/reset"
  warn "     password untuk cari IDOR & business-logic bug."
  warn "  2. Kalau nuclei/manual test menunjukkan indikasi SQLi, baru jalankan"
  warn "     sqlmap secara spesifik ke endpoint itu untuk PoC — jangan blind-run."
}

main() {
  log "Mulai pipeline untuk: $DOMAIN (threads=$THREADS, fuzz=$DO_FUZZ, quick=$QUICK)"
  stage_subdomains
  stage_dns
  stage_http
  if ! $QUICK; then
    stage_urls
    stage_params
    stage_secrets
    stage_vulns
    stage_fuzz
  fi
  send_notify
  summary
  log "Pipeline selesai."
}

main
