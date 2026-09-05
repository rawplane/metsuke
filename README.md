# Recon Pipeline v2.0.0

Automated reconnaissance pipeline untuk fase awal security assessment — subdomain enumeration, live host probing, port scanning, URL discovery, subdomain takeover check, screenshotting, dan vulnerability scanning. Mendukung eksekusi paralel, resume, CDN-aware scanning, dan integrasi opsional dengan **Burp Suite**.

> ⚠️ **Legal disclaimer**
> Script ini hanya boleh dijalankan terhadap target yang sudah kamu miliki izin eksplisit untuk diuji — scope bug bounty resmi, kontrak pentest, atau aset milik sendiri. Scanning tanpa izin melanggar hukum di hampir semua yurisdiksi (di Indonesia termasuk dalam UU ITE). Script akan meminta konfirmasi otorisasi manual setiap kali dijalankan.
>
> Opsi `--burp-active-scan` bersifat **intrusif** (aktif menyerang endpoint melalui Burp Scanner) — pastikan scope otorisasi kamu eksplisit mengizinkan active scanning, bukan hanya recon pasif. Script akan menampilkan peringatan tambahan dan meminta konfirmasi khusus saat opsi ini aktif.

---

## Apa yang Baru di v2.0.0

| Fitur | Deskripsi |
|-------|-----------|
| 🔌 Integrasi Burp Suite | Passive traffic mirroring + active scan trigger (keduanya opsional, default mati) |
| ⚡ Eksekusi paralel | Phase independen jalan bersamaan, signifikan lebih cepat pada domain besar |
| ⏸️ Resume | Skip phase yang output-nya sudah ada — aman dilanjutkan kalau scan terputus |
| 🛡️ CDN-aware scanning | Skip port scan untuk host di belakang Cloudflare/WAF lain |
| 🔍 Subdomain takeover check | Phase baru pakai nuclei templates `http/takeovers/` |
| 📄 Config file | Simpan opsi default di file, tidak perlu ketik flag panjang tiap run |
| 🧪 Dry-run mode | Preview command yang akan dijalankan tanpa eksekusi nyata |
| 🔁 Retry logic | Panggilan ke crt.sh & Burp API otomatis retry saat gagal/timeout |
| 📊 JSON report | `results.json` untuk diintegrasikan ke tool/dashboard lain |
| 📝 Full logging | Semua output tersimpan ke `pipeline.log`, bukan cuma tampil di terminal |

## Requirements

### Wajib
| Tool | Fungsi | Install |
|------|--------|---------|
| [subfinder](https://github.com/projectdiscovery/subfinder) | Subdomain enumeration | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| [httpx](https://github.com/projectdiscovery/httpx) | Live host probing, CDN detection | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| [naabu](https://github.com/projectdiscovery/naabu) | Port scanning | `go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` |
| [nuclei](https://github.com/projectdiscovery/nuclei) | Vulnerability & takeover scanning | `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| `curl`, `jq` | HTTP request & JSON parsing | `sudo apt install curl jq -y` |

### Opsional (fitur terkait di-skip otomatis jika tidak ada)
| Tool | Fungsi | Install |
|------|--------|---------|
| [assetfinder](https://github.com/tomnomnom/assetfinder) | Sumber tambahan subdomain | `go install -v github.com/tomnomnom/assetfinder@latest` |
| [gau](https://github.com/lc/gau) | Historical URL discovery | `go install -v github.com/lc/gau/v2/cmd/gau@latest` |
| [gowitness](https://github.com/sensepost/gowitness) | Screenshot otomatis | `go install -v github.com/sensepost/gowitness@latest` |
| [Burp Suite](https://portswigger.net/burp) | Passive mirroring / active scan | Community (passive) atau Professional (active scan via REST API) |

Pastikan `$GOPATH/bin` (biasanya `~/go/bin`) sudah masuk `$PATH`:
```bash
export PATH=$PATH:$(go env GOPATH)/bin
```

Update template nuclei secara berkala (juga dipakai untuk takeover check):
```bash
nuclei -update-templates
```

## Instalasi

```bash
chmod +x recon_pipeline.sh
```

## Penggunaan

```bash
./recon_pipeline.sh -d <domain> [opsi]
```

### Opsi Dasar

| Flag | Deskripsi | Default |
|------|-----------|---------|
| `-d <domain>` | Target domain (wajib) | — |
| `-o <dir>` | Direktori output | `./recon_<domain>_<timestamp>` |
| `-t <threads>` | Jumlah concurrent threads | `50` |
| `--full` | Mode agresif: full port scan (1-65535) + semua severity nuclei | `false` |
| `--config <file>` | Load opsi default dari file config (bash source) | — |
| `-h` | Tampilkan bantuan | — |

### Opsi Performa

| Flag | Deskripsi |
|------|-----------|
| `--sequential` | Jalankan semua phase berurutan (default: paralel) |
| `--resume` | Skip phase yang output-nya sudah ada dari run sebelumnya |
| `--skip-cdn` | Skip port scanning untuk host yang terdeteksi di belakang CDN/WAF |
| `--dry-run` | Tampilkan command yang akan dijalankan tanpa eksekusi |

### Opsi Integrasi Burp Suite (opsional, default mati)

| Flag | Deskripsi |
|------|-----------|
| `--burp` | Mirror traffic `httpx` ke Burp proxy — Site Map terisi otomatis |
| `--burp-proxy <host:port>` | Alamat Burp proxy (default `127.0.0.1:8080`) |
| `--burp-active-scan` | Trigger **active scan** via Burp REST API (⚠️ intrusif) |
| `--burp-api-url <url>` | Alamat Burp REST API (default `http://127.0.0.1:1337`) |
| `--burp-api-key <key>` | API key Burp REST API (atau via `export BURP_API_KEY=...`) |

### Contoh

```bash
# Scan standar
./recon_pipeline.sh -d example.com

# Custom output dir, threads tinggi, skip CDN, bisa dilanjut kalau terputus
./recon_pipeline.sh -d example.com -o ./hasil -t 100 --skip-cdn --resume

# Mode agresif (full port range + semua severity nuclei)
./recon_pipeline.sh -d example.com --full

# Preview dulu tanpa eksekusi nyata
./recon_pipeline.sh -d example.com --dry-run

# Dengan notifikasi Slack/Discord
export RECON_WEBHOOK_URL="https://hooks.slack.com/services/xxx/yyy/zzz"
./recon_pipeline.sh -d example.com

# Load opsi dari config file
./recon_pipeline.sh -d example.com --config ./myconfig.conf
```

### Contoh Integrasi Burp Suite

```bash
# 1) Passive mirroring saja
#    Buka Burp Suite, pastikan proxy listener aktif di 127.0.0.1:8080, lalu:
./recon_pipeline.sh -d example.com --burp

# 2) Passive mirroring dengan port proxy custom
./recon_pipeline.sh -d example.com --burp --burp-proxy 127.0.0.1:9090

# 3) Passive + active scan (butuh Burp Suite Professional, REST API enabled)
export BURP_API_KEY="abcd1234-your-api-key"
./recon_pipeline.sh -d example.com --burp --burp-active-scan
```

**Cara aktifkan Burp REST API** (untuk opsi active scan): buka Burp Suite → `Settings` → `Suite` → `REST API` → aktifkan, generate API key. Jika endpoint di script tidak cocok dengan versi Burp kamu, cek dokumentasi Swagger di `{BURP_API_URL}/swagger.json` — format REST API bisa sedikit berbeda antar versi Burp.

Saat dijalankan, script akan meminta konfirmasi:
```
Ketik 'YA SAYA PUNYA IZIN' untuk melanjutkan:
```
Kalau `--burp-active-scan` aktif, akan muncul peringatan tambahan sebelum prompt konfirmasi ini — pastikan scope otorisasi memang mencakup active scanning.

## Config File

Simpan opsi yang sering dipakai di file config (format bash variable):

```bash
# myconfig.conf
THREADS=100
SKIP_CDN=true
BURP_PASSIVE=true
BURP_PROXY_HOST="127.0.0.1"
BURP_PROXY_PORT="8080"
NUCLEI_SEVERITY="medium,high,critical"
```

```bash
./recon_pipeline.sh -d example.com --config ./myconfig.conf
```

Flag CLI yang diberikan setelah `--config` akan override nilai dari file config.

## Alur Pipeline

```
┌──────────────────────┐
│ 1. Subdomain Enum     │  subfinder + assetfinder + crt.sh (retry) → dedupe
└──────────┬────────────┘
           ▼
┌──────────────────────┐
│ 2. Live Host Probing  │  httpx: status, title, tech, CDN detection
│    (+ Burp passive)   │  → traffic di-mirror ke Burp proxy jika --burp aktif
└──────────┬────────────┘
           ▼
     ┌─────┴─────────────────────────────────────────────────────┐
     │            PARALEL (default) atau SEQUENTIAL                │
     │                                                               │
     │  3. Port Scan (CDN-aware)   6. Screenshot (gowitness)        │
     │  4. URL Discovery (gau)     7. Vuln Scan (nuclei)             │
     │  5. Takeover Check (nuclei) 8. Burp Active Scan (opsional)    │
     └─────┬─────────────────────────────────────────────────────┘
           ▼
┌──────────────────────┐
│ Report Generation     │  summary.md + results.json
└──────────────────────┘
```

Tiap phase independen — kalau satu tool tidak terinstall atau gagal, pipeline lanjut dan mencatat warning, bukan berhenti total. Phase 3-8 berjalan **paralel secara default** karena semuanya cuma bergantung pada output Phase 1-2; pakai `--sequential` kalau mau eksekusi berurutan (misal untuk debugging atau resource terbatas).

## Struktur Output

```
recon_<domain>_<timestamp>/
├── pipeline.log                    # log lengkap seluruh eksekusi
├── scope.txt                       # domain target (audit trail)
├── subdomains/
│   ├── subfinder.txt
│   ├── assetfinder.txt
│   ├── crtsh.txt
│   └── all_subdomains.txt          # hasil gabungan, deduped
├── httpx/
│   ├── httpx_full.json             # detail lengkap (status, title, tech, cdn, IP)
│   ├── live_hosts.txt              # daftar URL host yang live
│   └── cdn_hosts.txt               # host yang terdeteksi di belakang CDN/WAF
├── ports/
│   ├── targets_noncdn.txt          # target port scan setelah filter CDN (jika --skip-cdn)
│   └── open_ports.txt              # host:port yang terbuka
├── urls/
│   ├── all_urls.txt                # semua historical URL
│   ├── js_files.txt                # file .js yang ditemukan
│   ├── urls_with_params.txt        # URL dengan parameter (kandidat testing)
│   └── interesting_urls.txt        # admin/api/backup/.env/swagger/dll
├── screenshots/                    # screenshot per host (jika gowitness ada)
├── vulns/
│   ├── nuclei_results.jsonl        # temuan vulnerability, format JSON lines
│   └── takeover_results.jsonl      # indikasi subdomain takeover
└── report/
    ├── summary.md                  # ringkasan akhir + rekomendasi next step
    ├── results.json                # ringkasan format JSON (untuk integrasi tool lain)
    └── burp_scan_response.json     # response dari Burp REST API (jika --burp-active-scan)
```

## Langkah Setelah Recon

1. Cek `vulns/nuclei_results.jsonl` dan `vulns/takeover_results.jsonl` dulu — prioritaskan severity `high`/`critical` dan indikasi takeover.
2. Review manual `urls/interesting_urls.txt` untuk kemungkinan exposed config/admin panel.
3. Kalau `--burp` aktif, buka Site Map di Burp Suite — struktur target sudah ter-mirror di sana untuk analisis manual lanjutan (manual testing, Repeater, dll).
4. Kalau `--burp-active-scan` aktif, cek progress di tab Scanner/Dashboard Burp Suite.
5. Lakukan content discovery lanjutan (`ffuf`/`gobuster`) pada host-host prioritas.
6. **Verifikasi manual setiap temuan** sebelum dilaporkan — hasil tool otomatis rawan false positive.

## Kustomisasi

- **Severity nuclei default**: ubah variabel `NUCLEI_SEVERITY` di bagian atas script, atau lewat config file.
- **Rate limiting**: sesuaikan `-rate` di `naabu` dan `-rate-limit` di `nuclei` kalau target sensitif terhadap traffic tinggi.
- **Tambah sumber subdomain**: tambahkan tool baru di fungsi `phase_subdomain_enum()`, pipe hasilnya ke file `.txt` di folder `subdomains/`, otomatis ikut ter-merge.
- **Tambah phase paralel baru**: tambahkan function `phase_xxx()` lalu daftarkan di `run_independent_phases()` (baik di blok paralel maupun sequential).
- **Ganti endpoint Burp REST API**: kalau format API berubah di versi Burp kamu, edit variabel `endpoint` di dalam `phase_burp_active_scan()`.
- **CI/CD integration**: prompt konfirmasi otorisasi bisa diganti dengan environment variable check (mis. `RECON_AUTHORIZED=true`) untuk dijalankan non-interaktif — pastikan tetap ada guardrail di level lain (mis. daftar domain yang di-whitelist), dan sebaiknya jangan aktifkan `--burp-active-scan` di pipeline otomatis tanpa review manusia.

## Troubleshooting

| Masalah | Solusi |
|---------|--------|
| `command not found` untuk tool ProjectDiscovery | Cek `$PATH` sudah include `$(go env GOPATH)/bin` |
| `crt.sh` query timeout/kosong | Layanan crt.sh kadang rate-limit atau down; script sudah retry otomatis 3x, kalau tetap gagal source ini di-skip |
| Hasil nuclei kosong padahal ada temuan manual | Update templates: `nuclei -update-templates` |
| Port scan lambat | Turunkan `-rate` di naabu, kurangi jumlah target sekaligus, atau pakai `--skip-cdn` |
| `Burp proxy TIDAK reachable` | Pastikan Burp Suite terbuka dan proxy listener aktif di host:port yang sama dengan `--burp-proxy` |
| `--burp-active-scan` gagal trigger | Cek API key benar, REST API sudah diaktifkan di Burp settings, dan endpoint sesuai versi Burp (lihat `{BURP_API_URL}/swagger.json`) |
| Mau lanjut scan yang terputus | Jalankan ulang command yang sama + tambahkan `--resume` |
| Ingin skip konfirmasi otorisasi | Jangan — itu ada agar tidak sengaja mengarah ke target yang salah. Untuk automation internal, ganti dengan approval gate di level CI/CD |
