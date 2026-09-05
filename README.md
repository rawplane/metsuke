# Recon Pipeline

Automated reconnaissance pipeline untuk fase awal security assessment — subdomain enumeration, live host probing, port scanning, URL discovery, screenshotting, dan vulnerability scanning, dibungkus dalam satu script bash dengan report otomatis.

> ⚠️ **Legal disclaimer**
> Script ini hanya boleh dijalankan terhadap target yang sudah kamu miliki izin eksplisit untuk diuji — scope bug bounty resmi, kontrak pentest, atau aset milik sendiri. Scanning tanpa izin melanggar hukum di hampir semua yurisdiksi (di Indonesia termasuk dalam UU ITE). Script akan meminta konfirmasi otorisasi manual setiap kali dijalankan dan **tidak** menonaktifkan itu secara default.

---

## Fitur

- **Dependency check** otomatis — kasih tahu tool apa yang belum terinstall + perintah install-nya
- **7 fase recon** berjalan berurutan, tiap fase bisa gagal tanpa menghentikan pipeline
- **Output terstruktur** per kategori, gampang di-diff antar-run
- **Report markdown** otomatis di akhir dengan ringkasan angka
- **Webhook notification** opsional (Slack/Discord) di titik-titik penting
- **Mode `--full`** untuk scan lebih agresif (full port range, semua severity nuclei)

## Requirements

### Wajib
| Tool | Fungsi | Install |
|------|--------|---------|
| [subfinder](https://github.com/projectdiscovery/subfinder) | Subdomain enumeration | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| [httpx](https://github.com/projectdiscovery/httpx) | Live host probing | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| [naabu](https://github.com/projectdiscovery/naabu) | Port scanning | `go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` |
| [nuclei](https://github.com/projectdiscovery/nuclei) | Vulnerability scanning | `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| `curl`, `jq` | HTTP request & JSON parsing | `sudo apt install curl jq -y` |

### Opsional (fitur terkait di-skip otomatis jika tidak ada)
| Tool | Fungsi | Install |
|------|--------|---------|
| [assetfinder](https://github.com/tomnomnom/assetfinder) | Sumber tambahan subdomain | `go install -v github.com/tomnomnom/assetfinder@latest` |
| [gau](https://github.com/lc/gau) | Historical URL discovery | `go install -v github.com/lc/gau/v2/cmd/gau@latest` |
| [gowitness](https://github.com/sensepost/gowitness) | Screenshot otomatis | `go install -v github.com/sensepost/gowitness@latest` |

Pastikan `$GOPATH/bin` (biasanya `~/go/bin`) sudah masuk `$PATH`:
```bash
export PATH=$PATH:$(go env GOPATH)/bin
```

Update template nuclei secara berkala:
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

### Opsi

| Flag | Deskripsi | Default |
|------|-----------|---------|
| `-d <domain>` | Target domain (wajib) | — |
| `-o <dir>` | Direktori output | `./recon_<domain>_<timestamp>` |
| `-t <threads>` | Jumlah concurrent threads | `50` |
| `--full` | Mode agresif: full port scan (1-65535) + semua severity nuclei | `false` |
| `-h` | Tampilkan bantuan | — |

### Contoh

```bash
# Scan standar
./recon_pipeline.sh -d example.com

# Custom output dir + threads lebih tinggi
./recon_pipeline.sh -d example.com -o ./hasil_recon -t 100

# Mode agresif (full port range + semua severity)
./recon_pipeline.sh -d example.com --full

# Dengan notifikasi Slack/Discord
export RECON_WEBHOOK_URL="https://hooks.slack.com/services/xxx/yyy/zzz"
./recon_pipeline.sh -d example.com
```

Saat dijalankan, script akan meminta konfirmasi:
```
Ketik 'YA SAYA PUNYA IZIN' untuk melanjutkan:
```
Ketik persis seperti itu untuk lanjut. Ini disengaja agar tidak bisa "tidak sengaja" menjalankan scan ke target yang salah.

## Alur Pipeline

```
┌─────────────────────┐
│ 1. Subdomain Enum    │  subfinder + assetfinder + crt.sh → dedupe
└──────────┬───────────┘
           ▼
┌─────────────────────┐
│ 2. Live Host Probing │  httpx: status code, title, tech stack, IP
└──────────┬───────────┘
           ▼
┌─────────────────────┐
│ 3. Port Scanning     │  naabu: top-1000 (atau full dengan --full)
└──────────┬───────────┘
           ▼
┌─────────────────────┐
│ 4. URL Discovery     │  gau: historical URL + filter admin/api/config
└──────────┬───────────┘
           ▼
┌─────────────────────┐
│ 5. Screenshot        │  gowitness (opsional)
└──────────┬───────────┘
           ▼
┌─────────────────────┐
│ 6. Vuln Scanning     │  nuclei: berbasis severity
└──────────┬───────────┘
           ▼
┌─────────────────────┐
│ 7. Report Generation │  summary.md otomatis
└─────────────────────┘
```

Tiap fase independen — kalau satu tool tidak terinstall atau gagal, pipeline lanjut ke fase berikutnya dan mencatat warning, bukan berhenti total.

## Struktur Output

```
recon_<domain>_<timestamp>/
├── scope.txt                      # domain target (audit trail)
├── subdomains/
│   ├── subfinder.txt
│   ├── assetfinder.txt
│   ├── crtsh.txt
│   └── all_subdomains.txt         # hasil gabungan, deduped
├── httpx/
│   ├── httpx_full.json            # detail lengkap (status, title, tech, IP)
│   └── live_hosts.txt             # daftar URL host yang live
├── ports/
│   └── open_ports.txt             # host:port yang terbuka
├── urls/
│   ├── all_urls.txt                # semua historical URL
│   ├── js_files.txt                # file .js yang ditemukan
│   ├── urls_with_params.txt        # URL dengan parameter (kandidat testing)
│   └── interesting_urls.txt        # admin/api/backup/.env/swagger/dll
├── screenshots/                    # screenshot per host (jika gowitness ada)
├── vulns/
│   └── nuclei_results.jsonl        # temuan nuclei, format JSON lines
└── report/
    └── summary.md                  # ringkasan akhir + rekomendasi next step
```

## Langkah Setelah Recon

1. Cek `vulns/nuclei_results.jsonl` dulu — prioritaskan severity `high`/`critical`.
2. Review manual `urls/interesting_urls.txt` untuk kemungkinan exposed config/admin panel.
3. Lakukan content discovery lanjutan (`ffuf`/`gobuster`) pada host-host prioritas.
4. **Verifikasi manual setiap temuan** sebelum dilaporkan — hasil tool otomatis rawan false positive.

## Kustomisasi

- **Severity nuclei default**: ubah variabel `NUCLEI_SEVERITY` di bagian atas script.
- **Rate limiting**: sesuaikan `-rate` di `naabu` dan `-rate-limit` di `nuclei` kalau target sensitif terhadap traffic tinggi.
- **Tambah sumber subdomain**: tambahkan tool baru di fungsi `phase_subdomain_enum()`, cukup pipe hasilnya ke file `.txt` di folder `subdomains/`, sudah otomatis ikut ter-merge.
- **CI/CD integration**: prompt konfirmasi otorisasi bisa diganti dengan environment variable check (mis. `RECON_AUTHORIZED=true`) kalau mau dijalankan non-interaktif — pastikan tetap ada guardrail di level lain (mis. daftar domain yang di-whitelist).

## Troubleshooting

| Masalah | Solusi |
|---------|--------|
| `command not found` untuk tool ProjectDiscovery | Cek `$PATH` sudah include `$(go env GOPATH)/bin` |
| `crt.sh` query timeout/kosong | Layanan crt.sh kadang rate-limit atau down, tidak fatal — subfinder tetap jalan |
| Hasil nuclei kosong padahal ada temuan manual | Update templates: `nuclei -update-templates` |
| Port scan lambat | Turunkan `-rate` di naabu, atau kurangi jumlah target sekaligus |
| Ingin skip konfirmasi otorisasi | Jangan — itu ada agar tidak tidak sengaja mengarah ke target yang salah. Kalau untuk automation internal, ganti dengan approval gate di level CI/CD |
