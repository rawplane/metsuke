# ⬡ Pentest Automation Pipeline v2

> Automated Web Penetration Testing Framework — Recon → Fuzz → Scan → Exploit
>
> ⚠️ **LEGAL USE ONLY** — Hanya untuk lab, CTF, atau sistem dengan izin tertulis. Penggunaan tanpa izin adalah ilegal dan dapat dipidana.

---

## 📋 Daftar Isi

- [Deskripsi](#deskripsi)
- [Fitur v2](#fitur-v2)
- [Struktur File](#struktur-file)
- [Requirements](#requirements)
- [Instalasi](#instalasi)
- [Cara Penggunaan](#cara-penggunaan)
- [Environment Variables](#environment-variables)
- [Output](#output)
- [Contoh Penggunaan](#contoh-penggunaan)
- [Rating & Roadmap](#rating--roadmap)
- [Disclaimer](#disclaimer)

---

## Deskripsi

Pentest Automation Pipeline adalah mini penetration testing framework berbasis Bash yang menggabungkan tools terbaik komunitas security ke dalam satu pipeline otomatis. Dirancang ringan di RAM (tanpa Java/Ruby), cocok untuk mesin dengan spesifikasi terbatas.

Pipeline ini terdiri dari 3 script utama:

| Script | Fungsi |
|--------|--------|
| `install_tools.sh` | Bootstrap installer semua dependensi |
| `01_recon_scan_v2.sh` | Pipeline Recon + Fuzz + Scan (non-destruktif) |
| `02_exploit_v2.sh` | Pipeline Exploitation (SQLi, brute-force, XSS) |

---

## Fitur v2

Dibandingkan v1, versi ini memiliki improvement signifikan:

- **Parallel Execution** — Fase fingerprint + subdomain berjalan bersamaan, nuclei + nikto paralel, hemat waktu hingga 40%
- **Progress Bar** — Spinner animasi dengan elapsed time untuk setiap proses background
- **Resume Checkpoint** — Jika script terputus di tengah jalan, lanjut dari fase terakhir tanpa mengulang dari awal
- **Rate Limiting** — Kontrol penuh req/s untuk semua tools (ffuf, nuclei, hydra) agar tidak membebani server
- **Scope Validation** — Whitelist domain/IP via file, host di luar scope otomatis di-skip
- **HTML Report** — Dashboard laporan HTML otomatis dihasilkan di akhir setiap pipeline
- **Audit Log** — Semua output tercatat di `pipeline.log` dengan timestamp
- **Stealth Mode** — Kontrol via `NMAP_TIMING=T1` dan `RATE_LIMIT=10` untuk scan lebih senyap
- **Auto-detect** — Login page dan parameter SQLi otomatis dideteksi dari hasil recon

---

## Struktur File

```
pentest-pipeline/
├── install_tools.sh        ← Installer semua dependensi
├── 01_recon_scan_v2.sh     ← Phase 1: Recon + Fuzz + Scan
├── 02_exploit_v2.sh        ← Phase 2: Exploitation
├── scope.txt               ← (opsional) Whitelist domain/IP
└── README.md
```

Output per sesi tersimpan otomatis di:

```
pentest_target.com_YYYYMMDD_HHMMSS/
├── .checkpoint             ← Resume state
├── pipeline.log            ← Audit log timestamped
├── report.html             ← HTML report fase 1
├── nmap.txt                ← Hasil port scan
├── whatweb.txt             ← Web technology fingerprint
├── httpx.txt               ← HTTP probing results
├── subdomains_all.txt      ← Semua subdomain
├── subdomains_live.txt     ← Subdomain aktif
├── ffuf_dirs.json          ← Raw ffuf output
├── ffuf_dirs.txt           ← Direktori & endpoint ditemukan
├── nuclei.txt              ← Vulnerability findings
├── nikto.txt               ← Server misconfig findings
└── exploit/
    ├── .checkpoint         ← Resume state exploit
    ├── exploit.log         ← Audit log exploit
    ├── exploit_report.html ← HTML report fase 2
    ├── headers_raw.txt     ← Raw HTTP headers
    ├── header_results.txt  ← Security header check
    ├── missing_headers.txt ← Header yang tidak ada
    ├── sensitive_files.txt ← File/endpoint sensitif
    ├── xss_results.txt     ← XSS & SSTI findings
    ├── sqlmap_output.txt   ← SQLi test results
    ├── sqlmap/             ← sqlmap output directory
    └── hydra_output.txt    ← Brute-force results
```

---

## Requirements

### Sistem Operasi
- Linux Mint / Ubuntu 22.04+ / Debian 11+
- RAM minimum: 2GB (optimal 4GB+)
- Disk: ~3.5GB untuk semua tools + wordlists

### Dependensi Utama

| Tool | Versi | Install Via |
|------|-------|-------------|
| nmap | latest | apt |
| nikto | latest | apt |
| hydra | latest | apt |
| sqlmap | latest | apt |
| whatweb | latest | apt |
| golang | 1.21+ | apt |
| python3 | 3.10+ | apt |
| subfinder | latest | go install |
| httpx | latest | go install |
| ffuf | v2+ | go install |
| nuclei | v3+ | go install |
| gobuster | v3+ | go install |
| wapiti3 | latest | pip3 |
| mitmproxy | latest | pip3 |
| httpie | latest | pip3 |
| Docker | latest | get.docker.com |
| lazydocker | latest | binary |

### Wordlists

| Wordlist | Ukuran | Keterangan |
|----------|--------|------------|
| SecLists | ~1.5GB | Koleksi lengkap: dir, param, subdomain |
| rockyou.txt | ~134MB | Password wordlist untuk brute-force |

---

## Instalasi

### 1. Clone atau download script

```bash
git clone https://github.com/username/pentest-pipeline.git
cd pentest-pipeline
```

### 2. Beri izin eksekusi

```bash
chmod +x install_tools.sh 01_recon_scan_v2.sh 02_exploit_v2.sh
```

### 3. Jalankan installer (sebagai root)

```bash
sudo bash install_tools.sh
```

Installer akan otomatis:
- Install semua tools via apt, go, dan pip
- Download nuclei templates
- Clone SecLists ke `~/SecLists`
- Setup rockyou.txt di `~/rockyou.txt`
- Install Docker dan lazydocker
- Setup PATH di `.bashrc` dan `.zshrc`

### 4. Reload shell

```bash
source ~/.bashrc
```

### 5. Verifikasi instalasi

```bash
# Cek tools penting
nmap --version
nuclei -version
ffuf -V
subfinder -version
sqlmap --version
```

---

## Cara Penggunaan

### Phase 1 — Recon + Fuzz + Scan

```bash
./01_recon_scan_v2.sh <target> [wordlist]
```

**Contoh:**

```bash
# Scan dasar
./01_recon_scan_v2.sh target.com

# Dengan custom wordlist
./01_recon_scan_v2.sh target.com ~/SecLists/Discovery/Web-Content/big.txt

# Stealth mode (lambat, lebih sulit terdeteksi)
NMAP_TIMING=T1 RATE_LIMIT=10 FFUF_RATE=5 ./01_recon_scan_v2.sh target.com

# Dengan scope file
echo "target.com" > scope.txt
SCOPE_FILE=scope.txt ./01_recon_scan_v2.sh target.com
```

### Phase 2 — Exploitation

```bash
./02_exploit_v2.sh <target_url>
```

**Contoh:**

```bash
# Basic (header check + sensitive files + XSS saja)
./02_exploit_v2.sh https://target.com

# Lengkap dengan SQLi dan brute-force
SQLI_URL='https://target.com/page?id=1' \
LOGIN_URL='https://target.com/login' \
LOGIN_FORM='/login:username=^USER^&password=^PASS^:Invalid credentials' \
./02_exploit_v2.sh https://target.com

# Dengan custom wordlist password
PASSLIST='/path/to/passwords.txt' \
LOGIN_URL='https://target.com/login' \
./02_exploit_v2.sh https://target.com
```

> **Catatan:** Script akan meminta konfirmasi `YES LEGAL` sebelum berjalan.

### Lab Lokal (Aman & Legal)

```bash
# Jalankan DVWA
docker run -d -p 8888:80 --name dvwa vulnerables/web-dvwa

# Jalankan Juice Shop
docker run -d -p 3000:3000 --name juiceshop bkimminich/juice-shop

# Scan ke lab lokal
./01_recon_scan_v2.sh localhost
./02_exploit_v2.sh http://localhost:8888

# Monitor container
lazydocker
```

### Jalankan di tmux (Rekomendasi)

Agar sesi tidak putus jika terminal tertutup:

```bash
# Buat sesi baru
tmux new -s pentest

# Jalankan script di dalam sesi
./01_recon_scan_v2.sh target.com

# Jika terminal tertutup, attach lagi
tmux attach -t pentest

# Layout 3 panel (recon | scan | exploit)
# Ctrl+b lalu % untuk split vertikal
# Ctrl+b lalu " untuk split horizontal
# Ctrl+b lalu arrow untuk pindah panel
```

### Resume Checkpoint

Jika script terputus di tengah jalan, cukup jalankan ulang perintah yang sama — script akan otomatis menawarkan resume dari fase terakhir:

```bash
./01_recon_scan_v2.sh target.com
# Output: "Checkpoint ditemukan! Resume? [Y/n]:"
```

---

## Environment Variables

### 01_recon_scan_v2.sh

| Variable | Default | Keterangan |
|----------|---------|------------|
| `THREADS` | `40` | Thread count untuk ffuf |
| `RATE_LIMIT` | `100` | Max req/s untuk nuclei |
| `FFUF_RATE` | `50` | Max req/s untuk ffuf |
| `TIMEOUT` | `10` | Timeout per request (detik) |
| `NMAP_TIMING` | `T3` | T1=stealth, T3=normal, T4=agresif |
| `SCOPE_FILE` | _(kosong)_ | Path file whitelist domain/IP |
| `WORDLIST` | `~/SecLists/.../medium.txt` | Custom wordlist untuk ffuf |

### 02_exploit_v2.sh

| Variable | Default | Keterangan |
|----------|---------|------------|
| `SQLI_URL` | _(kosong)_ | URL parameter untuk SQLi test |
| `LOGIN_URL` | _(kosong)_ | URL halaman login |
| `LOGIN_FORM` | _(kosong)_ | Format form brute-force hydra |
| `USERLIST` | _(built-in)_ | Path wordlist username |
| `PASSLIST` | `~/rockyou.txt` | Path wordlist password |
| `HYDRA_THREADS` | `4` | Thread count hydra |
| `HYDRA_TIMEOUT` | `30` | Timeout hydra (detik) |
| `SQLMAP_LEVEL` | `3` | Level agresivitas sqlmap (1-5) |
| `SQLMAP_RISK` | `2` | Risk level sqlmap (1-3) |
| `SQLMAP_THREADS` | `3` | Thread count sqlmap |
| `CURL_TIMEOUT` | `10` | Timeout curl (detik) |
| `SCOPE_FILE` | _(kosong)_ | Path file whitelist domain/IP |

### Format scope.txt

```
# Komentar diawali #
target.com
subdomain.target.com
192.168.1.100
```

---

## Output

Di akhir setiap pipeline, dua file HTML report dihasilkan otomatis:

**`report.html`** (Phase 1) — menampilkan:
- Stats overview: open ports, subdomain, dirs, vulns
- Tabel port scan hasil nmap
- Web technology fingerprint
- Daftar vulnerability dari nuclei
- Endpoint & direktori yang ditemukan

**`exploit_report.html`** (Phase 2) — menampilkan:
- Status SQLi, XSS, credentials, sensitive files
- Daftar security header yang hilang
- Daftar file sensitif yang terekspos
- XSS & SSTI payload yang berhasil

Buka report di browser:

```bash
firefox ./pentest_target.com_*/report.html &
firefox ./pentest_target.com_*/exploit/exploit_report.html &
```

---

## Contoh Penggunaan

### Skenario 1: CTF Web Challenge

```bash
# Setup lab
docker run -d -p 8888:80 vulnerables/web-dvwa

# Recon
./01_recon_scan_v2.sh localhost

# Exploit dengan SQLi
SQLI_URL='http://localhost:8888/vulnerabilities/sqli/?id=1&Submit=Submit' \
./02_exploit_v2.sh http://localhost:8888
```

### Skenario 2: Bug Bounty Recon

```bash
# Buat scope file sesuai program
cat > scope.txt << EOF
target.com
api.target.com
dev.target.com
EOF

# Scan stealthy
SCOPE_FILE=scope.txt \
NMAP_TIMING=T2 \
RATE_LIMIT=30 \
FFUF_RATE=20 \
./01_recon_scan_v2.sh target.com
```

### Skenario 3: Internal Pentest

```bash
# Scan jaringan internal
./01_recon_scan_v2.sh 192.168.1.100

# Full exploit assessment
SQLI_URL='http://192.168.1.100/app?id=1' \
LOGIN_URL='http://192.168.1.100/login' \
LOGIN_FORM='/login:user=^USER^&pass=^PASS^:Login failed' \
USERLIST='./internal_users.txt' \
./02_exploit_v2.sh http://192.168.1.100
```

---

## Rating & Roadmap

Rating saat ini: **83/100**

| Kategori | Score |
|----------|-------|
| Functionality | 85/100 |
| Reliability | 80/100 |
| Performance | 82/100 |
| Security & Ethics | 85/100 |
| Code Quality | 80/100 |
| Completeness | 75/100 |

### Roadmap Improvement

- [ ] HTML report lebih detail dengan grafik severity
- [ ] Post-exploitation module (privilege escalation check)
- [ ] Integrasi Caido/mitmproxy untuk intercept otomatis
- [ ] Notifikasi (Telegram/Discord) saat temuan kritis
- [ ] Support multi-target dari file list
- [ ] Docker container untuk pipeline itu sendiri

---

## Disclaimer

Script ini dibuat untuk tujuan **edukasi, penelitian keamanan, CTF, dan penetration testing legal**.

Pengguna bertanggung jawab penuh atas penggunaan script ini. Penulis tidak bertanggung jawab atas:
- Penggunaan ilegal atau tidak beretika
- Kerusakan sistem yang tidak disengaja
- Konsekuensi hukum akibat penyalahgunaan

**Selalu dapatkan izin tertulis sebelum melakukan pengujian pada sistem apapun.**

---

*Pentest Automation Pipeline v2 — Built for security researchers, by security researchers.*
