# 目付 (metsuke.sh)

**Metsuke** (目付) was an inspector role in Edo-era Japan — an officially mandated position, with a clear mandate, to observe and report before acting. This name was chosen because the defining trait of this tool isn't just scan speed, but authorization discipline (a permission-confirmation gate) and structured reporting before performing deep inspection of sensitive endpoints.

> ⚠️ **LEGAL WARNING**
> This script may **ONLY** be run against targets for which you already have explicit permission. Scanning without authorization is illegal in most jurisdictions. Every execution requires manual authorization confirmation before proceeding.

---

## Features

- 8 sequential/parallel recon phases: subdomain enum → live host probing → port scan → URL discovery → subdomain takeover check → screenshots → vulnerability scan → Burp active scan (optional)
- Mandatory authorization confirmation gate before any execution
- `--resume` to skip phases whose output already exists, `--dry-run` to preview commands without executing them
- CDN-aware port scanning (optionally skip hosts behind a WAF/CDN)
- Combined URL discovery: passive sources (`gau`, `urlfinder`) + active crawling (`katana`, JS-aware)
- URL normalization & dedup based on path-templating and parameter-signature (reduces noise from IDs/UUIDs/tokens in URLs)
- `--extended-workflows` mode to detect sensitive endpoints (admin panels, auth, cloud config, `.env`/`.git`, token/session) and verify which are still live
- Optional Burp Suite integration: passive proxy mirroring and active scan triggering via REST API
- Optional webhook notifications per phase

---

## Requirements

**Required:**
```
subfinder, httpx, naabu, nuclei, curl, jq
```

**Optional** (related features are automatically skipped if not present):
```
assetfinder, gau, gowitness, katana, urlfinder
```

### Quick install

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/assetfinder@latest
sudo apt install jq curl -y
```

Make sure `$GOPATH/bin` is in your `$PATH`. This script does **not** automatically install tools or modify your shell profile files — installation must be done manually.

---

## Usage

```bash
chmod +x metsuke.sh
./metsuke.sh -d <domain> [options]
```

When run, you will be asked to type `I HAVE AUTHORIZATION` to confirm authorization before the pipeline continues.

### Basic options

| Option | Description |
|---|---|
| `-d <domain>` | Target domain (required), e.g.: `example.com` |
| `-o <dir>` | Output directory (default: `./recon_<domain>_<timestamp>`) |
| `-t <threads>` | Number of concurrent threads (default: `50`) |
| `--full` | Aggressive mode: full port scan (1–65535) + all nuclei severities |
| `--config <file>` | Load default options from a config file (bash source) |
| `-h` | Show help |

### Performance options

| Option | Description |
|---|---|
| `--sequential` | Run all phases sequentially (default: parallel) |
| `--resume` | Skip phases whose output already exists from a previous run |
| `--skip-cdn` | Skip port scanning for hosts behind a CDN/WAF |
| `--dry-run` | Show the commands that would run without executing them |

### Advanced URL discovery options

| Option | Description |
|---|---|
| `--katana` | Active crawling with `katana` (JS-aware) in addition to the passive `gau` source |
| `--web-archives` | Use `urlfinder` (wayback/CT logs etc.) as an additional source |
| `--extended-workflows` | Detect sensitive endpoints (admin/auth/cloud-config/`.env`/`.git`) and verify which are live |
| `--session-header "H: V"` | Extra header for crawling (e.g. a session cookie), can be repeated for multiple headers |

### Burp Suite integration (optional, default off)

| Option | Description |
|---|---|
| `--burp` | Mirror `httpx` traffic to a Burp proxy (auto-populates the Site Map) |
| `--burp-proxy <host:port>` | Burp proxy address (default: `127.0.0.1:8080`) |
| `--burp-active-scan` | Trigger an **active scan** via the Burp REST API — **INTRUSIVE**, actively attacks endpoints |
| `--burp-api-url <url>` | Burp REST API address (default: `http://127.0.0.1:1337`) |
| `--burp-api-key <key>` | Burp REST API key (or set env `BURP_API_KEY`) |

---

## Examples

```bash
# Basic recon
./metsuke.sh -d example.com

# Full scan + resume, custom output
./metsuke.sh -d example.com -o ./results -t 100 --full --resume

# Advanced URL discovery: active crawl + search for sensitive endpoints
./metsuke.sh -d example.com --katana --extended-workflows

# Crawl with an authenticated session
./metsuke.sh -d example.com --session-header "Cookie: session=abcd" --katana

# Preview without executing
./metsuke.sh -d example.com --full --dry-run

# With Burp Suite (passive mirror)
./metsuke.sh -d example.com --burp --burp-proxy 127.0.0.1:8080

# Active scan trigger (INTRUSIVE — make sure scope allows it)
./metsuke.sh -d example.com --burp-active-scan --burp-api-key abcd1234
```

---

## Output structure

```
recon_<domain>_<timestamp>/
├── scope.txt                     # target domain
├── pipeline.log                  # full execution log
├── subdomains/
│   ├── subfinder.txt / assetfinder.txt / crtsh.txt
│   └── all_subdomains.txt        # merged + deduplicated results
├── httpx/
│   ├── httpx_full.json
│   ├── live_hosts.txt
│   └── cdn_hosts.txt
├── ports/
│   └── open_ports.txt
├── urls/
│   ├── all_urls_raw.txt          # before dedup
│   ├── all_urls.txt              # after normalization + dedup
│   ├── js_files.txt
│   ├── urls_with_params.txt
│   ├── interesting_urls.txt
│   └── extended_sensitive_endpoints.txt   # if --extended-workflows
├── screenshots/
├── vulns/
│   ├── takeover_results.jsonl
│   └── nuclei_results.jsonl
└── report/
    ├── summary.txt
    └── burp_scan_response.json   # if --burp-active-scan
```

---

## Pipeline phases

1. **Subdomain Enumeration** — `subfinder`, `assetfinder`, crt.sh (with retry)
2. **Live Host Probing** — `httpx` (status code, title, tech-detect, CDN detection), optional mirroring to Burp
3. **Port Scanning** — `naabu`, CDN-aware if `--skip-cdn`
4. **URL & Endpoint Discovery** — `gau`/`urlfinder` (passive) + `katana` (active, `--katana`), then URL normalization/dedup; if `--extended-workflows`, scans for sensitive endpoint patterns and verifies live status
5. **Subdomain Takeover Check** — `nuclei` `http/takeovers/` templates
6. **Screenshots** — `gowitness` (optional)
7. **Vulnerability Scanning** — `nuclei` according to the selected severity
8. **Burp Active Scan Trigger** — only if `--burp-active-scan` and `BURP_API_KEY` are provided

---

## Security notes

- Every execution requires manual authorization confirmation — there is no bypass mode.
- `--extended-workflows` still relies on passive GET requests (not exploits), but specifically searches for potentially sensitive information (credentials, cloud configuration, admin panels). Make sure your scope allows this kind of search.
- `--burp-active-scan` is intrusive and will send active payloads to target endpoints — only use it if your authorization scope explicitly allows active scanning.
- Session headers provided via `--session-header` are temporarily stored with `600` permissions in the output directory; delete/protect the output directory according to your organization's sensitive-data policy.
