# 目付 metsuke

**Modular recon pipeline with authorization discipline & auditing**

The name comes from an Edo-era inspector title (*metsuke*, 目付) — an officially
mandated role, with a clear mandate, to observe and report before acting. This
script follows the same philosophy: **authorize first, then act.**

> **Version:** 4.0.0

---

## ⚠️ Legal Warning

This script may **ONLY** be run against targets for which you already have
**explicit permission** — a bug bounty scope, a signed pentest contract, or
your own assets. Scanning without authorization is illegal in most
jurisdictions.

- `--burp-active-scan` is **INTRUSIVE** (it attacks endpoints). Make sure your
  authorization scope explicitly allows active scanning, not just passive
  recon.
- `--extended-workflows` searches for endpoints that could potentially leak
  credentials or configuration (`.env`, `.git`, admin panels, cloud config,
  token/session endpoints), and fetches JS files to look for hardcoded
  secrets. These remain passive `GET` requests (not exploits), but make sure
  your scope allows this kind of sensitive information search.

Every non-dry-run execution requires you to type an explicit confirmation
phrase before any request is sent to the target.

---

## Features

- **Modular pipeline** — subdomain enumeration → live host probing → port
  scanning → URL/endpoint discovery → JS secret scanning → takeover checks →
  screenshots → vulnerability scanning → optional Burp active scan.
- **Authorization gate** — an interactive confirmation prompt before any
  network activity (skipped only in `--dry-run`).
- **Full audit trail** — every run writes a timestamped `audit.log` (with
  secrets redacted from the recorded arguments) alongside the full pipeline
  log.
- **Scope enforcement** — subdomains are matched with an anchored regex
  against the target domain (not a naive substring match), with optional
  `--exclude-sub` regex filters applied before any request is sent.
- **Passive-only mode** — a zero-contact OSINT mode that only queries
  third-party sources (subfinder, crt.sh, gau) and never touches the target
  directly.
- **Resumable** — `--resume` skips phases whose output already exists.
- **Config file support** — load defaults from a file (CLI flags always
  win).
- **Rate limiting & timeouts** — tunable per-request timeout and
  requests/second cap.
- **Secure secret handling** — session headers and API keys can be supplied
  via files (chmod 600) instead of the command line, where they'd be visible
  in `ps`.
- **Optional Burp Suite integration** — passive traffic mirroring to
  populate the Site Map, and optional active scan triggering via the Burp
  REST API.
- **Single-instance locking** — prevents two runs from clobbering the same
  output directory.
- **Structured output & summary** — per-phase artifacts plus a final
  `summary.txt` / `summary.json` report.

---

## Requirements

### Required dependencies
- [`subfinder`](https://github.com/projectdiscovery/subfinder)
- [`httpx`](https://github.com/projectdiscovery/httpx)
- [`naabu`](https://github.com/projectdiscovery/naabu)
- [`nuclei`](https://github.com/projectdiscovery/nuclei)
- `curl`
- `jq`
- `awk` (GNU `gawk` preferred)

> In `--passive-only` mode, `httpx`, `naabu`, and `nuclei` are not required.

### Optional dependencies
- [`assetfinder`](https://github.com/tomnomnom/assetfinder)
- [`gau`](https://github.com/lc/gau)
- [`gowitness`](https://github.com/sensepost/gowitness)
- [`katana`](https://github.com/projectdiscovery/katana)
- [`urlfinder`](https://github.com/projectdiscovery/urlfinder)
- `perl` (used to sanitize katana output; falls back to `tr`)
- GNU coreutils `timeout(1)` (enables per-phase timeouts; degrades
  gracefully if absent)

### Optional integration
- Burp Suite Pro/Community running locally, for passive proxy mirroring
  and/or active scan triggering via the REST API (Burp Pro only).

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
sudo apt install jq curl gawk -y
```

Make sure `$GOPATH/bin` is in your `$PATH`. The script will **not**
automatically install tools or modify your shell profile — install
everything manually first.

---

## Installation

```bash
chmod +x metsuke.sh
./metsuke.sh -h
```

---

## Usage

```bash
./metsuke.sh -d <domain> [options]
```

### Basic options

| Flag | Description |
|---|---|
| `-d <domain>` | Target domain (required), e.g. `example.com` |
| `-o <dir>` | Output directory (default: `./recon_<domain>_<timestamp>`) |
| `-t <threads>` | Concurrent threads (default: 50) |
| `--full` | Aggressive mode: full port scan (1-65535) + all nuclei severities |
| `--config <file>` | Load default options from a config file (sourced before CLI parsing, so CLI flags always win) |
| `--timeout <sec>` | Per-request HTTP timeout (default: 10, range 3-300) |
| `--rate-limit <rps>` | Requests/second cap for httpx/naabu/nuclei (default: off) |
| `-V`, `--version` | Print version and exit |
| `-h` | Show help |

### Scope & safety options

| Flag | Description |
|---|---|
| `--exclude-sub <regex>` | ERE matched per line; matching subdomains are pruned **before** any request is sent (repeatable) |
| `--passive-only` | Zero-contact mode: only third-party OSINT sources (subfinder / crt.sh / gau); no direct requests to the target |
| `--no-interactsh` | Disable nuclei out-of-band (interact.sh) callbacks |
| `--no-notify` | Disable webhook notifications for this run |
| `--resume` | Skip phases whose output already exists from a previous run |
| `--dry-run` | Show the commands that would run, without executing them |
| `--skip-cdn` | Skip port scanning for hosts detected behind a CDN/WAF |

### Performance options

| Flag | Description |
|---|---|
| `--sequential` | Run all phases sequentially (default, safest) |
| `--parallel` | Run port scan & URL discovery concurrently (higher combined request rate) |

### Advanced URL discovery options

| Flag | Description |
|---|---|
| `--katana` | Active, JS-aware crawling with katana, in addition to gau |
| `--web-archives` | Use urlfinder (Wayback/CT/etc.) in addition to gau |
| `--extended-workflows` | Sensitive endpoint detection (admin/auth/cloud/.env/.git) + JS hardcoded-secret scanning (passive GETs only) |
| `--session-header "H: V"` | Extra header for crawling (e.g. `Cookie`), repeatable. **Visible in `ps`** — prefer `--session-header-file` |
| `--session-header-file <f>` | File with one `Header: value` per line (chmod 600) |

### Nuclei options

| Flag | Description |
|---|---|
| `--nuclei-severity <list>` | Comma list (default: `low,medium,high,critical`) |
| `--nuclei-tags <tags>` | Restrict nuclei to specific tags (default: all) |
| `--update-templates` | Run `nuclei -update-templates` before scanning |

### Burp Suite integration (optional, default OFF)

| Flag | Description |
|---|---|
| `--burp` | Mirror httpx traffic to the Burp proxy (populates Site Map) |
| `--burp-proxy <host:port>` | Burp proxy address (default: `127.0.0.1:8080`) |
| `--burp-active-scan` | Trigger an **active scan** via the Burp REST API (**INTRUSIVE**) |
| `--burp-api-url <url>` | Burp REST API address (default: `http://127.0.0.1:1337`) |
| `--burp-api-key <key>` | Burp REST API key. **Visible in `ps`** — prefer the `BURP_API_KEY` env var or a chmod-600 config file |

### Environment variables

| Variable | Description |
|---|---|
| `RECON_WEBHOOK_URL` | Webhook URL for phase-completion notifications |
| `BURP_API_KEY` | Burp REST API key (preferred over `--burp-api-key`) |

---

## Examples

```bash
# Basic run
./metsuke.sh -d example.com

# Custom output dir, more threads, full aggressive scan, resumable
./metsuke.sh -d example.com -o ./results -t 100 --full --resume

# Zero-contact OSINT only
./metsuke.sh -d example.com --passive-only

# Exclude known out-of-scope subdomains, active JS-aware crawl
./metsuke.sh -d example.com --exclude-sub '^(dev|internal|vpn)\.' --katana

# Authenticated crawling with headers kept out of the command line
./metsuke.sh -d example.com --session-header-file ./cookies.txt --katana

# Sensitive endpoint / secret hunting, no OOB callbacks
./metsuke.sh -d example.com --extended-workflows --no-interactsh

# Mirror traffic into Burp's Site Map
./metsuke.sh -d example.com --burp --burp-proxy 127.0.0.1:8080

# Trigger a Burp active scan (intrusive — scope must explicitly allow this)
./metsuke.sh -d example.com --burp-active-scan --burp-api-key abcd1234
```

---

## Pipeline phases

1. **Subdomain Enumeration** — subfinder, assetfinder, and crt.sh, merged,
   lowercased, and filtered to an anchored in-scope regex; `--exclude-sub`
   patterns are applied last.
2. **Live Host Probing (httpx)** — status codes, titles, tech stack, CDN
   detection; optionally mirrored to a Burp proxy.
3. **Port Scanning (naabu)** — top-1000 ports by default, or full
   1–65535 with `--full`; can skip CDN-fronted hosts with `--skip-cdn`.
4. **URL & Endpoint Discovery** — gau / urlfinder (passive) and optional
   katana (active, JS-aware) crawling, followed by path templating and
   parameter-signature deduplication. With `--extended-workflows`, sensitive
   endpoint candidates are additionally verified live via passive `GET`
   requests.
5. **JS Hardcoded-Secret Detection** (`--extended-workflows` only) —
   downloads discovered JS files and greps for common credential/token
   patterns (AWS keys, GitHub tokens, Slack webhooks, JWTs, private key
   headers, etc.). Findings are **candidates only** and must be verified
   manually.
6. **Subdomain Takeover Check** — nuclei's takeover templates against all
   in-scope subdomains.
7. **Screenshots** (optional) — via `gowitness`, if installed.
8. **Vulnerability Scanning (nuclei)** — configurable severity and tags.
9. **Burp Suite Active Scan** (optional, `--burp-active-scan`) — submits
   live hosts to the Burp REST API to trigger an active scan.

A final **Summary** phase writes `report/summary.txt` and
`report/summary.json` with counts for every phase.

---

## Output layout

```
recon_<domain>_<timestamp>/
├── scope.txt                  # target domain
├── pipeline.log                # full run log
├── audit.log                   # timestamped, redacted audit trail
├── subdomains/
│   └── all_subdomains.txt
├── httpx/
│   ├── httpx_full.json
│   ├── live_hosts.txt
│   └── cdn_hosts.txt
├── ports/
│   └── open_ports.txt
├── urls/
│   ├── all_urls.txt
│   ├── js_files.txt
│   ├── interesting_urls.txt
│   └── extended_sensitive_endpoints.txt   # (--extended-workflows)
├── vulns/
│   ├── js_secrets.txt                     # (--extended-workflows)
│   ├── takeover_results.jsonl
│   └── nuclei_results.jsonl
├── screenshots/
└── report/
    ├── summary.txt
    ├── summary.json
    └── burp_scan_response.json            # (--burp-active-scan)
```

The output directory is created with `umask 077`, so results — including any
session headers or findings — stay private to the invoking user.

---

## Safety mechanisms

- **Interactive authorization gate** — requires typing
  `I HAVE AUTHORIZATION` before any request is sent (skipped only in
  `--dry-run`).
- **Redacted audit log** — `--session-header` and `--burp-api-key` values
  are stripped from the recorded command line.
- **Anchored scope matching** — subdomains are matched with `(^|\.)domain$`,
  not a substring, to avoid accidentally including out-of-scope look-alike
  hosts.
- **Config/secret file permission checks** — warns if a session header file
  isn't `chmod 600`/`400`.
- **Single-instance lock** — a stale or active lock in the output directory
  prevents concurrent runs from colliding.
- **Graceful interrupt handling** — `Ctrl-C` stops child processes, logs the
  interruption, and cleans up the lock.

---

## Notes

- The script does **not** install any tools or modify your shell profile —
  install dependencies manually first.
- `--extended-workflows` and the JS secret scanner only ever issue passive
  `GET` requests, but they specifically hunt for endpoints and material that
  can disclose credentials — treat findings as sensitive and make sure your
  scope explicitly covers this kind of search.
- `--burp-active-scan` is the only phase in this pipeline that actively
  attacks endpoints. It is off by default and requires an explicit API key.
