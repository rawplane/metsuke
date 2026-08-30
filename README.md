# Bug Bounty Recon & Non‑Destructive Scanning Pipeline

This Bash script automates the reconnaissance and non‑destructive vulnerability scanning stages of a bug bounty or authorized penetration testing engagement. It is designed to be **safe**, **polite**, and **modular**, with built‑in scope validation and rate limiting.

> **Disclaimer:** Use this tool only on targets for which you have explicit written permission (e.g., an official bug bounty program or a signed pentest contract). Unauthorized scanning is illegal and unethical. The author assumes no liability for misuse.

---

## Features

- **Subdomain enumeration** using passive sources (subfinder, assetfinder, crt.sh) with DNS resolution.
- **HTTP probing & fingerprinting** with httpx (status, title, technologies).
- **Port scanning** (top 1000 ports) with naabu (or nmap fallback).
- **Content discovery** via katana crawling and ffuf fuzzing (with strict rate limits).
- **Vulnerability scanning** using nuclei with CVE/misconfig templates (non‑destructive, excludes DoS and brute‑force).
- **Deduplication and prioritization** based on nuclei severity.
- **Structured output** (JSON/Markdown) ready for manual review and report submission.
- **Modular design** – run the full pipeline or individual stages.

---

## Prerequisites

All required tools must be installed and available in your `PATH`. The script checks for some tools and falls back to alternatives where possible.

### Required tools

| Tool        | Purpose                              | Installation (Linux / macOS)                          |
|-------------|--------------------------------------|-------------------------------------------------------|
| `subfinder` | Passive subdomain enumeration        | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| `assetfinder`| Subdomain discovery from multiple sources | `go install github.com/tomnomnom/assetfinder@latest` |
| `dnsx`      | Fast DNS resolution                  | `go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| `httpx`     | HTTP probing & fingerprinting        | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| `naabu`     | Fast port scanning                   | `go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` |
| `katana`    | Modern web crawler                   | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| `ffuf`      | Directory & parameter fuzzing        | `go install github.com/ffuf/ffuf/v2@latest`          |
| `nuclei`    | Vulnerability scanner (template‑based)| `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| `jq`        | JSON processing                      | `sudo apt install jq` (Debian/Ubuntu) or `brew install jq` (macOS) |
| `nmap`      | Optional fallback port scanner       | `sudo apt install nmap`                              |

> **Note:** Ensure `$HOME/go/bin` is in your `PATH`.

---

## Setup

1. Clone or download this repository.
2. Make the script executable:
   ```bash
   chmod +x bug_hunter_pipeline.sh