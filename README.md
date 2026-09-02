# Pipeline Penetration Tester

Advanced web application penetration testing pipeline built in Python. Automates reconnaissance, vulnerability scanning, security header checks, and authentication testing with comprehensive reporting.

## Features

### Reconnaissance
- **Subdomain Enumeration** - DNS-based subdomain discovery
- **Port Scanning** - Common port scanning with multithreading
- **Technology Detection** - Server, framework, and CMS fingerprinting
- **Link Crawling** - Discovers endpoints, forms, and parameters
- **robots.txt / sitemap.xml** - Parses and identifies sensitive paths
- **Directory Bruteforce** - Tests common directory paths

### Vulnerability Scanning
- **SQL Injection** - Error-based and time-based blind SQLi detection
- **Cross-Site Scripting (XSS)** - Reflected XSS via GET and POST
- **OS Command Injection** - Tests for command execution
- **Local File Inclusion (LFI)** - Path traversal and file reading
- **Server-Side Request Forgery (SSRF)** - Internal/external request testing
- **IDOR** - Insecure Direct Object Reference detection
- **XML External Entity (XXE)** - XML entity injection testing

### Security Headers & Misconfiguration
- Missing security headers (CSP, HSTS, X-Frame-Options, etc.)
- Information disclosure via headers
- Cookie security (Secure, HttpOnly, SameSite)
- CORS misconfiguration
- Dangerous HTTP methods
- Directory listing exposure
- `.git` and `.env` file exposure

### Authentication & Session Testing
- Session fixation
- Session timeout/cookie expiry
- Default credentials
- SQL injection auth bypass
- Weak password policy

### Reporting
- **HTML** - Rich interactive report with severity badges
- **JSON** - Machine-readable format
- **TXT** - Plain text summary

## Installation

```bash
git clone <repository>
cd pipeline-penetration
pip install -r requirements.txt
```

## Usage

### Basic Usage
```bash
python main.py -u http://example.com
```

### With Custom Config
```bash
python main.py -u http://example.com -c config/myconfig.yaml
```

### Select Specific Stages
```bash
python main.py -u http://example.com --stages recon,security_headers,report
```

### HTML Report Only
```bash
python main.py -u http://example.com --format html
```

### With Proxy (e.g., Burp Suite)
```bash
python main.py -u http://example.com --proxy http://127.0.0.1:8080
```

### Verbose Mode
```bash
python main.py -u http://example.com -v
```

### All Options
```bash
python main.py -h
```

## Configuration

Edit `config/config.yaml` to customize:

- Target URL and scope
- Pipeline stages
- Scan modules (enable/disable)
- Network settings (timeout, delay, retries)
- Proxy settings
- Report format
- Logging level

## Project Structure

```
pipeline-penetration/
├── config/
│   └── config.yaml          # Main configuration
├── src/
│   ├── core/
│   │   ├── config.py        # Configuration loader
│   │   ├── logger.py        # Colored logging system
│   │   ├── http_client.py   # HTTP client with retry/rate-limit
│   │   ├── models.py        # Finding & ScanResult data models
│   │   ├── pipeline.py      # Pipeline orchestrator
│   │   └── report.py        # HTML/JSON/TXT report generator
│   ├── modules/
│   │   ├── recon.py         # Reconnaissance module
│   │   ├── vuln_scanner.py  # Vulnerability scanner
│   │   ├── security_headers.py # Security headers checker
│   │   └── auth_testing.py  # Authentication tester
│   └── utils/
│       ├── payloads.py      # Injection payload database
│       └── url_parser.py    # URL parsing utilities
├── wordlists/
│   ├── directories.txt      # Directory bruteforce wordlist
│   └── default_creds.txt    # Default credentials list
├── tests/
│   └── test_pipeline.py     # Unit tests
├── output/                  # Generated reports & logs
├── main.py                  # CLI entry point
├── requirements.txt         # Python dependencies
└── README.md
```

## Testing

```bash
python -m pytest tests/ -v
```

## Disclaimer

This tool is for **authorized security testing only**. Only use it against systems you own or have explicit written permission to test. Unauthorized use is illegal and unethical.

## License

MIT
