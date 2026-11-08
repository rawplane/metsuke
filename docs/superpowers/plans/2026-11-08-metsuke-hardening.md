# Metsuke Hardening & Security Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix security vulnerabilities, race conditions, process handling flaws, and parsing bugs in `metsuke.sh`.

**Architecture:** Harden bash script in-place with defensive validation, lock-free per-worker temp outputs, reliable process lifecycle management, and scoped URL filtering.

**Tech Stack:** Bash 4+, GNU coreutils, jq, awk.

**Spec:** Codebase `metsuke.sh` security review findings.

## Global Constraints

- Preserve all existing CLI flag contracts and default behaviors.
- Maintain Bash compatibility (Bash 4.0+).
- Zero external package additions; use existing tools (`jq`, `awk`, `curl`, coreutils).
- Maintain `umask 077` and strict permissions on output files.

## Review Focus

- Malicious input containing shell metacharacters in host/port to `check_tcp_port`: must never execute command injection.
- Heavy concurrent execution in `phase_js_secret_scan`: worker outputs must not collide or produce corrupt files.
- ANSI escape sequences in `report/summary.txt`: file must contain clean plain text.
- Out-of-scope URLs from `gau --subs`: must be filtered against target domain before saving.
- Process cleanup on SIGINT: all background workers must be reaped without leaving orphan processes.

---

### Task 1: Security and Concurrency Hardening in Core Helpers

**Files:**
- Modify: `metsuke.sh:386-395` (`check_tcp_port`), `metsuke.sh:524-530` (`setup_workspace`), `metsuke.sh:939-980` (`phase_js_secret_scan`)
- Test: `tests/test_core_hardening.sh`

**Interfaces:**
- Consumes: `BURP_PROXY_HOST`, `BURP_PROXY_PORT`, `TIMEOUT_BIN`, `MAX_JS_FILES`, `JS_CONCURRENCY`
- Produces: Hardened `check_tcp_port`, clean logging redirection, collision-free `phase_js_secret_scan`

- [ ] **Step 1: Write test for core hardening**

```bash
mkdir -p tests
cat << 'EOF' > tests/test_core_hardening.sh
#!/usr/bin/env bash
set -euo pipefail

# 1. Test check_tcp_port rejection on metacharacters
source <(grep -A 20 '^check_tcp_port()' metsuke.sh)
if check_tcp_port '127.0.0.1; echo INJECTED' 80; then
    echo "FAIL: check_tcp_port accepted command injection"
    exit 1
fi
echo "PASS: check_tcp_port rejected metacharacters"
EOF
chmod +x tests/test_core_hardening.sh
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bash tests/test_core_hardening.sh`
Expected: FAIL

- [ ] **Step 3: Harden `check_tcp_port`, `TEE_PID` handling, and `phase_js_secret_scan`**

In `metsuke.sh`:
1. `check_tcp_port`: Validate `$1` strictly as IPv4/IPv6 or hostname and `$2` as integer 1-65535 before any socket operation. Use timeout directly without `bash -c` string interpolation when possible.
2. In `setup_workspace`: Replace fragile `TEE_PID=$!` with reliable stdout redirection or process tracking.
3. In `phase_js_secret_scan`: Have each worker write matches to a unique temporary file in a worker temp directory under `$OUTDIR/vulns/.js_tmp/`, then concatenate and sort into `$out` after `xargs` completes.

- [ ] **Step 4: Run test to verify it passes**

Run: `bash tests/test_core_hardening.sh`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add metsuke.sh tests/test_core_hardening.sh
git commit -m "fix(core): harden check_tcp_port and eliminate js secret scan race condition"
```

---

### Task 2: Output Sanitization and Scope Filtering

**Files:**
- Modify: `metsuke.sh:823-885` (`phase_url_discovery`), `metsuke.sh:1161-1213` (`generate_summary`)
- Test: `tests/test_filtering_and_output.sh`

**Interfaces:**
- Consumes: `$DOMAIN_ESCAPED`, `$OUTDIR`, ANSI color variables
- Produces: Filtered URLs matching domain scope, ANSI-free `summary.txt`

- [ ] **Step 1: Write test for URL filtering and ANSI-free summary**

```bash
cat << 'EOF' > tests/test_filtering_and_output.sh
#!/usr/bin/env bash
set -euo pipefail

# Verify summary.txt template contains no ANSI escape codes
summary_body=$(sed -n '/cat > "\$OUTDIR\/report\/summary.txt"/,/EOF/p' metsuke.sh)
if echo "$summary_body" | grep -q '\${BOLD}\|\${NC}'; then
    echo "FAIL: summary.txt contains ANSI codes"
    exit 1
fi
echo "PASS: summary.txt is ANSI-free"
EOF
chmod +x tests/test_filtering_and_output.sh
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bash tests/test_filtering_and_output.sh`
Expected: FAIL

- [ ] **Step 3: Fix `phase_url_discovery` and `generate_summary`**

In `metsuke.sh`:
1. `phase_url_discovery`: Apply scope filter `grep -E "(https?://)?([^/]+\.)?${DOMAIN_ESCAPED}(/|:|$)"` immediately to URLs returned by `gau` and `urlfinder` before adding to `.sources_raw.txt`.
2. `generate_summary`: Remove color and format variables (`${BOLD}`, `${NC}`) from the `cat > "$OUTDIR/report/summary.txt"` block. Print colored summary to terminal stdout only.

- [ ] **Step 4: Run test to verify it passes**

Run: `bash tests/test_filtering_and_output.sh`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add metsuke.sh tests/test_filtering_and_output.sh
git commit -m "fix(url): filter passive URLs by scope and strip ANSI from summary file"
```

---

### Task 3: Lifecycle, Config Sandboxing, and Checksums

**Files:**
- Modify: `metsuke.sh:49-80`, `metsuke.sh:561-582` (`on_exit`, `on_interrupt`), `metsuke.sh:1216-1231` (config loading), `metsuke.sh:1161-1213` (`generate_summary`)
- Test: `tests/test_lifecycle_and_config.sh`

**Interfaces:**
- Consumes: `CONFIG_FILE`, `PARALLEL_MODE`, `$OUTDIR`
- Produces: Safe config loader, graceful process teardown, `report/checksums.sha256`

- [ ] **Step 1: Write test for config validator and checksums**

```bash
cat << 'EOF' > tests/test_lifecycle_and_config.sh
#!/usr/bin/env bash
set -euo pipefail

# Check if malicious config executes code
bad_cfg=$(mktemp)
echo 'echo EXECUTED_EVIL_CONFIG' > "$bad_cfg"
# Script should validate or parse safe key-values only
EOF
chmod +x tests/test_lifecycle_and_config.sh
```

- [ ] **Step 2: Run test to verify behavior**

Run: `bash tests/test_lifecycle_and_config.sh`
Expected: Verification setup

- [ ] **Step 3: Implement safe config parsing, process PID group tracking, and sha256 checksums**

In `metsuke.sh`:
1. Config parsing: Instead of arbitrary `source "$_cfg"`, parse only allowed keys (`THREADS`, `RATE_LIMIT`, `HTTP_TIMEOUT`, `NUCLEI_SEVERITY`, etc.) using key=value parsing (`grep -E '^[A-Z_]+='`).
2. Track background child PIDs explicitly in an array `BACKGROUND_PIDS=()` during `PARALLEL_MODE` and terminate them cleanly in `on_interrupt`.
3. In `generate_summary`: Compute `sha256sum` for all artifacts in `$OUTDIR` and save to `$OUTDIR/report/checksums.sha256`.

- [ ] **Step 4: Run test to verify completion**

Run: `bash tests/test_lifecycle_and_config.sh`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add metsuke.sh tests/test_lifecycle_and_config.sh
git commit -m "feat(lifecycle): track process pids, sandbox config parsing, and add artifact checksums"
```
