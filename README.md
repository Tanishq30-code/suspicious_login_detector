# Suspicious Login Detector (v2.0)

A dependency-free bash/awk tool that correlates failed logins across multiple application types (SSH, web app, database, API gateway), flags brute-force patterns, generates firewall block commands, walks flagged IPs through a recovery workflow, and proves its own accuracy with a bundled benchmark suite.

> Linux & Shell Programming (CSET-213) — Bennett University

## What's new in v2.0

- **🎯 Benchmark / proof mode** — `-b` re-runs the detector against three bundled, ground-truth-tagged scenarios and prints a detected-vs-expected PASS/FAIL table.
- **🧩 Multi-application log sources** — parses four log formats (SSH, web app, database, API gateway) and correlates the *same* attacking IP across all of them.
- **🚫 Block that IP** — `-B` generates ready-to-review `iptables`/`ufw` block commands for every flagged IP and records them in a persistent blocklist.
- **♻️ Recovery actions** — every flagged IP gets a recovery checklist, and `-r` reviews the blocklist after a cooldown and generates matching unblock commands.

## Project structure

```
suspicious-login-detector/
├── suspicious_login_detector.sh   # main script
├── sample_logs/
│   ├── ssh_auth.log               # SSH/syslog demo data
│   ├── web_auth.log               # web app login demo data
│   ├── db_auth.log                # database auth demo data
│   ├── api_auth.log               # API gateway demo data
│   ├── clean_traffic.log          # benign-only, zero false positives
│   └── *.expected / expected_combined.txt   # benchmark ground truth
├── reports/                       # generated .txt / .csv / benchmark / block / unblock output
├── blocklist.tsv                  # persistent block state (created on first -B run)
└── guide.html                     # full usage guide
```

## Requirements

- Any Linux distribution with `bash`
- `gawk` (GNU awk) — used for `mktime()` / `strftime()` / `match()`
- Standard coreutils: `date`, `mkdir`, `mktemp`
- *Optional:* `mailx`/`sendmail` for email alerts, `iptables`/`ufw` to actually apply generated blocks

> **Note:** Block commands are never auto-executed. `-B` only writes a reviewable `block_commands_*.sh` script and a blocklist entry. The actual `iptables`/`ufw` command only runs if you also pass `-x` **and** the script is running as root — always review the generated script first.

## Setup / Steps to run the demo

1. **Open a terminal in the project folder**
   ```bash
   cd ~/Downloads/personal/suspicious-login-detector
   ```

2. **Make the script executable (first time only)**
   ```bash
   chmod +x suspicious_login_detector.sh
   ```

3. **Run it with zero flags — loads the four bundled application sources**
   ```bash
   ./suspicious_login_detector.sh
   ```
   With no `-a`/`-f` given, it automatically loads all four demo sources (`ssh`, `web`, `db`, `api`) and correlates them by IP.

4. **Read the summary**
   Example output: the same attacker IP hitting SSH, web, and API gets escalated to **CRITICAL**; an IP hitting only one service (e.g. brute-forcing the DB) is flagged **HIGH** on volume alone. Each flagged IP gets a Recovery Actions checklist (block, force logout, password reset, review prior successful logins, re-review after cooldown).

5. **Generate block commands for flagged IPs**
   ```bash
   ./suspicious_login_detector.sh -B
   ```
   Writes `reports/block_commands_<timestamp>.sh` and adds each IP to `blocklist.tsv` with status `active`. Review the script, then run it yourself when ready.

6. **Later: review the blocklist and unblock anything past cooldown**
   ```bash
   ./suspicious_login_detector.sh -r -c 24
   ```
   Anything blocked more than 24h ago gets an unblock command in `reports/unblock_commands_<timestamp>.sh` and flips to `recovered`; anything still cooling down stays `active`.

7. **Prove it works: run the benchmark suite**
   ```bash
   ./suspicious_login_detector.sh -b
   ```
   Runs three controlled scenarios (combined multi-app, SSH-only, clean-traffic-only) against bundled ground truth and writes `reports/benchmark_<timestamp>.txt` with PASS/FAIL + timing per scenario.

## Command-line options

| Flag | Meaning | Default |
|---|---|---|
| `-a TYPE:FILE` | Add a log source; `TYPE` is `ssh`, `web`, `db`, or `api`. Repeatable. | bundled 4-source demo set |
| `-f FILE` | Shorthand for `-a ssh:FILE` (v1.0 back-compat) | — |
| `-t N` | Flag an IP once it exceeds N attempts in the window | `5` |
| `-w N` | Sliding window size, in minutes | `10` |
| `-o DIR` | Output directory for reports | `./reports` |
| `-m EMAIL` | Email the report if any IP was flagged (needs `mailx`/`sendmail`) | off |
| `-B` | Generate firewall block commands + blocklist entry for every flagged IP | off |
| `-x` | Actually execute the generated block commands (needs `-B` + root) | off |
| `-L FILE` | Blocklist state file | `./blocklist.tsv` |
| `-r` | Recovery mode: review blocklist cooldowns, generate unblocks, exit | off |
| `-c N` | Recovery cooldown, in hours, before an IP is unblock-eligible | `24` |
| `-b` | Benchmark mode: run bundled scenarios, print proof report, exit | off |
| `-q` | Quiet mode — write report files but print nothing to console | off |
| `-h` | Show help text | — |

### More examples

```bash
# Point at real logs from three different applications at once
./suspicious_login_detector.sh -a ssh:/var/log/auth.log -a web:/var/log/app/login.log -a db:/var/log/mysql/error.log

# Stricter: flag after 3 attempts within a 5-minute window
./suspicious_login_detector.sh -t 3 -w 5

# Detect AND generate block commands, quiet for cron, only e-mail when flagged
./suspicious_login_detector.sh -B -q -m you@example.com

# Detect, actually apply the blocks (root), review the script that was run first
sudo ./suspicious_login_detector.sh -B -x

# Weekly cron: review the blocklist and lift anything past a 48h cooldown
./suspicious_login_detector.sh -r -c 48
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Ran successfully — nothing flagged, or all benchmark scenarios passed |
| 1 | Usage or input error (bad flag, missing/unreadable log file) |
| 2 | Ran successfully — one or more IPs were flagged, or a benchmark scenario failed |

## How detection works

Each source is parsed by a small dedicated matcher and normalized to a common `epoch|ip|user|app` event:

| Type | Matches on |
|---|---|
| `ssh` | `Failed password` / PAM `authentication failure` |
| `web` | `LOGIN_FAILED` with `ip=`/`user=` tokens |
| `db` | `Access denied for user '…'@'…'` |
| `api` | JSON lines with `"event":"auth_failure"` |

For each distinct IP across all sources, failed-attempt timestamps are sorted and the script slides a window across them: if any `(threshold + 1)` consecutive attempts fall within `window` seconds, the IP is flagged. This tells a genuine burst apart from the same attempt count spread over hours.

**Severity:** `MEDIUM` at baseline → `HIGH` if attempts reach 2× the threshold *or* 2+ applications are hit → `CRITICAL` if 3+ distinct applications are hit.

## Response workflow: block → recover

1. **Detect** — a normal run (optionally `-B`) identifies and reports flagged IPs; every flagged IP gets a Recovery Actions checklist regardless of `-B`.
2. **Block (opt-in, reviewable)** — `-B` writes `block_commands_*.sh` and a `blocklist.tsv` row. Nothing touches the firewall unless you also pass `-x` as root.
3. **Recover** — run `-r` periodically (e.g. daily via cron). Entries past the `-c` cooldown get an `unblock_commands_*.sh` script and flip to `recovered`.

## Automating with cron

```cron
# Every 15 minutes: detect + generate block commands, email only when flagged
*/15 * * * * /home/<you>/Downloads/personal/suspicious-login-detector/suspicious_login_detector.sh \
  -B -q -m you@example.com \
  -o /home/<you>/Downloads/personal/suspicious-login-detector/reports

# Once a day: review the blocklist and lift anything past a 24h cooldown
0 3 * * * /home/<you>/Downloads/personal/suspicious-login-detector/suspicious_login_detector.sh -r -c 24 -q
```

> Reading real system logs and applying `-x` block commands usually requires root. When scheduling via root's crontab, use absolute paths exactly as shown, since cron jobs run with a minimal environment.

## Known limitations & extension ideas

- **IPv4 only** — IPv6 source addresses are skipped by the validation regex.
- **Timestamps assumed UTC** — ISO-8601 timezone offsets are currently ignored during parsing.
- **Four built-in application parsers** — adding a fifth log format means adding one more matcher block to `normalize.awk`; the rest of the pipeline is format-agnostic.
- **Blocking is IP-only** — it does not identify or lock targeted user accounts; that's left as a manual step in the Recovery Actions checklist.
- **Alerting** — currently email only; CSV output is intentionally machine-parsable for future Slack/webhook alerting.

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `Permission denied` running the script | Run `chmod +x suspicious_login_detector.sh` once. |
| `cannot read log file` | The path in `-a TYPE:FILE`/`-f` is wrong, or you need `sudo` to read system logs. |
| `unknown source type` | `TYPE` in `-a TYPE:FILE` must be exactly `ssh`, `web`, `db`, or `api`. |
| `-x requires -B` | Pass both together: `-B -x`. `-x` alone has nothing to execute. |
| Block commands weren't actually applied | By design — without `-x` (and root), `-B` only writes the reviewable script. |
| `this script requires GNU awk` | Install gawk: `sudo apt install gawk` (Debian/Ubuntu) or `sudo yum install gawk` (RHEL/CentOS). |
| Everything shows as unflagged unexpectedly | Lower `-t` or widen `-w` — the rule is *more than* N attempts, so `-t 5` needs 6+ attempts. |

---
*Suspicious Login Detector v2.0 — Bennett University, School of Computer Science Engineering & Technology. Linux & Shell Programming (CSET-213), Academic Year 2025-26.*
