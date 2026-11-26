#!/usr/bin/env bash
#
# suspicious_login_detector.sh
# ---------------------------------------------------------------------------
# Bennett University - School of Computer Science Engineering & Technology
# Linux & Shell Programming (CSET-213) - Course Project
# "Suspicious Login Detector" - v2.0
#
# Parses authentication logs from MULTIPLE application types (SSH, web app,
# database, API gateway), normalizes them to a common event format, groups
# failed login attempts by source IP across all applications, flags IPs that
# exceed a configurable attempt threshold within a sliding time window, and
# writes a text + CSV report. Flagged IPs additionally get:
#   - generated firewall block commands (-B)
#   - a per-IP recovery action checklist (always included in the report)
#   - a recovery/unblock workflow after a cooldown period (-r)
# A benchmark mode (-b) re-runs the tool against bundled, ground-truth-tagged
# sample scenarios and reports detected-vs-expected results as proof of
# detection accuracy.
#
# Requires only: bash, gawk (GNU awk), coreutils (date, mkdir, mktemp). No
# external packages, no SIEM, no third-party dependencies.
# ---------------------------------------------------------------------------

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VERSION="2.0"

# ---- Defaults ----------------------------------------------------------
declare -a SOURCES=()      # each entry: "type:path"
THRESHOLD=5                # flag an IP once it has MORE THAN this many attempts in the window
WINDOW_MIN=10              # sliding window size, in minutes
OUT_DIR="./reports"
MAIL_TO=""
QUIET=0
DO_BLOCK=0
DO_EXECUTE=0
BLOCKLIST_FILE="./blocklist.tsv"
COOLDOWN_HOURS=24
MODE="detect"              # detect | recover | benchmark

usage() {
  cat <<EOF
Suspicious Login Detector v${VERSION}
Parses authentication logs from multiple application types and flags source
IPs showing brute-force-like failed login patterns (more than N failed
attempts within a sliding window), correlated across applications.

Usage: ${SCRIPT_NAME} [options]

Log sources (repeatable; default: bundled 4-application demo set):
  -a TYPE:FILE   Add a log source. TYPE is one of: ssh, web, db, api
  -f FILE        Shorthand for -a ssh:FILE (back-compat with v1.0)

Detection options:
  -t N        Threshold: flag IPs with MORE THAN N failed attempts in the window (default: ${THRESHOLD})
  -w N        Sliding time window, in minutes (default: ${WINDOW_MIN})
  -o DIR      Output directory for reports (default: ${OUT_DIR})
  -m EMAIL    Email the summary report to EMAIL (via mailx/sendmail) if any IP is flagged
  -q          Quiet mode: do not print the summary to the console (files are still written)

Response actions:
  -B          Generate firewall block commands for every flagged IP (dry-run script + blocklist entry)
  -x          Actually execute the generated block commands (requires -B, root, and iptables/ufw)
  -L FILE     Blocklist state file (default: ${BLOCKLIST_FILE})
  -r          Recovery mode: review the blocklist and unblock IPs past the cooldown, then exit
  -c N        Recovery cooldown, in hours, before an IP is eligible to be unblocked (default: ${COOLDOWN_HOURS})

Benchmarking:
  -b          Benchmark mode: run bundled ground-truth scenarios and print a detection-accuracy
              proof report (detected vs. expected per scenario), then exit

  -h          Show this help and exit

Examples:
  ${SCRIPT_NAME}                                    # zero-flag demo: all 4 bundled application sources
  ${SCRIPT_NAME} -a ssh:/var/log/auth.log -a web:/var/log/app/login.log
  ${SCRIPT_NAME} -f /var/log/auth.log -t 5 -w 10 -o reports
  ${SCRIPT_NAME} -B -x                              # detect AND actively block flagged IPs (root)
  ${SCRIPT_NAME} -r -c 24                            # review blocklist, unblock anything past cooldown
  ${SCRIPT_NAME} -b                                  # run the benchmark / proof suite

Exit codes:
  0  ran successfully, nothing flagged / all benchmark scenarios passed
  1  usage / input error
  2  ran successfully, one or more IPs were flagged / a benchmark scenario failed (useful in cron/alerting)
EOF
}

while getopts ":a:f:t:w:o:m:qBxL:rc:bh" opt; do
  case "$opt" in
    a) SOURCES+=("$OPTARG") ;;
    f) SOURCES+=("ssh:${OPTARG}") ;;
    t) THRESHOLD="$OPTARG" ;;
    w) WINDOW_MIN="$OPTARG" ;;
    o) OUT_DIR="$OPTARG" ;;
    m) MAIL_TO="$OPTARG" ;;
    q) QUIET=1 ;;
    B) DO_BLOCK=1 ;;
    x) DO_EXECUTE=1 ;;
    L) BLOCKLIST_FILE="$OPTARG" ;;
    r) MODE="recover" ;;
    c) COOLDOWN_HOURS="$OPTARG" ;;
    b) MODE="benchmark" ;;
    h) usage; exit 0 ;;
    \?) echo "Error: unknown option -$OPTARG" >&2; usage; exit 1 ;;
    :) echo "Error: option -$OPTARG requires an argument" >&2; usage; exit 1 ;;
  esac
done

if ! command -v gawk >/dev/null 2>&1; then
  echo "Error: this script requires GNU awk (gawk) for the mktime()/strftime()/match() functions." >&2
  exit 1
fi
if ! [[ "$THRESHOLD" =~ ^[0-9]+$ ]]; then
  echo "Error: threshold (-t) must be a non-negative integer" >&2
  exit 1
fi
if ! [[ "$WINDOW_MIN" =~ ^[1-9][0-9]*$ ]]; then
  echo "Error: window (-w) must be a positive integer" >&2
  exit 1
fi
if [[ "$DO_EXECUTE" -eq 1 && "$DO_BLOCK" -eq 0 ]]; then
  echo "Error: -x requires -B" >&2
  exit 1
fi

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

# ---- Shared gawk programs (written once, reused per source / per run) ----
NORMALIZE_AWK="$WORKDIR/normalize.awk"
cat > "$NORMALIZE_AWK" <<'AWK_EOF'
function iso_to_epoch(ts,   a) {
    if (!match(ts, /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})/, a)) return -1
    return mktime(a[1] " " a[2] " " a[3] " " a[4] " " a[5] " " a[6], 1)
}
BEGIN {
    n = split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", monarr, " ")
    for (m = 1; m <= n; m++) mon2num[monarr[m]] = m
    total_lines = 0
    matched = 0
}
{
    total_lines++
}
type == "ssh" && (/Failed password/ || /authentication failure/) {
    ip = ""; user = ""
    if ($0 ~ /Failed password/) {
        for (i = 1; i <= NF; i++) {
            if ($i == "for" && $(i+1) == "invalid" && $(i+2) == "user") user = $(i+3)
            else if ($i == "for" && user == "") user = $(i+1)
            if ($i == "from") ip = $(i+1)
        }
    } else {
        for (i = 1; i <= NF; i++) {
            if ($i ~ /^rhost=/) { split($i, kv, "="); ip = kv[2] }
            if ($i ~ /^user=/)  { split($i, kv, "="); user = kv[2] }
        }
    }
    if (ip == "" || ip !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) next
    if (user == "") user = "unknown"
    mon = mon2num[$1]
    if (mon == "") next
    day = $2
    split($3, tm, ":")
    if (tm[1] == "" || tm[2] == "" || tm[3] == "") next
    epoch = mktime(year " " mon " " day " " tm[1] " " tm[2] " " tm[3], 1)
    if (epoch <= 0) next
    matched++
    print epoch "|" ip "|" user "|" app >> normfile
}
type == "web" && /LOGIN_FAILED/ {
    ip = ""; user = ""; tsraw = $1
    for (i = 1; i <= NF; i++) {
        if ($i ~ /^ip=/)   { split($i, kv, "="); ip = kv[2] }
        if ($i ~ /^user=/) { split($i, kv, "="); user = kv[2] }
    }
    if (ip == "" || ip !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) next
    if (user == "") user = "unknown"
    epoch = iso_to_epoch(tsraw)
    if (epoch <= 0) next
    matched++
    print epoch "|" ip "|" user "|" app >> normfile
}
type == "db" && /Access denied/ {
    ip = ""; user = ""; tsraw = $1
    if (match($0, /user '([^']+)'@'([0-9.]+)'/, a)) { user = a[1]; ip = a[2] }
    if (ip == "" || ip !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) next
    if (user == "") user = "unknown"
    epoch = iso_to_epoch(tsraw)
    if (epoch <= 0) next
    matched++
    print epoch "|" ip "|" user "|" app >> normfile
}
type == "api" && /auth_failure/ {
    ip = ""; user = ""; tsraw = ""
    if (match($0, /"time":"([^"]+)"/, a)) tsraw = a[1]
    if (match($0, /"ip":"([0-9.]+)"/, a)) ip = a[1]
    if (match($0, /"user":"([^"]+)"/, a)) user = a[1]
    if (ip == "" || ip !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) next
    if (user == "") user = "unknown"
    epoch = iso_to_epoch(tsraw)
    if (epoch <= 0) next
    matched++
    print epoch "|" ip "|" user "|" app >> normfile
}
END {
    printf "%d %d\n", total_lines, matched
}
AWK_EOF

DETECT_AWK="$WORKDIR/detect.awk"
cat > "$DETECT_AWK" <<'AWK_EOF'
BEGIN { FS = "|" }
{
    epoch = $1 + 0; ip = $2; user = $3; app = $4
    cnt[ip]++
    idx = cnt[ip]
    ts[ip, idx] = epoch
    akey = ip SUBSEP app
    if (!(akey in appseen)) {
        appseen[akey] = 1
        napps[ip]++
        applist[ip] = (applist[ip] == "" ? app : applist[ip] ";" app)
    }
    if (!(ip in users)) users[ip] = user
    else if (index(users[ip], user) == 0) users[ip] = users[ip] ";" user
    if (!(ip in first) || epoch < first[ip]) first[ip] = epoch
    if (!(ip in last)  || epoch > last[ip])  last[ip]  = epoch
}
END {
    flagged_total = 0
    span = threshold + 1
    for (ip in cnt) {
        entries = cnt[ip]
        for (a = 1; a <= entries; a++) arr[a] = ts[ip, a]
        for (a = 2; a <= entries; a++) {
            key = arr[a]; b = a - 1
            while (b >= 1 && arr[b] > key) { arr[b+1] = arr[b]; b-- }
            arr[b+1] = key
        }
        is_flagged = 0
        for (a = 1; a <= entries - span + 1; a++) {
            if (arr[a + span - 1] - arr[a] <= window_sec) { is_flagged = 1; break }
        }
        flag_ip[ip] = is_flagged
        if (is_flagged) flagged_total++

        severity[ip] = "-"
        if (is_flagged) {
            severity[ip] = "MEDIUM"
            if (cnt[ip] >= threshold * 2) severity[ip] = "HIGH"
            if (napps[ip] >= 2 && severity[ip] == "MEDIUM") severity[ip] = "HIGH"
            if (napps[ip] >= 3) severity[ip] = "CRITICAL"
        }
        delete arr
    }

    printf "TOTAL_FLAGGED %d\n", flagged_total > stats_out
    for (ip in cnt) {
        printf "%s|%d|%d|%s|%s|%s|%s|%s|%s\n", ip, cnt[ip], napps[ip], applist[ip], users[ip], \
            strftime("%Y-%m-%d %H:%M:%S", first[ip], 1), strftime("%Y-%m-%d %H:%M:%S", last[ip], 1), \
            (flag_ip[ip] ? "YES" : "no"), severity[ip] >> ips_out
    }
    close(stats_out)
    close(ips_out)
}
AWK_EOF

# ---- Helpers -------------------------------------------------------------

normalize_source() {
  # args: type file app_label normfile
  local type="$1" file="$2" app_label="$3" normfile="$4"
  if [[ ! -r "$file" ]]; then
    echo "Error: cannot read log file: $file" >&2
    exit 1
  fi
  case "$type" in
    ssh|web|db|api) ;;
    *) echo "Error: unknown source type '$type' (expected ssh, web, db, or api)" >&2; exit 1 ;;
  esac
  gawk -v type="$type" -v app="$app_label" -v normfile="$normfile" -v year="$(date +%Y)" \
    -f "$NORMALIZE_AWK" "$file"
}

default_sources_if_empty() {
  if [[ "${#SOURCES[@]}" -eq 0 ]]; then
    SOURCES=(
      "ssh:${SCRIPT_DIR}/sample_logs/ssh_auth.log"
      "web:${SCRIPT_DIR}/sample_logs/web_auth.log"
      "db:${SCRIPT_DIR}/sample_logs/db_auth.log"
      "api:${SCRIPT_DIR}/sample_logs/api_auth.log"
    )
  fi
}

# Runs the full normalize+detect pipeline for the given sources array (by name)
# into the given output dir. Prints "elapsed_ms total_lines total_events" on stdout.
# Writes: $1/report.txt $1/report.csv
run_pipeline() {
  local -n _sources="$1"
  local pipeline_out="$2"
  mkdir -p "$pipeline_out"
  local normfile="$WORKDIR/normalized_$$_${RANDOM}.psv"
  : > "$normfile"

  local start_ns end_ns total_lines=0 total_events=0
  start_ns="$(date +%s%N)"

  for src in "${_sources[@]}"; do
    local type="${src%%:*}" file="${src#*:}"
    local stats
    stats="$(normalize_source "$type" "$file" "$type" "$normfile")"
    total_lines=$(( total_lines + $(awk '{print $1}' <<<"$stats") ))
    total_events=$(( total_events + $(awk '{print $2}' <<<"$stats") ))
  done

  local stats_out="$WORKDIR/stats_$$_${RANDOM}.txt"
  local ips_out="$pipeline_out/report.csv.body"
  : > "$ips_out"

  gawk -v threshold="$THRESHOLD" -v window_sec="$(( WINDOW_MIN * 60 ))" \
       -v stats_out="$stats_out" -v ips_out="$ips_out" \
       -f "$DETECT_AWK" "$normfile"

  end_ns="$(date +%s%N)"
  local elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))

  local flagged_total=0
  if [[ -s "$stats_out" ]]; then
    flagged_total="$(awk '{print $2}' "$stats_out")"
  fi

  {
    echo "ip,attempts,apps_hit,applications,usernames,first_seen,last_seen,flagged,severity"
    sort -t'|' -k1,1 "$ips_out" | tr '|' ','
  } > "$pipeline_out/report.csv"
  rm -f "$ips_out"

  {
    echo "==================================================================="
    echo " Suspicious Login Detector - Summary Report (v${VERSION})"
    echo "==================================================================="
    printf "Sources scanned         : %d application source(s)\n" "${#_sources[@]}"
    for src in "${_sources[@]}"; do
      printf "  - %-4s : %s\n" "${src%%:*}" "${src#*:}"
    done
    printf "Log lines scanned        : %d\n" "$total_lines"
    printf "Failed login events      : %d\n" "$total_events"
    printf "Threshold                : more than %d attempts within %d minute(s)\n" "$THRESHOLD" "$WINDOW_MIN"
    printf "Flagged suspicious IPs   : %d\n" "$flagged_total"
    echo "---------------------------------------------------------------------"

    if [[ "$flagged_total" -gt 0 ]]; then
      printf "%-16s %-9s %-9s %-18s %-25s %-9s\n" "IP" "Attempts" "AppsHit" "Applications" "Username(s)" "Severity"
      awk -F',' 'NR>1 && $8=="YES"{printf "%-16s %-9s %-9s %-18s %-25s %-9s\n",$1,$2,$3,$4,$5,$9}' "$pipeline_out/report.csv"
      echo "---------------------------------------------------------------------"
      echo "Recovery Actions (per flagged IP):"
      awk -F',' 'NR>1 && $8=="YES"{print $1"|"$9"|"$5}' "$pipeline_out/report.csv" | while IFS='|' read -r rip rsev rusers; do
        echo ""
        echo "  IP ${rip}  (severity: ${rsev})"
        echo "    [ ] Block this IP at the perimeter firewall (run with -B to generate commands)"
        echo "    [ ] Force logout / invalidate active sessions for: ${rusers}"
        echo "    [ ] Require a password reset for the targeted account(s) above"
        echo "    [ ] Review recent SUCCESSFUL logins from ${rip} for signs of prior compromise"
        echo "    [ ] Keep the block in place for ${COOLDOWN_HOURS}h, then re-review with -r (recovery mode)"
      done
      echo ""
    else
      echo "No IPs exceeded the configured threshold."
    fi
    echo "==================================================================="
  } > "$pipeline_out/report.txt"

  echo "$elapsed_ms $total_lines $total_events"
}

# ---- Mode: benchmark -------------------------------------------------------
run_benchmark() {
  mkdir -p "$OUT_DIR"
  local ts; ts="$(date +%Y%m%d_%H%M%S)"
  local bench_report="${OUT_DIR}/benchmark_${ts}.txt"

  declare -a scen_names=("combined-default" "ssh-only" "clean-traffic")
  declare -a scen_expected=(
    "${SCRIPT_DIR}/sample_logs/expected_combined.txt"
    "${SCRIPT_DIR}/sample_logs/ssh_auth.expected"
    "${SCRIPT_DIR}/sample_logs/clean_traffic.expected"
  )

  local overall_pass=1
  {
    echo "==================================================================="
    echo " Suspicious Login Detector - Benchmark / Proof Report (v${VERSION})"
    echo "==================================================================="
    echo "Generated : $(date -Iseconds)"
    echo "Threshold : more than ${THRESHOLD} attempts within ${WINDOW_MIN} minute(s)"
    echo "Scenarios : ${#scen_names[@]}"
    echo "---------------------------------------------------------------------"
  } > "$bench_report"

  local i
  for i in "${!scen_names[@]}"; do
    local name="${scen_names[$i]}" expfile="${scen_expected[$i]}"
    local scen_sources
    case "$name" in
      combined-default)
        scen_sources=(
          "ssh:${SCRIPT_DIR}/sample_logs/ssh_auth.log"
          "web:${SCRIPT_DIR}/sample_logs/web_auth.log"
          "db:${SCRIPT_DIR}/sample_logs/db_auth.log"
          "api:${SCRIPT_DIR}/sample_logs/api_auth.log"
        )
        ;;
      ssh-only)
        scen_sources=( "ssh:${SCRIPT_DIR}/sample_logs/ssh_auth.log" )
        ;;
      clean-traffic)
        scen_sources=( "ssh:${SCRIPT_DIR}/sample_logs/clean_traffic.log" )
        ;;
    esac

    local pipeline_out="$WORKDIR/bench_${name}"
    local timing
    timing="$(run_pipeline scen_sources "$pipeline_out")"
    local elapsed_ms total_lines total_events
    read -r elapsed_ms total_lines total_events <<<"$timing"

    local detected
    detected="$(awk -F',' 'NR>1 && $8=="YES"{print $1}' "$pipeline_out/report.csv" | sort | paste -sd, -)"
    local expected
    expected="$(grep '^flagged_ips=' "$expfile" | head -1 | cut -d= -f2- | tr ',' '\n' | sed '/^$/d' | sort | paste -sd, -)"

    local result="PASS"
    [[ "$detected" == "$expected" ]] || { result="FAIL"; overall_pass=0; }

    local throughput=0
    if [[ "$elapsed_ms" -gt 0 ]]; then
      throughput=$(( total_lines * 1000 / elapsed_ms ))
    fi

    {
      printf "Scenario            : %s\n" "$name"
      printf "  Log lines scanned : %d\n" "$total_lines"
      printf "  Failed events     : %d\n" "$total_events"
      printf "  Elapsed time      : %d ms  (~%d lines/sec)\n" "$elapsed_ms" "$throughput"
      printf "  Expected flagged  : %s\n" "${expected:-<none>}"
      printf "  Detected flagged  : %s\n" "${detected:-<none>}"
      printf "  Result            : %s\n" "$result"
      echo "---------------------------------------------------------------------"
    } >> "$bench_report"
  done

  {
    if [[ "$overall_pass" -eq 1 ]]; then
      echo "OVERALL RESULT: PASS - detected output matched ground truth on all ${#scen_names[@]} controlled scenarios."
    else
      echo "OVERALL RESULT: FAIL - one or more scenarios did not match ground truth. See above."
    fi
    echo "This report is the benchmark proof of detection accuracy referenced in the project write-up."
    echo "==================================================================="
  } >> "$bench_report"

  if [[ "$QUIET" -eq 0 ]]; then
    cat "$bench_report"
  fi
  echo "Benchmark report: $bench_report"

  [[ "$overall_pass" -eq 1 ]] && exit 0 || exit 2
}

# ---- Mode: recover ----------------------------------------------------------
run_recover() {
  mkdir -p "$OUT_DIR"
  local ts; ts="$(date +%Y%m%d_%H%M%S)"
  local unblock_script="${OUT_DIR}/unblock_commands_${ts}.sh"
  local recovery_report="${OUT_DIR}/recovery_actions_${ts}.txt"
  local cooldown_sec=$(( COOLDOWN_HOURS * 3600 ))
  local now_epoch; now_epoch="$(date +%s)"

  if [[ ! -f "$BLOCKLIST_FILE" ]]; then
    echo "No blocklist file found at $BLOCKLIST_FILE - nothing to recover." >&2
    exit 0
  fi

  {
    echo "#!/usr/bin/env bash"
    echo "# Auto-generated unblock commands - review before running. Requires root."
    echo "# Generated: $(date -Iseconds) by ${SCRIPT_NAME} v${VERSION} (recovery mode)"
    echo "set -e"
  } > "$unblock_script"
  chmod +x "$unblock_script"

  {
    echo "==================================================================="
    echo " Suspicious Login Detector - Recovery Actions Report (v${VERSION})"
    echo "==================================================================="
    echo "Cooldown period: ${COOLDOWN_HOURS}h"
  } > "$recovery_report"

  local tmp_blocklist="$WORKDIR/blocklist.tsv"
  : > "$tmp_blocklist"
  local recovered_count=0

  while IFS=$'\t' read -r ip first_blocked_iso expiry_iso severity status; do
    [[ -z "${ip:-}" || "$ip" == "#"* ]] && { [[ -n "${ip:-}" ]] && echo -e "${ip}\t${first_blocked_iso}\t${expiry_iso}\t${severity}\t${status}" >> "$tmp_blocklist"; continue; }
    if [[ "$status" == "active" ]]; then
      local first_epoch; first_epoch="$(date -d "$first_blocked_iso" +%s 2>/dev/null || echo 0)"
      local elapsed=$(( now_epoch - first_epoch ))
      if [[ "$elapsed" -ge "$cooldown_sec" ]]; then
        {
          echo "# ${ip} - blocked at ${first_blocked_iso}, severity ${severity}, cooldown elapsed"
          echo "iptables -D INPUT -s ${ip} -j DROP 2>/dev/null || true"
          echo "ufw delete deny from ${ip} to any 2>/dev/null || true"
        } >> "$unblock_script"
        {
          echo "-------------------------------------------------------------------"
          echo "IP ${ip} (was ${severity}) - COOLDOWN COMPLETE, recommended to unblock"
          echo "  [ ] Confirm no further failed attempts from this IP since blocking"
          echo "  [ ] Run the generated unblock command in ${unblock_script}"
          echo "  [ ] Rotate credentials for any account this IP targeted"
          echo "  [ ] Continue monitoring this IP for ${COOLDOWN_HOURS}h after unblocking"
        } >> "$recovery_report"
        echo -e "${ip}\t${first_blocked_iso}\t${expiry_iso}\t${severity}\trecovered" >> "$tmp_blocklist"
        recovered_count=$(( recovered_count + 1 ))
      else
        local remaining=$(( (cooldown_sec - elapsed) / 3600 ))
        {
          echo "-------------------------------------------------------------------"
          echo "IP ${ip} (${severity}) - still cooling down (~${remaining}h remaining), left active"
        } >> "$recovery_report"
        echo -e "${ip}\t${first_blocked_iso}\t${expiry_iso}\t${severity}\t${status}" >> "$tmp_blocklist"
      fi
    else
      echo -e "${ip}\t${first_blocked_iso}\t${expiry_iso}\t${severity}\t${status}" >> "$tmp_blocklist"
    fi
  done < "$BLOCKLIST_FILE"

  cp "$tmp_blocklist" "$BLOCKLIST_FILE"

  {
    echo "==================================================================="
    printf "IPs recommended for unblock this run: %d\n" "$recovered_count"
    echo "Unblock script: $unblock_script"
    echo "==================================================================="
  } >> "$recovery_report"

  if [[ "$QUIET" -eq 0 ]]; then
    cat "$recovery_report"
  fi
  echo "Blocklist updated: $BLOCKLIST_FILE"
  exit 0
}

# ---- Mode: detect (default) --------------------------------------------
run_detect() {
  default_sources_if_empty
  mkdir -p "$OUT_DIR"
  local ts; ts="$(date +%Y%m%d_%H%M%S)"
  local pipeline_out="$WORKDIR/detect_run"

  local timing
  timing="$(run_pipeline SOURCES "$pipeline_out")"
  local elapsed_ms total_lines total_events
  read -r elapsed_ms total_lines total_events <<<"$timing"

  local text_report="${OUT_DIR}/report_${ts}.txt"
  local csv_report="${OUT_DIR}/report_${ts}.csv"
  cp "$pipeline_out/report.txt" "$text_report"
  cp "$pipeline_out/report.csv" "$csv_report"

  local flagged_count
  flagged_count="$(awk -F',' 'NR>1 && $8=="YES"{c++} END{print c+0}' "$csv_report")"

  if [[ "$QUIET" -eq 0 ]]; then
    cat "$text_report"
    echo
    echo "Processing time          : ${elapsed_ms} ms"
    echo "Text report              : $text_report"
    echo "CSV report               : $csv_report"
  fi

  if [[ -n "$MAIL_TO" && "$flagged_count" -gt 0 ]]; then
    local subject="Suspicious Login Detector: ${flagged_count} IP(s) flagged on $(hostname)"
    if command -v mailx >/dev/null 2>&1; then
      mailx -s "$subject" "$MAIL_TO" < "$text_report"
    elif command -v sendmail >/dev/null 2>&1; then
      { echo "Subject: $subject"; echo "To: $MAIL_TO"; echo; cat "$text_report"; } | sendmail -t
    else
      echo "Warning: neither mailx nor sendmail is installed; skipping email alert." >&2
    fi
  fi

  if [[ "$DO_BLOCK" -eq 1 && "$flagged_count" -gt 0 ]]; then
    local block_script="${OUT_DIR}/block_commands_${ts}.sh"
    {
      echo "#!/usr/bin/env bash"
      echo "# Auto-generated block commands - review before running. Requires root/NET_ADMIN."
      echo "# Generated: $(date -Iseconds) by ${SCRIPT_NAME} v${VERSION}"
      echo "set -e"
    } > "$block_script"
    chmod +x "$block_script"

    [[ -f "$BLOCKLIST_FILE" ]] || : > "$BLOCKLIST_FILE"
    local now_iso; now_iso="$(date -Iseconds)"

    awk -F',' 'NR>1 && $8=="YES"{print $1"|"$9"|"$5}' "$csv_report" | while IFS='|' read -r bip bsev busers; do
      {
        echo "# ${bip} - severity ${bsev}, usernames targeted: ${busers}"
        echo "iptables -A INPUT -s ${bip} -j DROP"
        echo "ufw deny from ${bip} to any"
        echo ""
      } >> "$block_script"

      if ! grep -q "^${bip}"$'\t' "$BLOCKLIST_FILE" 2>/dev/null; then
        echo -e "${bip}\t${now_iso}\t-\t${bsev}\tactive" >> "$BLOCKLIST_FILE"
      fi

      if [[ "$DO_EXECUTE" -eq 1 ]]; then
        if [[ "$EUID" -eq 0 ]] && command -v iptables >/dev/null 2>&1; then
          iptables -A INPUT -s "$bip" -j DROP && echo "Executed: blocked ${bip} via iptables"
        else
          echo "Warning: -x given but not running as root or iptables missing; skipped execution for ${bip}" >&2
        fi
      fi
    done

    if [[ "$QUIET" -eq 0 ]]; then
      echo
      echo "Block commands generated: $block_script (review before running)"
      echo "Blocklist updated       : $BLOCKLIST_FILE"
    fi
  fi

  [[ "$flagged_count" -gt 0 ]] && exit 2
  exit 0
}

case "$MODE" in
  benchmark) run_benchmark ;;
  recover)   run_recover ;;
  detect)    run_detect ;;
esac
