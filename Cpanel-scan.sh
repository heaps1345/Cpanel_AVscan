#!/bin/bash
# CVE-2026-41940 IOC + ClamAV Infrastructure Scan
# Run as root: bash scan.sh [--verbose] [--purge [--yes]]

HOSTNAME=$(hostname)
DATE=$(date +%Y%m%d_%H%M)
LOG_DIR="/root/magn8_scan"
LOG_FILE="$LOG_DIR/${HOSTNAME}_scan_${DATE}.log"
ALERT_FILE="$LOG_DIR/${HOSTNAME}_ALERTS_${DATE}.txt"
mkdir -p "$LOG_DIR"

log()   { echo "$1" | tee -a "$LOG_FILE"; }
alert() { echo "[ALERT] $1" | tee -a "$LOG_FILE" | tee -a "$ALERT_FILE"; }
ok()    { echo "[OK]    $1" | tee -a "$LOG_FILE"; }
info()  { echo "[INFO]  $1" | tee -a "$LOG_FILE"; }

log "============================================================================"
log " Magn8 Infrastructure Security Scan"
log " Host     : $HOSTNAME"
log " Date     : $(date)"
log " Log      : $LOG_FILE"
log " Alerts   : $ALERT_FILE"
log "============================================================================"

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 1 — CVE-2026-41940 CPANEL VERSION CHECK
# ─────────────────────────────────────────────────────────────────────────────
log ""
log "============================================================================"
log " SECTION 1: CVE-2026-41940 — cPanel Version Check"
log "============================================================================"

PATCHED_VERSIONS=("11.86.0.41" "11.110.0.97" "11.118.0.63" "11.126.0.54"
                  "11.130.0.19" "11.132.0.29" "11.134.0.20" "11.136.0.5")

if command -v /usr/local/cpanel/cpanel &>/dev/null; then
    CPANEL_VER=$(/usr/local/cpanel/cpanel -V 2>/dev/null)
    log "cPanel version: $CPANEL_VER"
    PATCHED=false
    for v in "${PATCHED_VERSIONS[@]}"; do
        [[ "$CPANEL_VER" == *"$v"* ]] && PATCHED=true && break
    done
    if $PATCHED; then
        ok "cPanel version is patched for CVE-2026-41940"
    else
        alert "cPanel version $CPANEL_VER is NOT in patched list — PATCH IMMEDIATELY"
        alert "Run: /scripts/upcp --force"
        alert "Patched versions: ${PATCHED_VERSIONS[*]}"
    fi
else
    info "cPanel binary not found at /usr/local/cpanel/cpanel — may not be a cPanel server"
fi

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 2 — CVE-2026-41940 OFFICIAL CPANEL IOC SESSION SCAN
# cPanel official detection script (support.cpanel.net/hc/en-us/articles/
# 40073787579671) integrated verbatim with output redirected to our log
# ─────────────────────────────────────────────────────────────────────────────
log ""
log "============================================================================"
log " SECTION 2: CVE-2026-41940 — Official cPanel IOC Session File Scan"
log "============================================================================"

# Default paths (can be overridden with --sessions-dir / --access-log)
SESSIONS_DIR="/var/cpanel/sessions"
ACCESS_LOG="/usr/local/cpanel/logs/access_log"
VERBOSE=0
PURGE=0
ASSUME_YES=0

while [ $# -gt 0 ]; do
    case "$1" in
        --verbose)       VERBOSE=1 ;;
        --purge)         PURGE=1 ;;
        --yes|-y)        ASSUME_YES=1 ;;
        --sessions-dir)  SESSIONS_DIR="$2"; shift ;;
        --access-log)    ACCESS_LOG="$2"; shift ;;
        --help|-h)
            echo "Usage: $0 [--verbose] [--purge [--yes]] [--sessions-dir DIR] [--access-log FILE]"
            exit 0 ;;
        *)
            echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
    shift
done

FINDINGS=()
FINDING_SESSIONS=()
FINDING_TOKENS=()
FINDING_SEVERITIES=()
COUNT_CRITICAL=0
COUNT_WARNING=0
COUNT_INFO=0
COUNT_ATTEMPT=0

get_field() {
    local file="$1" key="$2"
    grep "^${key}=" "$file" | head -1 | cut -d= -f2-
}

hr() { echo "    ----------------------------------------------------------------"; }

dump_session() {
    local session_file="$1" token_val="$2"
    local session_name preauth_file
    session_name=$(basename "$session_file")
    preauth_file="$SESSIONS_DIR/preauth/$session_name"
    hr
    echo "    SESSION DUMP: $session_file"
    hr
    echo "    File metadata:"
    ls -la "$session_file" 2>/dev/null | sed 's/^/      /'
    echo
    echo "    Full session contents:"
    sed 's/^/      /' "$session_file"
    echo
    if [ -f "$preauth_file" ]; then
        echo "    Matching pre-auth file: $preauth_file"
        ls -la "$preauth_file" 2>/dev/null | sed 's/^/      /'
        echo "    Pre-auth contents:"
        sed 's/^/      /' "$preauth_file"
        echo
    fi
    if [ -n "$token_val" ] && [ -r "$ACCESS_LOG" ]; then
        echo "    Access log hits for token '$token_val':"
        grep -aF -- "$token_val" "$ACCESS_LOG" | sed 's/^/      /' || echo "      (none)"
        echo
    fi
    hr
}

report_finding() {
    local severity="$1" session_file="$2" token_val="$3" message="$4"
    local sev_rank=0
    case "$severity" in
        CRITICAL) sev_rank=3 ;;
        WARNING)  sev_rank=2 ;;
        ATTEMPT)  sev_rank=1 ;;
        INFO)     sev_rank=0 ;;
    esac

    local i found=0 prev_sev prev_rank
    for i in "${!FINDING_SESSIONS[@]}"; do
        if [ "${FINDING_SESSIONS[$i]}" = "$session_file" ]; then
            found=1
            prev_sev="${FINDING_SEVERITIES[$i]}"
            case "$prev_sev" in
                CRITICAL) prev_rank=3 ;;
                WARNING)  prev_rank=2 ;;
                ATTEMPT)  prev_rank=1 ;;
                INFO)     prev_rank=0 ;;
            esac
            if [ "$sev_rank" -le "$prev_rank" ]; then return; fi
            FINDING_SEVERITIES[$i]="$severity"
            [ -n "$token_val" ] && FINDING_TOKENS[$i]="$token_val"
            local j
            for j in "${!FINDINGS[@]}"; do
                local entry="${FINDINGS[$j]}"
                local entry_sev="${entry%%|*}"
                local entry_file="${entry#*|}"; entry_file="${entry_file%%|*}"
                if [ "$entry_file" = "$session_file" ] && [ "$entry_sev" = "$prev_sev" ]; then
                    FINDINGS[$j]="${severity}|${session_file}|${message}"
                    break
                fi
            done
            case "$prev_sev" in
                CRITICAL) COUNT_CRITICAL=$((COUNT_CRITICAL - 1)) ;;
                WARNING)  COUNT_WARNING=$((COUNT_WARNING - 1))   ;;
                ATTEMPT)  COUNT_ATTEMPT=$((COUNT_ATTEMPT - 1))   ;;
                INFO)     COUNT_INFO=$((COUNT_INFO - 1))         ;;
            esac
            break
        fi
    done

    if [ "$found" -eq 0 ]; then
        FINDING_SESSIONS+=("$session_file")
        FINDING_TOKENS+=("$token_val")
        FINDING_SEVERITIES+=("$severity")
        FINDINGS+=("${severity}|${session_file}|${message}")
    fi

    case "$severity" in
        CRITICAL) COUNT_CRITICAL=$((COUNT_CRITICAL + 1)) ;;
        WARNING)  COUNT_WARNING=$((COUNT_WARNING + 1))   ;;
        ATTEMPT)  COUNT_ATTEMPT=$((COUNT_ATTEMPT + 1))   ;;
        INFO)     COUNT_INFO=$((COUNT_INFO + 1))         ;;
    esac

    echo "[${severity}] ${message}: ${session_file}" | tee -a "$LOG_FILE"
    # Escalate CRITICAL and WARNING to the alert file
    if [ "$severity" = "CRITICAL" ] || [ "$severity" = "WARNING" ]; then
        echo "[ALERT][${severity}] CVE-2026-41940 IOC: ${message}: ${session_file}" >> "$ALERT_FILE"
    fi
}

check_token_denied_with_injected_token() {
    local session_file="$1"
    grep -q '^token_denied='      "$session_file" || return
    grep -q '^cp_security_token=' "$session_file" || return
    local token_val external_auth internal_auth hasroot tfa used
    token_val=$(get_field      "$session_file" cp_security_token)
    external_auth=$(get_field  "$session_file" successful_external_auth_with_timestamp)
    internal_auth=$(get_field  "$session_file" successful_internal_auth_with_timestamp)
    hasroot=$(get_field        "$session_file" hasroot)
    tfa=$(get_field            "$session_file" tfa_verified)
    used=""
    if [ -r "$ACCESS_LOG" ]; then
        used=$(grep -aF -- "$token_val" "$ACCESS_LOG" | grep -m1 " 200 ")
    fi
    local has_auth_markers=0
    if [ -n "$external_auth" ] || [ -n "$internal_auth" ] \
       || [ "$hasroot" = "1" ] || [ "$tfa" = "1" ] || [ -n "$used" ]; then
        has_auth_markers=1
    fi
    if grep -q '^origin_as_string=.*method=badpass' "$session_file"; then
        if [ "$has_auth_markers" -eq 1 ]; then
            report_finding CRITICAL "$session_file" "$token_val" \
                "Exploitation artifact - token_denied with injected cp_security_token (badpass origin, token used)"
        else
            if grep -q '^pass=' "$session_file"; then return; fi
            report_finding INFO "$session_file" "$token_val" \
                "Possible injected session (badpass origin, no usage observed)"
        fi
    elif grep -q '^origin_as_string=.*method=handle_form_login'    "$session_file" || \
         grep -q '^origin_as_string=.*method=create_user_session'  "$session_file" || \
         grep -q '^origin_as_string=.*method=handle_auth_transfer' "$session_file"; then
        return
    else
        report_finding WARNING "$session_file" "$token_val" \
            "Suspicious session with token_denied + cp_security_token (non-badpass origin)"
    fi
}

check_preauth_with_auth_attrs() {
    local session_file="$1"
    local session_name preauth_file
    session_name=$(basename "$session_file")
    preauth_file="$SESSIONS_DIR/preauth/$session_name"
    [ -f "$preauth_file" ] || return
    local marker
    if grep -qE '^successful_external_auth_with_timestamp=' "$session_file"; then
        marker="successful_external_auth_with_timestamp"
    elif grep -qE '^successful_internal_auth_with_timestamp=' "$session_file"; then
        marker="successful_internal_auth_with_timestamp"
    else
        return
    fi
    report_finding CRITICAL "$session_file" \
        "$(get_field "$session_file" cp_security_token)" \
        "Injected session - ${marker} present in pre-auth session"
}

check_tfa_with_bad_origin() {
    local session_file="$1"
    grep -qE '^tfa_verified=1$' "$session_file" || return
    grep -q '^origin_as_string=.*method=handle_form_login'    "$session_file" && return
    grep -q '^origin_as_string=.*method=create_user_session'  "$session_file" && return
    grep -q '^origin_as_string=.*method=handle_auth_transfer' "$session_file" && return
    report_finding WARNING "$session_file" \
        "$(get_field "$session_file" cp_security_token)" \
        "Session with tfa_verified=1 but suspicious origin"
}

check_malformed_session_line() {
    local session_file="$1"
    grep -nE -v '^[A-Za-z_][A-Za-z0-9_]*=|^[[:space:]]*$' "$session_file" >/dev/null 2>&1 || return
    report_finding CRITICAL "$session_file" \
        "$(get_field "$session_file" cp_security_token)" \
        "Malformed session line(s) detected (not key=value - newline injection footprint)"
}

check_badpass_with_auth_markers() {
    local session_file="$1"
    grep -q '^origin_as_string=.*method=badpass' "$session_file" || return
    local markers=()
    grep -q '^successful_external_auth_with_timestamp=' "$session_file" \
        && markers+=("successful_external_auth_with_timestamp")
    grep -q '^successful_internal_auth_with_timestamp=' "$session_file" \
        && markers+=("successful_internal_auth_with_timestamp")
    grep -qE '^hasroot=1$'      "$session_file" && markers+=("hasroot=1")
    grep -qE '^tfa_verified=1$' "$session_file" && markers+=("tfa_verified=1")
    [ "${#markers[@]}" -gt 0 ] || return
    local joined
    joined=$(IFS=,; echo "${markers[*]}")
    report_finding CRITICAL "$session_file" \
        "$(get_field "$session_file" cp_security_token)" \
        "badpass origin combined with authenticated markers ($joined) - impossible in benign flow"
}

check_failed_exploit_attempt() {
    local session_file="$1"
    grep -q '^origin_as_string=.*method=badpass' "$session_file" || return
    grep -q '^token_denied=' "$session_file" || return
    grep -q '^successful_internal_auth_with_timestamp=' "$session_file" && return
    grep -q '^successful_external_auth_with_timestamp=' "$session_file" && return
    grep -q '^pass=' "$session_file" || return
    report_finding ATTEMPT "$session_file" "$(get_field "$session_file" cp_security_token)" \
        "Failed exploit attempt (badpass origin, token_denied, no auth markers, anomalous pass= line)"
}

scan_sessions() {
    local session_file
    while IFS= read -r -d '' session_file; do
        check_token_denied_with_injected_token "$session_file"
        check_preauth_with_auth_attrs          "$session_file"
        check_tfa_with_bad_origin              "$session_file"
        check_malformed_session_line           "$session_file"
        check_badpass_with_auth_markers        "$session_file"
        check_failed_exploit_attempt           "$session_file"
    done < <(find "$SESSIONS_DIR/raw" -type f -print0 2>/dev/null)
}

print_cpanel_summary() {
    local total=$((COUNT_CRITICAL + COUNT_WARNING + COUNT_INFO + COUNT_ATTEMPT))
    log ""
    log "================================================================="
    log "  CVE-2026-41940 SESSION SCAN SUMMARY"
    log "================================================================="
    log "  CRITICAL findings : $COUNT_CRITICAL"
    log "  WARNING  findings : $COUNT_WARNING"
    log "  ATTEMPT  findings : $COUNT_ATTEMPT"
    log "  INFO     findings : $COUNT_INFO"
    log "  Total             : $total"
    log "-----------------------------------------------------------------"

    if [ "$total" -eq 0 ]; then
        ok "No CVE-2026-41940 session IOCs found"
        return
    fi

    if [ "$PURGE" -eq 1 ] && [ "$ASSUME_YES" -ne 1 ]; then
        if [ ! -t 0 ]; then
            echo "[ERROR] --purge requires --yes when stdin is not a TTY" >&2
            exit 64
        fi
        echo
        echo "About to delete ${#FINDING_SESSIONS[@]} session file(s) plus matching preauth markers."
        local confirm=""
        read -r -p "Type 'yes' to confirm: " confirm
        if [ "$confirm" != "yes" ]; then
            echo "[+] Aborted; no files deleted."
            PURGE=0
        fi
    fi

    local i session token severity message found=0
    for i in "${!FINDING_SESSIONS[@]}"; do
        session="${FINDING_SESSIONS[$i]}"
        token="${FINDING_TOKENS[$i]}"
        severity="${FINDING_SEVERITIES[$i]}"
        found=0
        for entry in "${FINDINGS[@]}"; do
            local entry_sev entry_file entry_msg
            IFS='|' read -r entry_sev entry_file entry_msg <<< "$entry"
            if [ "$entry_file" = "$session" ] && [ "$entry_sev" = "$severity" ]; then
                message="$entry_msg"
                found=1
                break
            fi
        done
        log ""
        log "================================================================="
        log "  SESSION: $session"
        log "================================================================="
        if [ "$found" -eq 1 ]; then
            printf "    [%-8s] %s\n" "$severity" "$message" | tee -a "$LOG_FILE"
        fi
        if [ "$VERBOSE" -eq 1 ]; then dump_session "$session" "$token"; fi
        if [ "$PURGE" -eq 1 ]; then
            log "    [ACTION] Deleting session file: $session"
            rm -f -- "$session"
            local preauth_marker="$SESSIONS_DIR/preauth/$(basename "$session")"
            if [ -e "$preauth_marker" ]; then
                log "    [ACTION] Deleting preauth marker: $preauth_marker"
                rm -f -- "$preauth_marker"
            fi
        fi
    done

    if [ "$COUNT_CRITICAL" -gt 0 ] || [ "$COUNT_WARNING" -gt 0 ]; then
        alert "CVE-2026-41940 INDICATORS OF COMPROMISE DETECTED"
        alert "  1. Purge all affected sessions: rm -f /var/cpanel/sessions/raw/*"
        alert "  2. Force password reset for root and all WHM users"
        alert "  3. Audit /var/log/wtmp and WHM access logs"
        alert "  4. Check for persistence: cron jobs, SSH keys, WHM hooks, backdoors"
    fi
}

if [ ! -d "$SESSIONS_DIR/raw" ]; then
    info "Session directory $SESSIONS_DIR/raw not found — skipping cPanel IOC session scan"
else
    scan_sessions
    print_cpanel_summary
fi

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 3 — ACCESS LOG EXPLOIT SIGNATURE CHECK
# ─────────────────────────────────────────────────────────────────────────────
log ""
log "============================================================================"
log " SECTION 3: CVE-2026-41940 — Access Log Exploit Signature Check"
log "============================================================================"

CPANEL_LOG="/usr/local/cpanel/logs/access_log"
if [ -f "$CPANEL_LOG" ]; then
    # CRLF injection signatures in Basic Auth header
    CRLF_HITS=$(grep -aicE "Authorization.*Basic.*DQo|%0d%0a" "$CPANEL_LOG" 2>/dev/null)
    if [ "$CRLF_HITS" -gt 0 ]; then
        alert "CRLF injection pattern detected in cPanel access log ($CRLF_HITS hits)"
        grep -aiE "Authorization.*Basic.*DQo|%0d%0a" "$CPANEL_LOG" | tail -20 | tee -a "$LOG_FILE"
    else
        ok "No CRLF injection patterns in cPanel access log"
    fi

    # 401 on /login followed by non-login Basic Auth (exploit chain pattern)
    EXPLOIT_CHAIN=$(grep -aE "POST /login/\?login_only=1.*401" "$CPANEL_LOG" 2>/dev/null | wc -l)
    if [ "$EXPLOIT_CHAIN" -gt 0 ]; then
        alert "Potential exploit chain: $EXPLOIT_CHAIN POST /login 401 hits (check for follow-up auth bypass)"
    else
        ok "No exploit chain pattern detected in access log"
    fi
else
    info "cPanel access log not found at $CPANEL_LOG"
fi

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 4 — POST-EXPLOITATION PERSISTENCE CHECKS
# ─────────────────────────────────────────────────────────────────────────────
log ""
log "============================================================================"
log " SECTION 4: Post-Exploitation Persistence Checks"
log "============================================================================"

log ""
log "--- Root SSH Authorized Keys ---"
if [ -f "/root/.ssh/authorized_keys" ]; then
    alert "Root authorized_keys exists — review for rogue keys:"
    cat /root/.ssh/authorized_keys | tee -a "$LOG_FILE"
else
    ok "No root authorized_keys file"
fi

log ""
log "--- WHM/cPanel User Accounts ---"
if [ -f "/etc/trueuserdomains" ]; then
    info "cPanel accounts on this server:"
    cut -d: -f2 /etc/trueuserdomains | sort -u | tee -a "$LOG_FILE"
fi

log ""
log "--- Crontabs ---"
info "Root crontab:"
crontab -l 2>/dev/null | tee -a "$LOG_FILE"
info "Cron spool:"
ls /var/spool/cron/ 2>/dev/null | tee -a "$LOG_FILE"
info "System cron.d:"
grep -h -v "^#\|^$" /etc/cron.d/* 2>/dev/null | tee -a "$LOG_FILE"

log ""
log "--- Recently Modified PHP Files (last 60 days) ---"
find /home /var/www /usr/local/apache/htdocs -name "*.php" \
    -newer /etc/passwd -ls 2>/dev/null | tee -a "$LOG_FILE"

log ""
log "--- Webshell Content Check ---"
WEBSHELL_HITS=$(find /home /var/www /usr/local/apache/htdocs -name "*.php" 2>/dev/null | \
    xargs grep -lE "eval\(base64_decode|shell_exec|passthru|assert\(\\\$_|preg_replace.*\/e" \
    2>/dev/null)
if [ -n "$WEBSHELL_HITS" ]; then
    alert "Potential webshell(s) detected:"
    echo "$WEBSHELL_HITS" | tee -a "$LOG_FILE"
else
    ok "No webshell signatures found in PHP files"
fi

log ""
log "--- Suspicious tmp/shm Files ---"
find /tmp /var/tmp /dev/shm -type f 2>/dev/null | tee -a "$LOG_FILE"

log ""
log "--- /root/.bashrc / .bash_profile Modifications ---"
ls -la /root/.bashrc /root/.bash_profile /root/.profile 2>/dev/null | tee -a "$LOG_FILE"
grep -v "^#\|^$" /root/.bashrc 2>/dev/null | tee -a "$LOG_FILE"

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 5 — CLAMAV SCAN
# ─────────────────────────────────────────────────────────────────────────────
log ""
log "============================================================================"
log " SECTION 5: ClamAV Malware Scan"
log "============================================================================"

if ! command -v clamscan &>/dev/null; then
    info "ClamAV not installed — installing..."
    if command -v yum &>/dev/null; then
        yum install -y clamav clamav-update 2>&1 | tee -a "$LOG_FILE"
    elif command -v apt-get &>/dev/null; then
        apt-get install -y clamav clamav-daemon 2>&1 | tee -a "$LOG_FILE"
    else
        alert "Could not install ClamAV — unknown package manager. Install manually."
    fi
fi

if command -v clamscan &>/dev/null; then
    log "Updating ClamAV signatures..."
    freshclam 2>&1 | tail -5 | tee -a "$LOG_FILE"

    log "Scanning web roots, home directories, tmp..."
    clamscan -r \
        --infected \
        --include-pua \
        --scan-ole2 \
        --scan-html \
        --scan-pdf \
        --scan-archive \
        --log="$LOG_DIR/${HOSTNAME}_clamav_${DATE}.log" \
        /home \
        /var/www \
        /tmp \
        /var/tmp \
        /dev/shm \
        /usr/local/apache/htdocs 2>&1 | tee -a "$LOG_FILE"

    INFECTED=$(grep "Infected files:" "$LOG_DIR/${HOSTNAME}_clamav_${DATE}.log" | awk '{print $NF}')
    if [ "$INFECTED" != "0" ] && [ -n "$INFECTED" ]; then
        alert "ClamAV found $INFECTED infected file(s) — see $LOG_DIR/${HOSTNAME}_clamav_${DATE}.log"
    else
        ok "ClamAV: 0 infected files"
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# FINAL SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
log ""
log "============================================================================"
log " SCAN COMPLETE"
log " Host    : $HOSTNAME"
log " Date    : $(date)"
log " Full log: $LOG_FILE"
log " Alerts  : $ALERT_FILE"
log "============================================================================"
log ""
log "=== ALERT SUMMARY ==="
if [ -s "$ALERT_FILE" ]; then
    cat "$ALERT_FILE" | tee -a "$LOG_FILE"
else
    log "No alerts raised — host appears clean"
fi

log ""
log "=== RECOMMENDED NEXT STEPS ==="
log "  1. If CVE-2026-41940 IOCs found:  rm -f /var/cpanel/sessions/raw/*"
log "  2. Force cPanel update:           /scripts/upcp --force"
log "  3. Restart cPanel service:        /scripts/restartsrv_cpsrvd"
log "  4. Rotate all passwords:          root, WHM users, cPanel accounts"
log "  5. Block ports if unpatched:      iptables -A INPUT -p tcp --dport 2083 -j DROP"
log "                                    iptables -A INPUT -p tcp --dport 2087 -j DROP"
log "  6. Review wtmp for rogue logins:  last -F | head -50"
log "============================================================================"
