#!/usr/bin/env bash
# =============================================================================
# proc_monitor.sh - Flag suspicious or unexpected running processes
#
# Usage:
#   sudo ./proc_monitor.sh            # single snapshot
#   sudo ./proc_monitor.sh --watch    # repeat every 30 seconds
#
# What it does:
#   - Snapshots all running processes
#   - Flags processes running from unusual locations
#   - Flags processes with suspicious command line patterns
#   - Flags processes owned by unexpected users
#   - Flags network-connected processes
#   - In --watch mode, highlights NEW processes since last snapshot
#
# This script makes NO changes to the system.
# =============================================================================

set -euo pipefail

WATCH_MODE=false
WATCH_INTERVAL=30
[[ "${1:-}" == "--watch" ]] && WATCH_MODE=true

# =============================================================================
# Known legitimate process owners
# Processes owned by users not in this list will be flagged
# =============================================================================
LEGITIMATE_USERS=(
    # Standard system accounts
    "root"
    "daemon"
    "nobody"
    "systemd"
    "systemd-timesync"
    "systemd-network"
    "systemd-resolve"
    "messagebus"
    "syslog"
    "avahi"
    "polkitd"
    "rtkit"
    "colord"
    "usbmux"
    "kernoops"
    "whoopsie"
    "speech-dispatcher"
    "fwupd-refresh"
    # Service accounts
    "www-data"
    "mysql"
    "postgres"
    # Competition accounts
    "cyberrange"
    "GREYTEAM"
    "scp343"
)

# =============================================================================
# Suspicious command patterns to flag regardless of owner
# These patterns match common reverse shell and persistence techniques
# =============================================================================
SUSPICIOUS_PATTERNS=(
    '/dev/tcp'
    '/dev/udp'
    'bash -i'
    'bash -c.*exec'
    'python.*socket'
    'python.*pty'
    'nc -'
    'ncat '
    'socat '
    'base64 -d'
    'curl.*sh'
    'wget.*sh'
    'mkfifo'
    'LD_PRELOAD'
    '/tmp/\.'          # hidden files in /tmp
    '/var/tmp/\.'      # hidden files in /var/tmp
)

# =============================================================================
# Known legitimate binary locations
# Processes running from outside these paths are suspicious
# =============================================================================
LEGITIMATE_PATHS=(
    "/usr/bin/"
    "/usr/sbin/"
    "/usr/lib/"
    "/usr/libexec/"      # Debian 13 moved many daemons here
    "/lib/"
    "/bin/"
    "/sbin/"
    "/usr/local/bin/"
    "/usr/local/sbin/"
    "/usr/local/lib/"
    "/usr/share/"
    "/var/www/"
    "/opt/"
    "/run/user/"         # User runtime daemons (dbus session, etc.)
)

# =============================================================================
# Helpers
# =============================================================================
RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

crit()   { echo -e "${RED}${BOLD}[SUSPICIOUS]${RESET} $*"; }
warn()   { echo -e "${YELLOW}[REVIEW]${RESET}    $*"; }
ok()     { echo -e "${GREEN}[OK]${RESET}        $*"; }
info()   { echo -e "${CYAN}[INFO]${RESET}      $*"; }
header() { echo -e "\n${BOLD}=== $* ===${RESET}"; }

if [[ "$(id -u)" -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

# Build legitimate user lookup set
declare -A LEGIT_USER_SET
for u in "${LEGITIMATE_USERS[@]}"; do
    LEGIT_USER_SET["$u"]=1
done

# =============================================================================
# Core snapshot and analysis function
# =============================================================================
PREV_PIDS_FILE="/tmp/.proc_monitor_prev_pids"

run_snapshot() {
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    echo ""
    echo -e "${BOLD}PROCESS SNAPSHOT - ${timestamp}${RESET}"
    echo "Hostname: $(hostname)"
    echo ""

    # Collect current PIDs for watch mode diff
    declare -A CURRENT_PIDS
    NEW_PROCESS_COUNT=0
    SUSPICIOUS_COUNT=0
    REVIEW_COUNT=0

    header "Network-Connected Processes"

    # Find all PIDs with network connections first
    declare -A NET_PIDS
    while IFS= read -r line; do
        pid=$(echo "$line" | awk '{print $7}' | grep -o '[0-9]*' | head -1)
        [[ -n "$pid" ]] && NET_PIDS["$pid"]=1
    done < <(ss -tnpu 2>/dev/null | grep -v '^Netid' || true)

    if [[ "${#NET_PIDS[@]}" -eq 0 ]]; then
        ok "No processes with network connections"
    else
        for pid in "${!NET_PIDS[@]}"; do
            [[ -d "/proc/$pid" ]] || continue
            cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || echo "unknown")
            owner=$(stat -c '%U' "/proc/$pid" 2>/dev/null || echo "unknown")
            conn=$(ss -tnpu 2>/dev/null | grep "pid=${pid}" | \
                awk '{print $5 " -> " $6}' | head -3 | tr '\n' ' ')
            # Only flag as suspicious if owner is unknown
            if [[ -z "${LEGIT_USER_SET[$owner]+_}" ]]; then
                crit "PID ${pid} [${owner}] UNKNOWN OWNER with network: ${cmd:0:80}"
                echo "       Connections: ${conn}"
            else
                info "PID ${pid} [${owner}]: ${cmd:0:60}"
                echo "       Connections: ${conn}"
            fi
        done
    fi

    header "Processes by Owner"

    # Walk /proc for all processes
    while IFS= read -r -d '' proc_dir; do
        pid=$(basename "$proc_dir")
        [[ "$pid" =~ ^[0-9]+$ ]] || continue
        [[ -f "${proc_dir}/cmdline" ]] || continue

        cmd=$(tr '\0' ' ' < "${proc_dir}/cmdline" 2>/dev/null | xargs 2>/dev/null || true)
        [[ -z "$cmd" ]] && continue  # skip kernel threads

        owner=$(stat -c '%U' "$proc_dir" 2>/dev/null || echo "unknown")
        exe=$(readlink -f "${proc_dir}/exe" 2>/dev/null || echo "unknown")

        CURRENT_PIDS["$pid"]=1

        # -- Check 1: unexpected owner --
        # Only flag if the owner is completely unknown to us.
        # Known users (even non-root) running normal processes are fine -
        # the path check below will catch if they're running from odd locations.
        if [[ -z "${LEGIT_USER_SET[$owner]+_}" ]]; then
            crit "PID ${pid} owned by UNKNOWN user '${owner}': ${cmd:0:80}"
            (( SUSPICIOUS_COUNT++ )) || true
            continue
        fi

        # -- Check 2: suspicious command patterns --
        PATTERN_HIT=false
        for pattern in "${SUSPICIOUS_PATTERNS[@]}"; do
            if echo "$cmd" | grep -qP "$pattern" 2>/dev/null; then
                crit "PID ${pid} [${owner}] matches suspicious pattern '${pattern}':"
                echo "       CMD: ${cmd:0:100}"
                PATTERN_HIT=true
                (( SUSPICIOUS_COUNT++ )) || true
                break
            fi
        done
        $PATTERN_HIT && continue

        # -- Check 3: running from unexpected location --
        if [[ "$exe" != "unknown" ]]; then
            PATH_OK=false
            for legit_path in "${LEGITIMATE_PATHS[@]}"; do
                if [[ "$exe" == "${legit_path}"* ]]; then
                    PATH_OK=true
                    break
                fi
            done
            if ! $PATH_OK; then
                warn "PID ${pid} [${owner}] running from unusual path: ${exe}"
                echo "       CMD: ${cmd:0:80}"
                (( REVIEW_COUNT++ )) || true
            fi
        fi

    done < <(find /proc -maxdepth 1 -name '[0-9]*' -print0 2>/dev/null)

    # -- Watch mode: detect new processes since last snapshot --
    if $WATCH_MODE && [[ -f "$PREV_PIDS_FILE" ]]; then
        header "New Processes Since Last Snapshot"
        while IFS= read -r prev_pid; do
            true  # just reading
        done < "$PREV_PIDS_FILE"

        NEW_FOUND=false
        for pid in "${!CURRENT_PIDS[@]}"; do
            if ! grep -q "^${pid}$" "$PREV_PIDS_FILE" 2>/dev/null; then
                [[ -d "/proc/$pid" ]] || continue
                cmd=$(tr '\0' ' ' < "/proc/${pid}/cmdline" 2>/dev/null || true)
                [[ -z "$cmd" ]] && continue
                owner=$(stat -c '%U' "/proc/$pid" 2>/dev/null || echo "unknown")
                warn "NEW PID ${pid} [${owner}]: ${cmd:0:80}"
                NEW_FOUND=true
                (( NEW_PROCESS_COUNT++ )) || true
            fi
        done
        $NEW_FOUND || ok "No new processes since last snapshot"
    fi

    # Save current PIDs for next watch iteration
    printf '%s\n' "${!CURRENT_PIDS[@]}" > "$PREV_PIDS_FILE"

    # Summary
    header "Snapshot Summary"
    echo "  Total processes:      $(ps aux --no-headers | wc -l)"
    echo "  Suspicious (action):  ${SUSPICIOUS_COUNT}"
    echo "  Review recommended:   ${REVIEW_COUNT}"
    $WATCH_MODE && echo "  New since last snap:  ${NEW_PROCESS_COUNT}"
    echo ""

    if [[ "$SUSPICIOUS_COUNT" -gt 0 ]]; then
        echo -e "${RED}${BOLD}ACTION REQUIRED: ${SUSPICIOUS_COUNT} suspicious process(es) found${RESET}"
        echo "  Kill a process:       kill -9 <pid>"
        echo "  Kill by user:         pkill -9 -u <username>"
        echo "  Investigate:          ls -la /proc/<pid>/fd"
        echo "                        cat /proc/<pid>/environ | tr '\\0' '\\n'"
    fi
}

# =============================================================================
# Main - single run or watch loop
# =============================================================================
if $WATCH_MODE; then
    echo -e "${BOLD}PROCESS MONITOR - Watch Mode (interval: ${WATCH_INTERVAL}s)${RESET}"
    echo "Press Ctrl+C to stop"
    trap 'rm -f "$PREV_PIDS_FILE"; echo ""; echo "Monitor stopped."; exit 0' INT TERM

    while true; do
        run_snapshot
        echo "Next snapshot in ${WATCH_INTERVAL} seconds..."
        sleep "$WATCH_INTERVAL"
    done
else
    run_snapshot
fi