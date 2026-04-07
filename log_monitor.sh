#!/usr/bin/env bash
# =============================================================================
# log_monitor.sh - Highlight suspicious authentication and network events
#
# Usage:
#   sudo ./log_monitor.sh             # analyze last 60 minutes
#   sudo ./log_monitor.sh --since 2h  # analyze last 2 hours
#   sudo ./log_monitor.sh --follow    # tail logs in real time
#
# What it does:
#   - Parses auth logs for failed logins, SSH events, sudo usage
#   - Parses UFW logs for blocked connections
#   - Parses Apache logs for suspicious requests
#   - Parses syslog for suspicious system events
#   - In --follow mode, tails all relevant logs simultaneously
#
# This script makes NO changes to the system.
# =============================================================================

set -euo pipefail

# =============================================================================
# Argument parsing
# =============================================================================
SINCE="60 minutes ago"
FOLLOW_MODE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --since)
            SINCE="${2} ago"
            shift 2
            ;;
        --follow)
            FOLLOW_MODE=true
            shift
            ;;
        *)
            shift
            ;;
    esac
done

# =============================================================================
# Helpers
# =============================================================================
RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

crit()   { echo -e "${RED}${BOLD}[ALERT]${RESET}   $*"; }
warn()   { echo -e "${YELLOW}[WARN]${RESET}    $*"; }
ok()     { echo -e "${GREEN}[OK]${RESET}      $*"; }
info()   { echo -e "${CYAN}[INFO]${RESET}    $*"; }
header() { echo -e "\n${BOLD}=== $* ===${RESET}"; }

if [[ "$(id -u)" -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

# =============================================================================
# Follow mode - real-time log tailing
# =============================================================================
if $FOLLOW_MODE; then
    echo -e "${BOLD}LOG MONITOR - Follow Mode${RESET}"
    echo "Tailing all relevant logs. Press Ctrl+C to stop."
    echo ""

    # Collect log files to tail
    TAIL_FILES=()

    # journald via journalctl is preferred on systemd systems
    # We use multitail-style approach with labeled output

    # Auth events
    if journalctl --since "1 minute ago" -u ssh &>/dev/null; then
        # systemd system - use journalctl
        echo "Using journalctl (systemd detected)"
        echo ""
        journalctl -f -n 50 \
            -u ssh \
            -u apache2 \
            -u mysql \
            -u mariadb \
            -u ufw \
            --output=short-iso 2>/dev/null | while IFS= read -r line; do
            # Color code by content
            if echo "$line" | grep -qiP 'fail|invalid|error|denied|refused|breach'; then
                echo -e "${RED}${line}${RESET}"
            elif echo "$line" | grep -qiP 'accept|success|opened|started'; then
                echo -e "${GREEN}${line}${RESET}"
            elif echo "$line" | grep -qiP 'warn|block|drop'; then
                echo -e "${YELLOW}${line}${RESET}"
            else
                echo "$line"
            fi
        done
    else
        # Fall back to file tailing
        for f in /var/log/auth.log /var/log/syslog /var/log/apache2/access.log \
                  /var/log/apache2/error.log /var/log/ufw.log; do
            [[ -f "$f" ]] && TAIL_FILES+=("$f")
        done

        if [[ "${#TAIL_FILES[@]}" -eq 0 ]]; then
            echo "No log files found to tail"
            exit 1
        fi

        tail -f "${TAIL_FILES[@]}" | while IFS= read -r line; do
            if echo "$line" | grep -qiP 'fail|invalid|error|denied|refused'; then
                echo -e "${RED}${line}${RESET}"
            elif echo "$line" | grep -qiP 'accept|success|opened'; then
                echo -e "${GREEN}${line}${RESET}"
            elif echo "$line" | grep -qiP 'warn|block|drop'; then
                echo -e "${YELLOW}${line}${RESET}"
            else
                echo "$line"
            fi
        done
    fi
    exit 0
fi

# =============================================================================
# Snapshot analysis mode
# =============================================================================
echo ""
echo -e "${BOLD}LOG ANALYSIS REPORT${RESET}"
echo "Generated: $(date)"
echo "Analyzing: last ${SINCE}"
echo ""

# Helper to query journald or fall back to grep on log files
query_journal() {
    local unit="$1"
    local pattern="$2"
    local since_arg="--since=${SINCE}"

    if journalctl "$since_arg" -u "$unit" &>/dev/null 2>&1; then
        journalctl "$since_arg" -u "$unit" --no-pager -q 2>/dev/null \
            | grep -iP "$pattern" || true
    fi
}

query_file() {
    local file="$1"
    local pattern="$2"
    [[ -f "$file" ]] || return 0
    grep -iP "$pattern" "$file" 2>/dev/null | tail -100 || true
}

# =============================================================================
# Section 1 - SSH Authentication Events
# =============================================================================
header "SSH AUTHENTICATION"

# Failed logins
info "Failed SSH login attempts:"
FAILED_SSH=$(
    { journalctl --since="${SINCE}" -u ssh --no-pager -q 2>/dev/null || true; \
      query_file /var/log/auth.log "ssh"; } \
    | grep -iP "failed|invalid|authentication failure" || true
)

if [[ -n "$FAILED_SSH" ]]; then
    # Count and group by IP
    echo "$FAILED_SSH" | \
        grep -oP 'from \K[\d.]+' 2>/dev/null | \
        sort | uniq -c | sort -rn | \
        while read -r count ip; do
            if [[ "$count" -gt 10 ]]; then
                crit "${count} failed attempts from ${ip}"
            elif [[ "$count" -gt 3 ]]; then
                warn "${count} failed attempts from ${ip}"
            else
                info "${count} failed attempt(s) from ${ip}"
            fi
        done
    echo ""
    info "Last 10 failed attempts:"
    echo "$FAILED_SSH" | tail -10 | sed 's/^/    /'
else
    ok "No failed SSH attempts in this period"
fi

echo ""

# Successful logins
info "Successful SSH logins:"
SUCCESS_SSH=$(
    { journalctl --since="${SINCE}" -u ssh --no-pager -q 2>/dev/null || true; \
      query_file /var/log/auth.log "ssh"; } \
    | grep -iP "accepted|session opened for user" || true
)

if [[ -n "$SUCCESS_SSH" ]]; then
    echo "$SUCCESS_SSH" | while IFS= read -r line; do
        # Flag logins for unexpected users
        if echo "$line" | grep -qvP "cyberrange|GREYTEAM|root"; then
            crit "Login for unexpected user: ${line}"
        else
            warn "${line}"
        fi
    done
else
    ok "No successful SSH logins in this period"
fi

echo ""

# New SSH keys added
info "Checking for recent authorized_keys modifications..."
while IFS=: read -r user _ uid _ _ home _; do
    [[ "$uid" -lt 1000 ]] && [[ "$user" != "root" ]] && continue
    [[ "$uid" -eq 65534 ]] && continue
    auth_file="${home}/.ssh/authorized_keys"
    [[ -f "$auth_file" ]] || continue
    modified_mins=$(( ( $(date +%s) - $(stat -c %Y "$auth_file") ) / 60 ))
    if [[ "$modified_mins" -lt 120 ]]; then
        crit "${auth_file} modified ${modified_mins} minute(s) ago - check for injected keys"
    fi
done < /etc/passwd

# =============================================================================
# Section 2 - Sudo Usage
# =============================================================================
header "SUDO USAGE"

SUDO_LOG=""

# Check dedicated sudo log first (set by our harden_sudo.sh)
if [[ -f /var/log/sudo.log ]]; then
    SUDO_LOG=$(tail -200 /var/log/sudo.log 2>/dev/null || true)
    info "Source: /var/log/sudo.log"
else
    SUDO_LOG=$(
        { journalctl --since="${SINCE}" --no-pager -q 2>/dev/null || true; \
          query_file /var/log/auth.log "sudo"; } \
        | grep -iP "sudo" || true
    )
    info "Source: journald/auth.log (sudo.log not found - run harden_sudo.sh)"
fi

if [[ -n "$SUDO_LOG" ]]; then
    # Flag sudo by unexpected users
    echo "$SUDO_LOG" | while IFS= read -r line; do
        if echo "$line" | grep -qvP "cyberrange|GREYTEAM|root"; then
            crit "Sudo by unexpected user: ${line}"
        else
            info "${line}"
        fi
    done
else
    ok "No sudo activity in this period"
fi

# =============================================================================
# Section 3 - User Account Changes
# =============================================================================
header "USER ACCOUNT CHANGES"

USERADD_EVENTS=$(
    { journalctl --since="${SINCE}" --no-pager -q 2>/dev/null || true; \
      query_file /var/log/auth.log "useradd\|userdel\|usermod\|groupadd"; } \
    | grep -iP "useradd|userdel|usermod|groupadd|new user|new group" || true
)

if [[ -n "$USERADD_EVENTS" ]]; then
    crit "User/group account changes detected:"
    echo "$USERADD_EVENTS" | sed 's/^/    /'
else
    ok "No user account changes detected"
fi

# =============================================================================
# Section 4 - UFW / Firewall Events
# =============================================================================
header "FIREWALL EVENTS"

if command -v ufw &>/dev/null && ufw status | grep -q "active"; then
    info "UFW blocked connection summary (top source IPs):"

    UFW_BLOCKS=$(
        { journalctl --since="${SINCE}" -u ufw --no-pager -q 2>/dev/null || true; \
          query_file /var/log/ufw.log ""; } \
        | grep -i "BLOCK\|DROP" || true
    )

    if [[ -n "$UFW_BLOCKS" ]]; then
        echo "$UFW_BLOCKS" | \
            grep -oP 'SRC=\K[\d.]+' 2>/dev/null | \
            sort | uniq -c | sort -rn | head -20 | \
            while read -r count ip; do
                if [[ "$count" -gt 50 ]]; then
                    crit "${count} blocked packets from ${ip}"
                elif [[ "$count" -gt 10 ]]; then
                    warn "${count} blocked packets from ${ip}"
                else
                    info "${count} blocked packet(s) from ${ip}"
                fi
            done

        echo ""
        info "Blocked outbound connections (potential callback attempts):"
        echo "$UFW_BLOCKS" | grep "OUT=" | \
            grep -oP 'DST=\K[\d.]+ DPT=\K[\d]+' 2>/dev/null | \
            sort | uniq -c | sort -rn | head -10 | \
            while read -r count dest; do
                warn "${count} blocked outbound to ${dest}"
            done || true
    else
        ok "No UFW block events in this period"
    fi
else
    warn "UFW is not active - no firewall log available"
fi

# =============================================================================
# Section 5 - Apache Access Log
# =============================================================================
header "APACHE ACCESS LOG"

APACHE_ACCESS="/var/log/apache2/access.log"
APACHE_ERROR="/var/log/apache2/error.log"

if [[ -f "$APACHE_ACCESS" ]]; then
    info "Top requesting IPs:"
    tail -5000 "$APACHE_ACCESS" 2>/dev/null | \
        awk '{print $1}' | sort | uniq -c | sort -rn | head -10 | \
        while read -r count ip; do
            echo "    ${count} requests from ${ip}"
        done

    echo ""
    info "Suspicious request patterns (scanners, path traversal, shells):"
    SUSPICIOUS_REQUESTS=$(tail -5000 "$APACHE_ACCESS" 2>/dev/null | \
        grep -iP '\.\./|cmd=|exec\(|eval\(|union.*select|<script|wget|curl|/etc/passwd|/bin/sh|/bin/bash|\.php\?.*=http|wp-admin|xmlrpc|server-status|server-info' \
        2>/dev/null || true)

    if [[ -n "$SUSPICIOUS_REQUESTS" ]]; then
        crit "Suspicious HTTP requests detected:"
        echo "$SUSPICIOUS_REQUESTS" | tail -20 | sed 's/^/    /'
    else
        ok "No obviously suspicious HTTP requests found"
    fi

    echo ""
    info "HTTP error rate (4xx/5xx):"
    total=$(tail -5000 "$APACHE_ACCESS" 2>/dev/null | wc -l)
    errors=$(tail -5000 "$APACHE_ACCESS" 2>/dev/null | \
        awk '$9 ~ /^[45]/' | wc -l || true)
    if [[ "$total" -gt 0 ]]; then
        pct=$(( errors * 100 / total ))
        if [[ "$pct" -gt 20 ]]; then
            warn "High error rate: ${errors}/${total} requests (${pct}%) are 4xx/5xx"
        else
            ok "Error rate: ${errors}/${total} requests (${pct}%) are 4xx/5xx"
        fi
    fi
else
    info "Apache access log not found at ${APACHE_ACCESS}"
fi

if [[ -f "$APACHE_ERROR" ]]; then
    echo ""
    info "Recent Apache errors:"
    tail -20 "$APACHE_ERROR" 2>/dev/null | sed 's/^/    /'
fi

# =============================================================================
# Section 6 - System Events (syslog / journald)
# =============================================================================
header "SYSTEM EVENTS"

info "Recent high-severity system messages:"
journalctl --since="${SINCE}" -p err..emerg --no-pager -q 2>/dev/null \
    | tail -20 \
    | while IFS= read -r line; do
        warn "${line}"
    done || query_file /var/log/syslog "err|crit|alert|emerg" | tail -20 | \
    while IFS= read -r line; do
        warn "${line}"
    done || ok "No high-severity system messages"

# =============================================================================
# Summary
# =============================================================================
header "ANALYSIS COMPLETE"
echo ""
info "Useful follow-up commands:"
echo "  Live log follow:         sudo ./log_monitor.sh --follow"
echo "  Last 2 hours:            sudo ./log_monitor.sh --since 2h"
echo "  SSH log detail:          journalctl -u ssh --since '1 hour ago'"
echo "  Block an IP in UFW:      ufw deny from <IP>"
echo "  View UFW drops live:     journalctl -fu ufw | grep BLOCK"
echo "  Apache last 100 lines:   tail -100 /var/log/apache2/access.log"
echo ""