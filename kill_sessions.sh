#!/usr/bin/env bash
# =============================================================================
# kill_sessions.sh - Drop all SSH sessions except your own and grey team
#
# Usage:
#   sudo ./kill_sessions.sh
#
# What it does:
#   1. Identifies your own active session so it is never touched
#   2. Identifies any GREYTEAM or grey team subnet sessions to preserve
#   3. Displays all active sessions and which will be kept vs killed
#   4. Prompts for confirmation before taking any action
#   5. Sends SIGHUP to the sshd child process for each target session,
#      which cleanly drops the connection
#
# Safety:
#   - Your own session is protected by SOURCE IP matching, not username.
#     If red team is using your username from their IP, their session is
#     killed while yours (from your IP) is kept.
#   - Console sessions (tty1, tty2, etc.) are explicitly skipped - only
#     pts (SSH) sessions are eligible for killing.
#   - GREYTEAM username is always preserved.
#   - Any session originating from the grey team subnet is always preserved.
#   - Confirmation prompt shows exactly what will be killed before acting.
# =============================================================================

set -euo pipefail

# =============================================================================
# !! CONFIGURATION - EDIT IF NEEDED !!
#
# Grey team subnet - any session whose source IP falls in this range will be preserved regardless of username.
# From the blue team packet topology: grey team is on 10.10.10.200/24
# =============================================================================
GREYTEAM_USER="GREYTEAM"
GREYTEAM_SUBNET="10.10.10.200"   # Used as a prefix match - see note below

# We match grey team IPs by prefix rather than full CIDR parsing to keep
# this pure bash with no dependencies. Adjust the prefix to match the
# actual grey team subnet if it differs from the packet.
# Example: "10.10.10." matches anything in 10.10.10.0/24
GREYTEAM_IP_PREFIX="10.10.10.2"  # Matches 10.10.10.200-10.10.10.254 range

# =============================================================================
# Helpers
# =============================================================================
info()    { echo "[*] $*"; }
success() { echo "[+] $*"; }
warn()    { echo "[!] $*" >&2; }
error()   { echo "[-] $*" >&2; }

# =============================================================================
# Preflight checks
# =============================================================================
if [[ "$(id -u)" -ne 0 ]]; then
    error "This script must be run as root"
    exit 1
fi

if ! command -v who &>/dev/null; then
    error "'who' is not available on this system"
    exit 1
fi

# =============================================================================
# Identify our own session
#
# MY_TTY - our current terminal device, stripped of /dev/ prefix.
#   If we are on a console (tty1, tty2, etc.) this will be ttyN.
#   If we are on SSH it will be pts/N.
#   Console sessions are skipped entirely - who only shows them without
#   a source IP, and pkill -t cannot safely target them.
#
# MY_IP - the source IP of our current SSH session, extracted from the
#   SSH_CONNECTION environment variable which sshd sets automatically.
#   Format: "client_ip client_port server_ip server_port"
#   We use this to protect our session by IP rather than username, so
#   even if red team is logged in as the same user we can still kill
#   their session without touching ours.
#   If MY_IP is empty we are on a console - no SSH session to protect.
# =============================================================================
MY_TTY=$(tty 2>/dev/null | sed 's|/dev/||')
MY_IP=$(echo "${SSH_CONNECTION:-}" | awk '{print $1}')

if [[ -n "$MY_IP" ]]; then
    info "Your current session: ${MY_TTY} from ${MY_IP}"
else
    info "Your current session: ${MY_TTY} (console - not an SSH session)"
fi
echo ""

# =============================================================================
# Parse active sessions from 'who'
#
# 'who' output format:
#   username   pts/0   2026-04-03 12:34  (10.10.10.50)
#
# Fields: $1=username $2=pts $3=date $4=time $5=source_ip
# The source IP is wrapped in parentheses - we strip those.
# =============================================================================

declare -a SESSION_USERS
declare -a SESSION_PTS
declare -a SESSION_IPS
declare -a SESSION_PIDS
declare -a SESSION_ACTION   # "KEEP" or "KILL"
declare -a SESSION_REASON

while IFS= read -r line; do
    # Skip blank lines
    [[ -z "$line" ]] && continue

    username=$(echo "$line" | awk '{print $1}')

    # Extract the pts/tty field by pattern rather than position
    pts=$(echo "$line" | grep -oP '(pts/\d+|tty\d+|seat\d*)' | head -1 || true)

    # Source IP is always the last field wrapped in parentheses
    source_raw=$(echo "$line" | grep -oP '\(\K[^)]+' || true)

    # source_raw already has parentheses stripped by the grep pattern above
    source_ip="${source_raw:-console}"

    # -- Skip console sessions entirely --
    # Console logins appear as tty1, tty2, etc. in who output.
    # They have no source IP and cannot be safely targeted by this script.
    # SSH sessions always appear as pts/N.
    if [[ "$pts" != pts/* ]]; then
        SESSION_USERS+=("$username")
        SESSION_PTS+=("$pts")
        SESSION_IPS+=("console")
        SESSION_PIDS+=("N/A")
        SESSION_ACTION+=("SKIP")
        SESSION_REASON+=("console session - never killed")
        continue
    fi

    # Find the sshd child process PID that owns this pts
    pts_pid=$(ps aux 2>/dev/null \
        | grep "sshd" \
        | grep -v grep \
        | awk -v p="$pts" '$0 ~ p {print $2}' \
        | head -1 || true)

    SESSION_USERS+=("$username")
    SESSION_PTS+=("$pts")
    SESSION_IPS+=("$source_ip")
    SESSION_PIDS+=("${pts_pid:-unknown}")

    # -- Determine action --

    # Is this our own session? Match by source IP, not username or pts.
    # This means if red team has a session as our user from their IP,
    # their session is killed. Our session from our IP is kept.
    if [[ -n "$MY_IP" ]] && [[ "$source_ip" == "$MY_IP" ]]; then
        SESSION_ACTION+=("KEEP")
        SESSION_REASON+=("your IP (${MY_IP})")
        continue
    fi

    # Fallback: if we have no MY_IP (shouldn't happen for SSH but just in case)
    # fall back to pts matching as a last resort
    if [[ -z "$MY_IP" ]] && [[ "$pts" == "$MY_TTY" ]]; then
        SESSION_ACTION+=("KEEP")
        SESSION_REASON+=("your pts (no IP available)")
        continue
    fi

    # Is this the GREYTEAM user?
    if [[ "$username" == "$GREYTEAM_USER" ]]; then
        SESSION_ACTION+=("KEEP")
        SESSION_REASON+=("GREYTEAM user")
        continue
    fi

    # Is this from the grey team subnet?
    if [[ "$source_ip" == ${GREYTEAM_IP_PREFIX}* ]]; then
        SESSION_ACTION+=("KEEP")
        SESSION_REASON+=("grey team subnet (${source_ip})")
        continue
    fi

    # Everything else gets killed
    SESSION_ACTION+=("KILL")
    SESSION_REASON+=("unauthorized session")

done < <(who)

# =============================================================================
# Display session table and prompt for confirmation
# =============================================================================
TOTAL=${#SESSION_USERS[@]}

if [[ "$TOTAL" -eq 0 ]]; then
    info "No active sessions found."
    exit 0
fi

echo "============================================================"
echo "  ACTIVE SSH SESSIONS"
echo "============================================================"
printf "  %-15s %-10s %-18s %-10s  %s\n" "USER" "PTS" "SOURCE IP" "ACTION" "REASON"
echo "  ------------------------------------------------------------"

KILL_COUNT=0
for i in "${!SESSION_USERS[@]}"; do
    printf "  %-15s %-10s %-18s %-10s  %s\n" \
        "${SESSION_USERS[$i]}" \
        "${SESSION_PTS[$i]}" \
        "${SESSION_IPS[$i]}" \
        "${SESSION_ACTION[$i]}" \
        "${SESSION_REASON[$i]}"
    if [[ "${SESSION_ACTION[$i]}" == "KILL" ]]; then
        (( KILL_COUNT++ )) || true
    fi
done

echo "============================================================"
echo ""

if [[ "$KILL_COUNT" -eq 0 ]]; then
    info "No sessions to kill - only your own and/or grey team sessions are active."
    exit 0
fi

warn "${KILL_COUNT} session(s) will be dropped."
warn "If grey team is mid-scoring-check, this may cost points."
echo ""
read -r -p "  Proceed? Type YES to confirm: " CONFIRM
echo ""

if [[ "$CONFIRM" != "YES" ]]; then
    info "Aborted - no sessions were killed."
    exit 0
fi

# =============================================================================
# Kill target sessions
#
# We send SIGHUP to the sshd child process that owns the session.
# SIGHUP is the standard signal for hangup - it's what happens when a
# terminal is closed naturally. It's cleaner than SIGKILL and gives the
# shell a chance to clean up.
#
# If we can't find the sshd PID for a session, we fall back to pkill
# on the pts as a secondary method.
# =============================================================================
echo ""
info "Dropping sessions..."
echo ""

KILLED=0
FAILED=0

for i in "${!SESSION_USERS[@]}"; do
    [[ "${SESSION_ACTION[$i]}" != "KILL" ]] && continue

    username="${SESSION_USERS[$i]}"
    pts="${SESSION_PTS[$i]}"
    pid="${SESSION_PIDS[$i]}"

    info "Dropping: ${username} on ${pts} (source: ${SESSION_IPS[$i]})"

    if [[ "$pid" != "unknown" ]] && kill -HUP "$pid" 2>/dev/null; then
        success "  Sent SIGHUP to sshd PID ${pid} - session dropped"
        (( KILLED++ )) || true
    else
        # Fallback - kill any process using this pts
        warn "  Could not find sshd PID - attempting fallback via pts..."
        if pkill -HUP -t "/dev/$pts" 2>/dev/null; then
            success "  Session dropped via pts fallback"
            (( KILLED++ )) || true
        else
            error "  Failed to drop session for ${username} on ${pts} - manual kill may be needed"
            error "  Try: ps aux | grep sshd | grep ${pts}"
            (( FAILED++ )) || true
        fi
    fi
done

# =============================================================================
# Summary
# =============================================================================
echo ""
info "========================================="
info "Session Kill Summary"
info "  Dropped:  ${KILLED}"
info "  Failed:   ${FAILED}"
info "========================================="

if [[ "$FAILED" -gt 0 ]]; then
    warn "Some sessions could not be dropped automatically."
    warn "For manual cleanup: ps aux | grep sshd"
    warn "Then: kill -HUP <pid>"
fi