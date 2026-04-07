#!/usr/bin/env bash
# =============================================================================
# triage.sh - Rapid situational awareness for competition day
#
# Usage:
#   sudo ./triage.sh [--full]
#
# What it does:
#   Runs a series of read-only checks and produces a prioritized report
#   covering the most likely areas of compromise. Output is color-coded
#   by severity so you can immediately see where action is needed.
#
#   Default mode: fast checks only (~10-15 seconds)
#   --full mode:  includes filesystem scans which take longer (~60 seconds)
#
# This script makes NO changes to the system.
# =============================================================================

set -euo pipefail

FULL_SCAN=false
[[ "${1:-}" == "--full" ]] && FULL_SCAN=true

# =============================================================================
# Output helpers - color coded by severity
# =============================================================================
RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

crit()    { echo -e "${RED}${BOLD}[CRITICAL]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[WARNING]${RESET}  $*"; }
ok()      { echo -e "${GREEN}[OK]${RESET}       $*"; }
info()    { echo -e "${CYAN}[INFO]${RESET}     $*"; }
header()  { echo -e "\n${BOLD}========================================${RESET}"; \
            echo -e "${BOLD} $*${RESET}"; \
            echo -e "${BOLD}========================================${RESET}"; }

if [[ "$(id -u)" -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

echo ""
echo -e "${BOLD}SYSTEM TRIAGE REPORT${RESET}"
echo "Generated: $(date)"
echo "Hostname:  $(hostname)"
echo "Uptime:    $(uptime -p)"
$FULL_SCAN && echo "Mode:      FULL SCAN" || echo "Mode:      FAST (run with --full for filesystem scans)"

# =============================================================================
# Section 1 - User Accounts
# =============================================================================
header "1. USER ACCOUNTS"

# UID 0 accounts other than root
uid0=$(awk -F: '$3==0 && $1!="root" {print $1}' /etc/passwd)
if [[ -n "$uid0" ]]; then
    crit "Non-root accounts with UID 0: ${uid0}"
else
    ok "No non-root UID 0 accounts"
fi

# Human accounts (UID >= 1000, not nobody)
info "Local human accounts (UID >= 1000):"
while IFS=: read -r user _ uid _ _ home shell; do
    [[ "$uid" -lt 1000 ]] && continue
    [[ "$uid" -eq 65534 ]] && continue
    locked=""
    passwd_status=$(passwd -S "$user" 2>/dev/null | awk '{print $2}')
    [[ "$passwd_status" == "L" ]] && locked=" [LOCKED]"
    echo "    ${user} (uid=${uid}, home=${home}, shell=${shell})${locked}"
done < /etc/passwd

# Accounts with genuinely empty passwords (not locked - locked is fine)
# Empty password field means anyone can log in as that user with no password
echo ""
info "Checking for accounts with empty passwords..."
no_pw=$(awk -F: '$2=="" {print $1}' /etc/shadow 2>/dev/null || true)
if [[ -n "$no_pw" ]]; then
    crit "Accounts with EMPTY password (no auth required): ${no_pw}"
else
    ok "No accounts with empty passwords"
fi

# Recently modified passwd/shadow
echo ""
info "Checking age of /etc/passwd and /etc/shadow..."
for f in /etc/passwd /etc/shadow; do
    age_mins=$(( ( $(date +%s) - $(stat -c %Y "$f") ) / 60 ))
    if [[ "$age_mins" -lt 60 ]]; then
        warn "${f} was modified ${age_mins} minute(s) ago"
    else
        ok "${f} last modified ${age_mins} minutes ago"
    fi
done

# =============================================================================
# Section 2 - SSH & Authorized Keys
# =============================================================================
header "2. SSH & AUTHORIZED KEYS"

# authorized_keys audit across all users
AUTH_KEY_COUNT=0
while IFS=: read -r user _ uid _ _ home _; do
    [[ "$uid" -lt 1000 ]] && [[ "$user" != "root" ]] && continue
    [[ "$uid" -eq 65534 ]] && continue
    auth_file="${home}/.ssh/authorized_keys"
    [[ -f "$auth_file" ]] || continue
    key_count=$(grep -vc '^\s*#\|^\s*$' "$auth_file" 2>/dev/null || true)
    if [[ "$key_count" -gt 0 ]]; then
        warn "${auth_file} contains ${key_count} key(s):"
        grep -v '^\s*#\|^\s*$' "$auth_file" | while IFS= read -r key; do
            echo "    ${key:0:100}..."
        done
        (( AUTH_KEY_COUNT += key_count )) || true
    fi
done < /etc/passwd

[[ "$AUTH_KEY_COUNT" -eq 0 ]] && ok "No authorized_keys files found"

# SSH config check
echo ""
info "Key SSH config settings:"
sshd_conf="/etc/ssh/sshd_config"
dropin_dir="/etc/ssh/sshd_config.d"

check_ssh_setting() {
    local setting="$1"
    local expected="$2"
    local actual
    # Check drop-ins first (they take precedence), then main config
    actual=$(grep -rhi "^\s*${setting}\s" "$dropin_dir"/ "$sshd_conf" 2>/dev/null \
        | head -1 | awk '{print $2}')
    if [[ -z "$actual" ]]; then
        warn "${setting}: not explicitly set (using default)"
    elif [[ "${actual,,}" == "${expected,,}" ]]; then
        ok "${setting}: ${actual}"
    else
        warn "${setting}: ${actual} (expected: ${expected})"
    fi
}

check_ssh_setting "PermitRootLogin"        "no"
check_ssh_setting "PasswordAuthentication" "yes"
check_ssh_setting "PermitEmptyPasswords"   "no"
check_ssh_setting "AllowUsers"             "(set)"

# Active SSH sessions
echo ""
info "Active SSH sessions:"
who | while IFS= read -r line; do
    echo "    ${line}"
done
[[ -z "$(who)" ]] && echo "    (none)"

# =============================================================================
# Section 3 - ld.so.preload
# =============================================================================
header "3. LD.SO.PRELOAD (HIGH VALUE PERSISTENCE VECTOR)"

if [[ ! -f /etc/ld.so.preload ]]; then
    ok "/etc/ld.so.preload does not exist - clean"
elif [[ ! -s /etc/ld.so.preload ]]; then
    ok "/etc/ld.so.preload exists but is empty - clean"
else
    crit "/etc/ld.so.preload EXISTS and contains:"
    cat /etc/ld.so.preload
    echo ""
    crit "This is a system-wide persistence mechanism - clear immediately"
    echo "    To clear: > /etc/ld.so.preload"
fi

# =============================================================================
# Section 4 - Cron & Scheduled Tasks
#
# Strategy: scan ALL cron files for suspicious content regardless of filename.
# Known system cron files that are clean are noted but not fully printed.
# Non-system files are always fully printed.
# Any file containing suspicious patterns is always flagged with the
# specific matching lines shown - a poisoned system cron file will still
# be caught even if its filename looks legitimate.
# =============================================================================
header "4. CRON & SCHEDULED TASKS"

# Known Debian system cron files - these are checked for suspicious content
# but not fully printed if clean. A poisoned version will still be flagged.
SYSTEM_CRON_FILES=(
    "/etc/crontab"
    "/etc/cron.d/e2scrub_all"
    "/etc/cron.d/anacron"
    "/etc/cron.daily/dpkg"
    "/etc/cron.daily/man-db"
    "/etc/cron.daily/0anacron"
    "/etc/cron.daily/apt-compat"
    "/etc/cron.daily/logrotate"
    "/etc/cron.weekly/man-db"
    "/etc/cron.weekly/0anacron"
    "/etc/cron.monthly/0anacron"
)

declare -A SYSTEM_CRON_SET
for f in "${SYSTEM_CRON_FILES[@]}"; do
    SYSTEM_CRON_SET["$f"]=1
done

# Suspicious patterns to flag in any cron file regardless of source
CRON_SUSPICIOUS_PATTERN='\/dev\/tcp|\/dev\/udp|bash\s+-i|nc\s+-|ncat\s|socat\s|python.*socket|curl\s.*\|\s*bash|wget\s.*\|\s*bash|base64\s+-d|mkfifo|\/tmp\/\.|\/var\/tmp\/\.'

CRON_HITS=0
SYSTEM_CRON_CLEAN=0

# Collect all cron file locations to scan
ALL_CRON_FILES=()
for loc in /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily \
           /etc/cron.weekly /etc/cron.monthly /var/spool/cron/crontabs; do
    [[ -e "$loc" ]] || continue
    if [[ -f "$loc" ]]; then
        ALL_CRON_FILES+=("$loc")
    elif [[ -d "$loc" ]]; then
        while IFS= read -r -d '' f; do
            ALL_CRON_FILES+=("$f")
        done < <(find "$loc" -maxdepth 1 -type f -print0 2>/dev/null)
    fi
done

for f in "${ALL_CRON_FILES[@]}"; do
    is_system=false
    [[ -n "${SYSTEM_CRON_SET[$f]+_}" ]] && is_system=true

    # Always scan for suspicious patterns regardless of file origin
    suspicious_lines=$(grep -nP "$CRON_SUSPICIOUS_PATTERN" "$f" 2>/dev/null || true)

    if [[ -n "$suspicious_lines" ]]; then
        crit "SUSPICIOUS content in cron file ${f}:"
        echo "$suspicious_lines" | sed 's/^/    /'
        (( CRON_HITS++ )) || true
    elif $is_system; then
        # System file with no suspicious content - just note it's clean
        (( SYSTEM_CRON_CLEAN++ )) || true
    else
        # Non-system file - show full contents even if not suspicious
        content=$(grep -v '^\s*#\|^\s*$' "$f" 2>/dev/null || true)
        if [[ -n "$content" ]]; then
            warn "Non-standard cron file ${f}:"
            echo "$content" | sed 's/^/    /'
            (( CRON_HITS++ )) || true
        fi
    fi
done

# Per-user crontabs
while IFS=: read -r user _ uid _ _ _ _; do
    [[ "$uid" -lt 1000 ]] && [[ "$user" != "root" ]] && continue
    [[ "$uid" -eq 65534 ]] && continue
    ctab=$(crontab -l -u "$user" 2>/dev/null \
        | grep -v '^\s*#\|^\s*$' || true)
    if [[ -n "$ctab" ]]; then
        # Check for suspicious content first
        suspicious=$(echo "$ctab" | grep -P "$CRON_SUSPICIOUS_PATTERN" || true)
        if [[ -n "$suspicious" ]]; then
            crit "SUSPICIOUS content in crontab for ${user}:"
            echo "$suspicious" | sed 's/^/    /'
        else
            warn "User crontab for ${user} (review manually):"
            echo "$ctab" | sed 's/^/    /'
        fi
        (( CRON_HITS++ )) || true
    fi
done < /etc/passwd

if [[ "$CRON_HITS" -eq 0 ]]; then
    ok "No unexpected or suspicious cron entries found"
    info "  ${SYSTEM_CRON_CLEAN} standard system cron file(s) scanned and clean"
fi

# at jobs
echo ""
info "Pending at jobs:"
if command -v atq &>/dev/null; then
    atq_out=$(atq 2>/dev/null || true)
    if [[ -n "$atq_out" ]]; then
        warn "Pending at jobs found:"
        echo "$atq_out" | sed 's/^/    /'
        warn "View job contents: at -c <job_id>"
        warn "Remove all:        atq | awk '{print \$1}' | xargs atrm"
    else
        ok "No pending at jobs"
    fi
else
    info "atq not available"
fi

# =============================================================================
# Section 5 - MOTD & Login Scripts
# =============================================================================
header "5. MOTD & LOGIN SCRIPTS"

MOTD_DIR="/etc/update-motd.d"
if [[ -d "$MOTD_DIR" ]]; then
    info "Files in ${MOTD_DIR}:"
    while IFS= read -r -d '' f; do
        modified_mins=$(( ( $(date +%s) - $(stat -c %Y "$f") ) / 60 ))
        if [[ "$modified_mins" -lt 120 ]]; then
            warn "${f} (modified ${modified_mins} min ago) - REVIEW CONTENTS:"
            cat "$f" | sed 's/^/    /'
        else
            ok "${f} (modified ${modified_mins} min ago)"
        fi
    done < <(find "$MOTD_DIR" -maxdepth 1 -type f -print0 2>/dev/null)
else
    ok "${MOTD_DIR} does not exist"
fi

# Profile files for all users
echo ""
info "Checking shell profile files for suspicious content..."
PROFILE_FILES=(
    "/etc/profile"
    "/etc/bash.bashrc"
    "/root/.bashrc"
    "/root/.bash_profile"
    "/root/.profile"
)

# Add per-user profile files
while IFS=: read -r user _ uid _ _ home _; do
    [[ "$uid" -lt 1000 ]] && [[ "$user" != "root" ]] && continue
    [[ "$uid" -eq 65534 ]] && continue
    for f in ".bashrc" ".bash_profile" ".profile" ".bash_logout"; do
        [[ -f "${home}/${f}" ]] && PROFILE_FILES+=("${home}/${f}")
    done
done < /etc/passwd

for f in "${PROFILE_FILES[@]}"; do
    [[ -f "$f" ]] || continue
    # Look for suspicious patterns: network connections, base64, background processes
    hits=$(grep -nP \
        'bash\s+-i|/dev/tcp|/dev/udp|nc\s|ncat\s|python.*socket|curl.*sh|wget.*sh|base64|eval\s*\(|exec\s*>' \
        "$f" 2>/dev/null || true)
    if [[ -n "$hits" ]]; then
        crit "Suspicious content in ${f}:"
        echo "$hits" | sed 's/^/    /'
    fi
done

# =============================================================================
# Section 6 - Systemd Services & Timers
# =============================================================================
header "6. SYSTEMD SERVICES & TIMERS"

# Known standard Debian 13 desktop services - suppress these
KNOWN_SERVICES="auditd|cron|dbus|getty|networking|rsyslog|ssh|systemd|apache2|mysql|mariadb|ufw|apparmor|accounts-daemon|anacron|avahi-daemon|bluetooth|console-setup|cups|e2scrub|grub-common|keyboard-setup|low-memory-monitor|ModemManager|NetworkManager|open-vm-tools|power-profiles-daemon|switcheroo-control|udisks2|vgauth|wpa_supplicant|wtmpdb|gdm|plymouth|polkit|rtkit|colord|fwupd|packagekit|snapd"

info "Unexpected enabled services (non-standard for Debian 13):"
UNEXPECTED_SERVICES=$(systemctl list-unit-files --type=service --state=enabled 2>/dev/null \
    | grep "enabled" \
    | grep -vP "^(UNIT|${KNOWN_SERVICES})" || true)

if [[ -n "$UNEXPECTED_SERVICES" ]]; then
    echo "$UNEXPECTED_SERVICES" | while IFS= read -r line; do
        warn "    ${line}"
    done
else
    ok "No unexpected enabled services found"
fi

echo ""
info "Active systemd timers (summary):"
systemctl list-timers --all 2>/dev/null \
    | grep -v "^NEXT\|^$\|timers listed" \
    | awk '{print "    " $1 " | " $5 " " $6}' \
    | head -15

# =============================================================================
# Section 7 - Network Connections & Listening Ports
# =============================================================================
header "7. NETWORK - LISTENING PORTS & CONNECTIONS"

info "Listening ports:"
ss -tlnpu 2>/dev/null | while IFS= read -r line; do
    echo "    ${line}"
done

echo ""
info "Established outbound connections (potential callbacks):"
# Filter out known legitimate outbound connections:
#   - DHCP (port 67/68) - NetworkManager
#   - SSH port 22 - our own and grey team sessions
#   - Loopback addresses
SUSPICIOUS_OUTBOUND=$(ss -tnpu state established 2>/dev/null \
    | grep -v '127\.\|::1\|:22 \|:67 \|:68 ' || true)
if [[ -n "$SUSPICIOUS_OUTBOUND" ]]; then
    crit "Unexpected outbound connections - potential callbacks:"
    echo "$SUSPICIOUS_OUTBOUND" | while IFS= read -r line; do
        warn "    ${line}"
    done
else
    ok "No unexpected outbound connections"
fi

# =============================================================================
# Section 8 - Sudo Configuration
# =============================================================================
header "8. SUDO CONFIGURATION"

info "Current sudoers entries:"
grep -rh "^\s*[^#]" /etc/sudoers /etc/sudoers.d/ 2>/dev/null \
    | grep -v '^\s*Defaults\|^\s*$' \
    | while IFS= read -r line; do
        if echo "$line" | grep -q "NOPASSWD"; then
            warn "NOPASSWD: ${line}"
        else
            info "  ${line}"
        fi
    done

# =============================================================================
# Section 9 - Firewall Status
# =============================================================================
header "9. FIREWALL STATUS"

if command -v ufw &>/dev/null; then
    ufw_status=$(ufw status 2>/dev/null | head -1)
    if echo "$ufw_status" | grep -q "active"; then
        ok "UFW is active"
        ufw status verbose 2>/dev/null | sed 's/^/    /'
    else
        crit "UFW is INACTIVE - box is unprotected"
    fi
else
    warn "UFW not installed"
    info "Raw iptables rules:"
    iptables -L -n --line-numbers 2>/dev/null | head -40 | sed 's/^/    /'
fi

# =============================================================================
# Section 10 - Filesystem (full scan only)
# =============================================================================
if $FULL_SCAN; then
    header "10. FILESYSTEM SCAN (may take 30-60 seconds)"

    info "Files modified in the last 24 hours (excluding /proc /sys /run):"
    find / \
        -path /proc -prune -o \
        -path /sys -prune -o \
        -path /run -prune -o \
        -path /dev -prune -o \
        -newer /etc/hostname \
        -type f \
        -print 2>/dev/null \
        | grep -v "^/proc\|^/sys\|^/run\|^/dev" \
        | while IFS= read -r f; do
            modified_mins=$(( ( $(date +%s) - $(stat -c %Y "$f") ) / 60 ))
            owner=$(stat -c '%U' "$f")
            echo "    [${modified_mins}m ago] [${owner}] ${f}"
        done | sort -t'[' -k2 -n | head -50

    echo ""
    info "Unowned files (no valid user or group):"
    UNOWNED=$(find / \
        -path /proc -prune -o \
        -path /sys -prune -o \
        \( -nouser -o -nogroup \) \
        -type f \
        -print 2>/dev/null || true)
    if [[ -n "$UNOWNED" ]]; then
        warn "Unowned files found:"
        echo "$UNOWNED" | sed 's/^/    /'
    else
        ok "No unowned files found"
    fi

    echo ""
    info "Unexpected SUID/SGID binaries:"
    KNOWN_SUID=(
        "/usr/bin/sudo" "/usr/bin/su" "/usr/bin/passwd" "/usr/bin/chsh"
        "/usr/bin/chfn" "/usr/bin/gpasswd" "/usr/bin/newgrp" "/usr/bin/mount"
        "/usr/bin/umount" "/usr/bin/wall" "/usr/bin/write" "/usr/bin/ssh-agent"
        "/usr/bin/crontab" "/usr/bin/at" "/usr/bin/expiry" "/usr/bin/chage"
        "/usr/lib/dbus-1.0/dbus-daemon-launch-helper"
        "/usr/lib/openssh/ssh-keysign"
        "/usr/sbin/pam_extrausers_chkpwd"
        "/usr/sbin/unix_chkpwd"
    )
    declare -A KNOWN_SUID_SET
    for s in "${KNOWN_SUID[@]}"; do KNOWN_SUID_SET["$s"]=1; done

    find / \
        -path /proc -prune -o \
        -path /sys -prune -o \
        \( -perm -4000 -o -perm -2000 \) \
        -type f \
        -print 2>/dev/null \
        | while IFS= read -r f; do
            if [[ -z "${KNOWN_SUID_SET[$f]+_}" ]]; then
                crit "Unexpected SUID/SGID: ${f}"
                stat -c '    owner=%U mode=%a' "$f"
            fi
        done
else
    header "10. FILESYSTEM SCAN"
    info "Skipped - run with --full to include filesystem scans"
    info "  sudo ./triage.sh --full"
fi

# =============================================================================
# Final summary
# =============================================================================
header "TRIAGE COMPLETE"
echo ""
echo -e "${BOLD}Quick remediation reference:${RESET}"
echo "  Clear ld.so.preload:    > /etc/ld.so.preload"
echo "  Remove at jobs:         atq | awk '{print \$1}' | xargs atrm"
echo "  Kill user sessions:     pkill -u <username>"
echo "  Check file contents:    at -c <job_id>"
echo "  View recent auth:       journalctl -u ssh --since '1 hour ago'"
echo "  View UFW drops:         journalctl -u ufw | grep -i 'block\|drop'"
echo ""