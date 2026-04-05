#!/usr/bin/env bash
# =============================================================================
# harden_debian.sh - System-wide hardening for Debian 13 blue team boxes
#
# Usage:
#   sudo ./harden_debian.sh [--dry-run]
#
# What it does:
#   1. Enforces correct permissions and ownership on sensitive system files
#   2. Audits world-writable files outside of expected directories
#   3. Audits unexpected SUID/SGID binaries against a known-good allowlist
#   4. Renames attack tools so they are broken but recoverable
#   5. Checks /etc/ld.so.preload for unauthorized LD_PRELOAD persistence
#   6. Audits cron for unauthorized entries across all users
#   7. Snapshots running processes and listening ports for baseline reference
#
# Safety:
#   - World-writable and SUID findings prompt for confirmation before fixing
#   - Attack tools are renamed not deleted - recoverable if scoring needs them
#   - Sensitive file permissions are fixed automatically (low risk)
#   - ld.so.preload unauthorized content prompts before clearing
#   - Run with --dry-run to preview all actions without making changes
# =============================================================================

set -euo pipefail

# =============================================================================
# !! ATTACK TOOLS - EDIT IF NEEDED !!
#
# Binaries listed here will be renamed to <name>.disabled if found.
# They are NOT deleted - recoverable by renaming back.
#
# curl and tcpdump are commented out by default - grey team scoring
# checks may use curl to verify HTTP responses. Uncomment only if you
# are certain scoring does not depend on them.
# =============================================================================
ATTACK_TOOLS=(
    "netcat"
    "nc"
    "ncat"
    "gcc"
    "gcc-12"
    "gcc-13"
    "make"
    "socat"
    "nmap"
    # "curl"       # CAUTION - scoring checks may use this
    # "wget"       # CAUTION - scoring checks may use this
    # "tcpdump"    # CAUTION - may be used by monitoring scripts
)

# =============================================================================
# !! AUTHORIZED SUID/SGID BINARIES - EDIT IF NEEDED !!
#
# Any SUID/SGID binary NOT in this list will be flagged as suspicious.
# This list covers standard Debian 13 expected SUID binaries.
# Add any competition-specific binaries that legitimately need SUID.
# =============================================================================
AUTHORIZED_SUID=(
    "/usr/bin/sudo"
    "/usr/bin/su"
    "/usr/bin/passwd"
    "/usr/bin/chsh"
    "/usr/bin/chfn"
    "/usr/bin/gpasswd"
    "/usr/bin/newgrp"
    "/usr/bin/mount"
    "/usr/bin/umount"
    "/usr/bin/wall"
    "/usr/bin/write"
    "/usr/bin/ssh-agent"
    "/usr/bin/crontab"
    "/usr/bin/at"
    "/usr/bin/expiry"
    "/usr/bin/chage"
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper"
    "/usr/lib/openssh/ssh-keysign"
    "/usr/sbin/pam_extrausers_chkpwd"
    "/usr/sbin/unix_chkpwd"
    "/usr/lib/eject/dmcrypt-get-device"
)

# =============================================================================
# !! SENSITIVE FILES - permissions enforced automatically !!
#
# Format: "path:owner:group:permissions"
# These are the correct values for a standard Debian 13 system.
# =============================================================================
SENSITIVE_FILES=(
    "/etc/passwd:root:root:644"
    "/etc/passwd-:root:root:600"
    "/etc/shadow:root:shadow:640"
    "/etc/shadow-:root:shadow:640"
    "/etc/group:root:root:644"
    "/etc/group-:root:root:644"
    "/etc/gshadow:root:shadow:640"
    "/etc/gshadow-:root:shadow:640"
    "/etc/sudoers:root:root:440"
    "/etc/ssh/sshd_config:root:root:600"
    "/etc/crontab:root:root:600"
    "/etc/hosts:root:root:644"
    "/etc/hostname:root:root:644"
    "/etc/ld.so.preload:root:root:644"
    "/etc/shells:root:root:644"
    "/etc/security/opasswd:root:root:600"
)

# Directories where world-writable files are expected - skip these
WRITABLE_SKIP_DIRS=(
    "/tmp"
    "/var/tmp"
    "/run"
    "/dev"
    "/proc"
    "/sys"
)

# =============================================================================
# Configuration
# =============================================================================
DRY_RUN=false
BACKUP_DIR="/root/harden_backups"
SNAPSHOT_DIR="/root/system_snapshot"
TOOL_SEARCH_PATHS=("/usr/bin" "/usr/sbin" "/bin" "/sbin" "/usr/local/bin" "/usr/local/sbin")

# =============================================================================
# Helpers
# =============================================================================
info()    { echo "[*] $*"; }
success() { echo "[+] $*"; }
warn()    { echo "[!] $*" >&2; }
error()   { echo "[-] $*" >&2; }
dryrun()  { echo "[DRY-RUN] $*"; }

confirm() {
    # Usage: confirm "prompt text" && do_thing
    local prompt="$1"
    local answer
    read -r -p "  ${prompt} Type YES to confirm: " answer
    echo ""
    [[ "$answer" == "YES" ]]
}

# =============================================================================
# Preflight
# =============================================================================
if [[ "$(id -u)" -ne 0 ]]; then
    error "This script must be run as root"
    exit 1
fi

if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN=true
    warn "DRY-RUN mode - no changes will be made"
    echo ""
fi

mkdir -p "$BACKUP_DIR"
mkdir -p "$SNAPSHOT_DIR"

# Build SUID allowlist lookup
declare -A SUID_ALLOWED
for path in "${AUTHORIZED_SUID[@]}"; do
    SUID_ALLOWED["$path"]=1
done

# Build world-writable skip dir lookup
declare -A SKIP_DIR_SET
for d in "${WRITABLE_SKIP_DIRS[@]}"; do
    SKIP_DIR_SET["$d"]=1
done

# =============================================================================
# Step 1 - Sensitive file permissions
#
# For each sensitive file we check and enforce owner, group, and mode.
# These corrections are applied automatically - the risk of getting these
# wrong is low and the benefit of correct permissions is immediate.
# Files that don't exist yet (like ld.so.preload) are skipped silently.
# =============================================================================
info "Step 1: Enforcing sensitive file permissions..."
echo ""

for entry in "${SENSITIVE_FILES[@]}"; do
    IFS=: read -r filepath owner group mode <<< "$entry"

    if [[ ! -e "$filepath" ]]; then
        info "  ${filepath} does not exist - skipping"
        continue
    fi

    NEEDS_FIX=false
    ISSUES=()

    # Check owner
    current_owner=$(stat -c '%U' "$filepath")
    if [[ "$current_owner" != "$owner" ]]; then
        ISSUES+=("owner: ${current_owner} -> ${owner}")
        NEEDS_FIX=true
    fi

    # Check group
    current_group=$(stat -c '%G' "$filepath")
    if [[ "$current_group" != "$group" ]]; then
        ISSUES+=("group: ${current_group} -> ${group}")
        NEEDS_FIX=true
    fi

    # Check permissions (stat returns octal without leading zero)
    current_mode=$(stat -c '%a' "$filepath")
    if [[ "$current_mode" != "$mode" ]]; then
        ISSUES+=("mode: ${current_mode} -> ${mode}")
        NEEDS_FIX=true
    fi

    if ! $NEEDS_FIX; then
        success "  ${filepath} - OK (${owner}:${group} ${mode})"
        continue
    fi

    warn "  ${filepath} - NEEDS FIX: ${ISSUES[*]}"

    if $DRY_RUN; then
        dryrun "  Would run: chown ${owner}:${group} ${filepath} && chmod ${mode} ${filepath}"
    else
        chown "${owner}:${group}" "$filepath"
        chmod "$mode" "$filepath"
        success "  Fixed: ${filepath}"
    fi
done

echo ""

# =============================================================================
# Step 2 - /etc/ld.so.preload audit
#
# This file is the target of our own red team LD_PRELOAD persistence
# technique. If it exists and contains anything, that's a red flag.
# We show the contents and prompt before clearing it.
# =============================================================================
info "Step 2: Auditing /etc/ld.so.preload..."
echo ""

LD_PRELOAD_FILE="/etc/ld.so.preload"

if [[ ! -f "$LD_PRELOAD_FILE" ]]; then
    success "  /etc/ld.so.preload does not exist - clean"
elif [[ ! -s "$LD_PRELOAD_FILE" ]]; then
    success "  /etc/ld.so.preload is empty - clean"
else
    warn "  /etc/ld.so.preload EXISTS and contains:"
    echo ""
    cat "$LD_PRELOAD_FILE"
    echo ""
    warn "  This file is used for LD_PRELOAD persistence - likely red team backdoor"

    if $DRY_RUN; then
        dryrun "Would prompt to clear /etc/ld.so.preload"
    else
        if confirm "Clear /etc/ld.so.preload?"; then
            cp "$LD_PRELOAD_FILE" "${BACKUP_DIR}/ld.so.preload.bak"
            > "$LD_PRELOAD_FILE"
            success "  Cleared /etc/ld.so.preload (backup saved)"
        else
            warn "  Skipped - ld.so.preload NOT cleared"
        fi
    fi
fi

echo ""

# =============================================================================
# Step 3 - World-writable file audit
#
# World-writable files outside of expected temp directories are unusual
# and give red team a place to drop payloads or modify shared resources.
# We find them, present them, and prompt before removing the write bit.
# =============================================================================
info "Step 3: Auditing world-writable files..."
echo ""

# Build the find exclusion arguments from WRITABLE_SKIP_DIRS
FIND_PRUNE_ARGS=()
for skip_dir in "${WRITABLE_SKIP_DIRS[@]}"; do
    FIND_PRUNE_ARGS+=(-path "$skip_dir" -prune -o)
done

info "  Scanning filesystem (this may take a moment)..."

WRITABLE_FILES=()
while IFS= read -r -d '' f; do
    WRITABLE_FILES+=("$f")
done < <(find / \
    "${FIND_PRUNE_ARGS[@]}" \
    -type f \
    -perm -o+w \
    -not -path "/proc/*" \
    -not -path "/sys/*" \
    -print0 2>/dev/null || true)

if [[ "${#WRITABLE_FILES[@]}" -eq 0 ]]; then
    success "  No unexpected world-writable files found"
else
    warn "  Found ${#WRITABLE_FILES[@]} world-writable file(s):"
    echo ""
    for f in "${WRITABLE_FILES[@]}"; do
        perms=$(stat -c '%a %U:%G %n' "$f")
        warn "  ${perms}"
    done
    echo ""

    if $DRY_RUN; then
        dryrun "Would prompt to remove world-write bit from all findings"
    else
        if confirm "Remove world-write bit from all ${#WRITABLE_FILES[@]} file(s)?"; then
            for f in "${WRITABLE_FILES[@]}"; do
                chmod o-w "$f" && success "  Fixed: ${f}" || warn "  Failed to fix: ${f}"
            done
        else
            warn "  Skipped - world-writable files NOT modified"
        fi
    fi
fi

echo ""

# =============================================================================
# Step 4 - SUID/SGID binary audit
#
# SUID binaries run with the file owner's privileges regardless of who
# executes them - a common privilege escalation vector. We find all
# SUID/SGID binaries and flag any not in our allowlist.
# =============================================================================
info "Step 4: Auditing SUID/SGID binaries..."
echo ""

SUSPICIOUS_SUID=()
while IFS= read -r -d '' f; do
    if [[ -z "${SUID_ALLOWED[$f]+_}" ]]; then
        SUSPICIOUS_SUID+=("$f")
    fi
done < <(find / \
    -path /proc -prune -o \
    -path /sys -prune -o \
    \( -perm -4000 -o -perm -2000 \) \
    -type f \
    -print0 2>/dev/null || true)

if [[ "${#SUSPICIOUS_SUID[@]}" -eq 0 ]]; then
    success "  No unexpected SUID/SGID binaries found"
else
    warn "  Found ${#SUSPICIOUS_SUID[@]} unexpected SUID/SGID binary/binaries:"
    echo ""
    for f in "${SUSPICIOUS_SUID[@]}"; do
        perms=$(stat -c '%a %U:%G %n' "$f")
        warn "  ${perms}"
    done
    echo ""
    warn "  Review each carefully - some may be legitimate installed packages"

    if $DRY_RUN; then
        dryrun "Would prompt to remove SUID/SGID bit from findings"
    else
        if confirm "Remove SUID/SGID bit from all ${#SUSPICIOUS_SUID[@]} binary/binaries?"; then
            for f in "${SUSPICIOUS_SUID[@]}"; do
                chmod ug-s "$f" && success "  Removed SUID/SGID: ${f}" || warn "  Failed: ${f}"
            done
        else
            warn "  Skipped - SUID/SGID bits NOT modified"
        fi
    fi
fi

echo ""

# =============================================================================
# Step 5 - Attack tool disabling
#
# Offensive tools are renamed to <binary>.disabled rather than deleted.
# This breaks them for red team while keeping them recoverable if a
# scoring check unexpectedly needs one.
# =============================================================================
info "Step 5: Disabling attack tools..."
echo ""

FOUND_TOOLS=()
FOUND_PATHS=()

for tool in "${ATTACK_TOOLS[@]}"; do
    for search_dir in "${TOOL_SEARCH_PATHS[@]}"; do
        tool_path="${search_dir}/${tool}"
        if [[ -f "$tool_path" ]] && [[ ! -f "${tool_path}.disabled" ]]; then
            FOUND_TOOLS+=("$tool")
            FOUND_PATHS+=("$tool_path")
        fi
    done
done

if [[ "${#FOUND_TOOLS[@]}" -eq 0 ]]; then
    success "  No attack tools found (or already disabled)"
else
    warn "  Found ${#FOUND_TOOLS[@]} attack tool(s):"
    for path in "${FOUND_PATHS[@]}"; do
        warn "  ${path} -> ${path}.disabled"
    done
    echo ""

    if $DRY_RUN; then
        dryrun "Would rename all found tools to <name>.disabled"
    else
        for i in "${!FOUND_PATHS[@]}"; do
            path="${FOUND_PATHS[$i]}"
            mv "$path" "${path}.disabled" \
                && success "  Disabled: ${path}" \
                || warn "  Failed to disable: ${path}"
        done
    fi
fi

echo ""

# =============================================================================
# Step 6 - Cron audit
#
# Red team persistence often lives in cron. We scan all cron locations
# and print their contents for manual review. We don't auto-remove
# anything here - cron entries can be subtle and removal is a manual call.
# =============================================================================
info "Step 6: Auditing cron entries..."
echo ""

CRON_LOCATIONS=(
    "/etc/crontab"
    "/etc/cron.d"
    "/etc/cron.daily"
    "/etc/cron.hourly"
    "/etc/cron.weekly"
    "/etc/cron.monthly"
    "/var/spool/cron/crontabs"
)

CRON_FINDINGS=0

for location in "${CRON_LOCATIONS[@]}"; do
    if [[ ! -e "$location" ]]; then
        continue
    fi

    if [[ -f "$location" ]]; then
        # Single file
        content=$(grep -v '^#' "$location" | grep -v '^[[:space:]]*$' || true)
        if [[ -n "$content" ]]; then
            warn "  ${location}:"
            echo "$content" | while IFS= read -r line; do
                echo "    ${line}"
            done
            (( CRON_FINDINGS++ )) || true
        else
            info "  ${location} - empty or comments only"
        fi

    elif [[ -d "$location" ]]; then
        # Directory - scan each file inside
        while IFS= read -r -d '' f; do
            content=$(grep -v '^#' "$f" | grep -v '^[[:space:]]*$' || true)
            if [[ -n "$content" ]]; then
                warn "  ${f}:"
                echo "$content" | while IFS= read -r line; do
                    echo "    ${line}"
                done
                (( CRON_FINDINGS++ )) || true
            fi
        done < <(find "$location" -maxdepth 1 -type f -print0 2>/dev/null)
    fi
done

echo ""
if [[ "$CRON_FINDINGS" -eq 0 ]]; then
    success "  No active cron entries found"
else
    warn "  ${CRON_FINDINGS} cron file(s) with active entries - review manually"
    warn "  Remove suspicious entries with: crontab -r -u <username>"
    warn "  Or edit directly: crontab -e -u <username>"
fi

echo ""

# =============================================================================
# Step 7 - Unowned file audit
#
# Files with no valid owner or group exist when a user is deleted but their
# files are not cleaned up, or when red team drops files under a temporary
# account they then remove. These are prime targets for privilege escalation
# and should be reviewed and re-owned or deleted.
#
# We report findings but do not automatically remove or re-own - too risky
# to automate without knowing what the files are.
# =============================================================================
info "Step 7: Auditing files with no valid owner or group..."
echo ""

UNOWNED_COUNT=0

while IFS= read -r -d '' f; do
    warn "  UNOWNED FILE: ${f}"
    stat -c '    owner: %U  group: %G  mode: %a' "$f" >&2
    (( UNOWNED_COUNT++ )) || true
done < <(find / \
    -path /proc -prune -o \
    -path /sys -prune -o \
    \( -nouser -o -nogroup \) \
    -type f \
    -print0 2>/dev/null || true)

echo ""
if [[ "$UNOWNED_COUNT" -eq 0 ]]; then
    success "  No unowned files found"
else
    warn "  ${UNOWNED_COUNT} unowned file(s) found - review and re-own or delete manually"
    warn "  To re-own: chown root:root <file>"
    warn "  To find all unowned files again: find / -nouser -o -nogroup 2>/dev/null"
fi

echo ""

# =============================================================================
# Step 8 - Process and port snapshot
#
# Capture a baseline of what is running and what ports are listening.
# Saved to /root/system_snapshot/ for comparison during the competition.
# Running this again later and diffing the output reveals new processes
# or listeners that red team has started.
# =============================================================================
info "Step 8: Capturing system snapshot..."
echo ""

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
PROC_SNAPSHOT="${SNAPSHOT_DIR}/processes_${TIMESTAMP}.txt"
PORT_SNAPSHOT="${SNAPSHOT_DIR}/ports_${TIMESTAMP}.txt"

if $DRY_RUN; then
    dryrun "Would save process snapshot -> ${PROC_SNAPSHOT}"
    dryrun "Would save port snapshot    -> ${PORT_SNAPSHOT}"
else
    ps auxf > "$PROC_SNAPSHOT" 2>/dev/null
    success "  Process snapshot -> ${PROC_SNAPSHOT}"

    if command -v ss &>/dev/null; then
        ss -tlnpu > "$PORT_SNAPSHOT" 2>/dev/null
    elif command -v netstat &>/dev/null; then
        netstat -tlnpu > "$PORT_SNAPSHOT" 2>/dev/null
    else
        echo "ss and netstat not available" > "$PORT_SNAPSHOT"
    fi
    success "  Port snapshot    -> ${PORT_SNAPSHOT}"

    echo ""
    info "  To compare snapshots later, run:"
    info "  diff ${PROC_SNAPSHOT} \$(ls -t ${SNAPSHOT_DIR}/processes_*.txt | head -2 | tail -1)"
fi

# =============================================================================
# Summary
# =============================================================================
echo ""
info "========================================="
info "System Hardening Summary"
info "========================================="
if $DRY_RUN; then
    info "  Mode:              DRY-RUN (no changes made)"
else
    info "  Backups:           ${BACKUP_DIR}/"
    info "  Snapshots:         ${SNAPSHOT_DIR}/"
fi
info "  World-writable:    ${#WRITABLE_FILES[@]} found"
info "  Suspicious SUID:   ${#SUSPICIOUS_SUID[@]} found"
info "  Attack tools:      ${#FOUND_TOOLS[@]} found"
info "  Cron files:        ${CRON_FINDINGS} with active entries"
info "  Unowned files:     ${UNOWNED_COUNT} found"
info "========================================="
echo ""
warn "REMINDER: Cron findings require MANUAL review."
warn "REMINDER: Attack tools renamed to .disabled - recoverable if needed."
warn "REMINDER: Re-run this script periodically to catch new red team changes."