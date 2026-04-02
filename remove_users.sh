#!/usr/bin/env bash
# =============================================================================
# remove_users.sh — Remove unauthorized local users from Debian 13 boxes
#
# Usage:
#   sudo ./remove_users.sh [--dry-run]
#
# What it does:
#   1. Reads all local users with UID >= 1000 from /etc/passwd
#   2. Compares against the PROTECTED_USERS allowlist below
#   3. Archives the home directory of any unauthorized user to /root/evidence/
#   4. Removes the unauthorized user account and their home directory
#
# Safety:
#   - Run with --dry-run first to preview actions without making changes
#   - GREYTEAM and all system/service accounts are always protected
#   - Script must be run as root
#
# Update PROTECTED_USERS before competition use
# =============================================================================

set -euo pipefail

# =============================================================================
# !! PROTECTED USERS — EDIT THIS BEFORE COMPETITION DAY !!
# =============================================================================
PROTECTED_USERS=(
    "cyberrange"
    "GREYTEAM"
)

# =============================================================================
# Configuration
# =============================================================================
EVIDENCE_DIR="/root/evidence"
DRY_RUN=false

# =============================================================================
# Helpers
# =============================================================================
info()    { echo "[*] $*"; }
success() { echo "[+] $*"; }
warn()    { echo "[!] $*" >&2; }
error()   { echo "[-] $*" >&2; }
dryrun()  { echo "[DRY-RUN] $*"; }

# =============================================================================
# Preflight checks
# =============================================================================
if [[ "$(id -u)" -ne 0 ]]; then
    error "This script must be run as root"
    exit 1
fi

if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN=true
    warn "DRY-RUN mode — no changes will be made"
    echo ""
fi

# Build a quick-lookup set from PROTECTED_USERS
declare -A PROTECTED_SET
for u in "${PROTECTED_USERS[@]}"; do
    PROTECTED_SET["$u"]=1
done

# =============================================================================
# Main loop — find and remove unauthorized users
# =============================================================================
info "Scanning for unauthorized local users (UID >= 1000)..."
echo ""

REMOVED=0
SKIPPED=0

while IFS=: read -r username _ uid _ _ home _; do
    # Only look at human accounts (UID >= 1000), skip nobody (UID 65534)
    [[ "$uid" -lt 1000 ]] && continue
    [[ "$uid" -eq 65534 ]] && continue

    if [[ -n "${PROTECTED_SET[$username]+_}" ]]; then
        info "PROTECTED — skipping: ${username} (uid=${uid})"
        (( SKIPPED++ )) || true
        continue
    fi

    # This user is not in the allowlist — remove them
    warn "UNAUTHORIZED user found: ${username} (uid=${uid}, home=${home})"

    if $DRY_RUN; then
        dryrun "Would archive ${home} -> ${EVIDENCE_DIR}/${username}_home.tar.gz"
        dryrun "Would run: userdel -r ${username}"
        (( REMOVED++ )) || true
        continue
    fi

    # Archive home directory before deletion
    if [[ -d "$home" ]]; then
        mkdir -p "$EVIDENCE_DIR"
        ARCHIVE="${EVIDENCE_DIR}/${username}_home_$(date +%Y%m%d_%H%M%S).tar.gz"
        info "Archiving ${home} -> ${ARCHIVE}"
        tar -czf "$ARCHIVE" -C "$(dirname "$home")" "$(basename "$home")" 2>/dev/null || \
            warn "Archive failed for ${home} — continuing with removal anyway"
    else
        info "No home directory found at ${home} — skipping archive"
    fi

    # Kill any running processes owned by this user before deletion
    if pgrep -u "$username" &>/dev/null; then
        info "Killing active processes for ${username}..."
        pkill -u "$username" || true
        sleep 1
    fi

    # Remove the account and home directory
    userdel -r "$username" 2>/dev/null || userdel "$username" 2>/dev/null || \
        warn "userdel failed for ${username} — may need manual removal"

    success "Removed user: ${username}"
    (( REMOVED++ )) || true

done < /etc/passwd

# =============================================================================
# Summary
# =============================================================================
echo ""
info "========================================="
info "Scan complete"
info "  Protected (skipped): ${SKIPPED}"
if $DRY_RUN; then
    info "  Would remove:        ${REMOVED}"
    echo ""
    warn "Re-run without --dry-run to apply changes"
else
    info "  Removed:             ${REMOVED}"
    if [[ "$REMOVED" -gt 0 ]]; then
        info "  Evidence archived to: ${EVIDENCE_DIR}/"
    fi
fi
info "========================================="