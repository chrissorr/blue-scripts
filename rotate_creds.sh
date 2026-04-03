#!/usr/bin/env bash
# =============================================================================
# rotate_credentials.sh — Rotate passwords for local users on Debian 13 boxes
#
# Usage:
#   sudo ./rotate_credentials.sh [--dry-run]
#
# What it does:
#   1. Iterates over every username listed in ROTATE_USERS below
#   2. Generates a strong random password for each
#   3. Sets the new password via chpasswd
#   4. Prints a clear summary table of all new credentials at the end
#
# Safety:
#   - Run with --dry-run to preview which accounts would be rotated
#   - GREYTEAM is hardcoded to NEVER be rotated regardless of config
#   - Always record the output — new passwords are only shown once
# =============================================================================

set -euo pipefail

# =============================================================================
# !! ROTATE USERS — EDIT THIS BEFORE COMPETITION DAY !!

# List every account whose password should be rotated
# Passwords will be randomly generated and printed to the stdout
# =============================================================================
ROTATE_USERS=(
    "cyberrange"
)

# =============================================================================
# Configuration
# =============================================================================
DRY_RUN=false
PASSWORD_LENGTH=12

# Accounts that can NEVER be rotated, regardless of what's in ROTATE_USERS
# do not remove GREYTEAM from this list
NEVER_ROTATE=(
    "GREYTEAM"
    "root"
)

# =============================================================================
# Helpers
# =============================================================================
info()    { echo "[*] $*"; }
success() { echo "[+] $*"; }
warn()    { echo "[!] $*" >&2; }
error()   { echo "[-] $*" >&2; }
dryrun()  { echo "[DRY-RUN] $*"; }

# Generate a strong random password
# Uses /dev/urandom — alphanumeric only to avoid shell quoting issues
gen_password() {
    tr -dc 'A-Za-z0-9!@#%^&*' < /dev/urandom | head -c "${PASSWORD_LENGTH}"
    echo ""
}

# =============================================================================
# Preflight checks
# =============================================================================
if [[ "$(id -u)" -ne 0 ]]; then
    error "This script must be run as root"
    exit 1
fi

if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN=true
    warn "DRY-RUN mode — no passwords will be changed"
    echo ""
fi

# Build never_rotate lookup set
declare -A NEVER_SET
for u in "${NEVER_ROTATE[@]}"; do
    NEVER_SET["$u"]=1
done

# =============================================================================
# Rotation loop
# =============================================================================

declare -a RESULT_USERS
declare -a RESULT_PASSWORDS
declare -a RESULT_STATUS

info "Starting credential rotation..."
echo ""

for username in "${ROTATE_USERS[@]}"; do

    # Hard safety check — never rotate protected accounts
    if [[ -n "${NEVER_SET[$username]+_}" ]]; then
        warn "BLOCKED — ${username} is in the NEVER_ROTATE list. Skipping."
        RESULT_USERS+=("$username")
        RESULT_PASSWORDS+=("UNCHANGED")
        RESULT_STATUS+=("BLOCKED - never rotate")
        continue
    fi

    # Verify the account actually exists on this system
    if ! id "$username" &>/dev/null; then
        warn "User ${username} does not exist on this system — skipping"
        RESULT_USERS+=("$username")
        RESULT_PASSWORDS+=("N/A")
        RESULT_STATUS+=("SKIPPED - user not found")
        continue
    fi

    # Generate new password
    NEW_PASS=$(gen_password)

    if $DRY_RUN; then
        dryrun "Would rotate password for: ${username}"
        RESULT_USERS+=("$username")
        RESULT_PASSWORDS+=("[would be generated]")
        RESULT_STATUS+=("DRY-RUN")
        continue
    fi

    # Set the new password
    if echo "${username}:${NEW_PASS}" | chpasswd; then
        success "Rotated password for: ${username}"
        RESULT_USERS+=("$username")
        RESULT_PASSWORDS+=("$NEW_PASS")
        RESULT_STATUS+=("OK")
    else
        error "Failed to rotate password for: ${username}"
        RESULT_USERS+=("$username")
        RESULT_PASSWORDS+=("FAILED")
        RESULT_STATUS+=("ERROR - chpasswd failed")
    fi

done

# =============================================================================
# Summary table — printed clearly so it can be recorded
# =============================================================================
echo ""
echo "============================================================"
echo "  CREDENTIAL ROTATION SUMMARY"
if $DRY_RUN; then
    echo "  (DRY-RUN — no changes made)"
fi
echo "============================================================"
printf "  %-20s %-25s %s\n" "USERNAME" "NEW PASSWORD" "STATUS"
echo "  ------------------------------------------------------------"
for i in "${!RESULT_USERS[@]}"; do
    printf "  %-20s %-25s %s\n" \
        "${RESULT_USERS[$i]}" \
        "${RESULT_PASSWORDS[$i]}" \
        "${RESULT_STATUS[$i]}"
done
echo "============================================================"
echo ""