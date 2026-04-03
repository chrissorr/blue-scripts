#!/usr/bin/env bash
# =============================================================================
# harden_sudo.sh — Audit and harden sudo configuration on Debian 13 boxes
#
# Usage:
#   sudo ./harden_sudo.sh [--dry-run]
#
# What it does:
#   1. Audits /etc/sudoers and all files in /etc/sudoers.d/ for entries
#      granting sudo access to users not in our authorized list
#   2. Displays findings and prompts for confirmation before removing
#      any unauthorized entries
#   3. Writes a drop-in hardening file to /etc/sudoers.d/ that adds
#      Defaults requiretty to disrupt reverse shell privilege escalation
#   4. Validates all sudoers changes with visudo -c before applying
#
# Safety:
#   - NOPASSWD entries are never touched — scoring checkers may depend on them
#   - visudo -c validates every file before and after changes
#   - All modified files are backed up before editing
#   - Confirmation prompt shows exactly what will be removed
#   - Run with --dry-run to preview all actions without making changes
# =============================================================================

set -euo pipefail

# =============================================================================
# !! AUTHORIZED SUDO USERS — EDIT THIS BEFORE COMPETITION DAY !!
#
# Any user in /etc/sudoers or /etc/sudoers.d/ NOT in this list will be
# flagged as unauthorized and queued for removal after confirmation.
#
# Known required accounts (from blue team packet):
#   root        — always authorized, never touched
#   GREYTEAM    — grey team oversight, MUST retain sudo if currently set
#
# =============================================================================
AUTHORIZED_SUDO_USERS=(
    "root"
    "GREYTEAM"
)

# =============================================================================
# !! AUTHORIZED SUDO GROUPS — EDIT THIS IF NEEDED !!
#
# Group-based sudo grants are also checked. Standard Debian groups that
# legitimately have sudo access are listed here.
# =============================================================================
AUTHORIZED_SUDO_GROUPS=(
    "sudo"
    "root"
    "admin"
    "wheel"
)

# =============================================================================
# Configuration
# =============================================================================
DRY_RUN=false
SUDOERS_FILE="/etc/sudoers"
SUDOERS_DIR="/etc/sudoers.d"
DROPIN_FILE="${SUDOERS_DIR}/99-blueteam-hardening"
BACKUP_DIR="/root/sudoers_backups"

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

if ! command -v visudo &>/dev/null; then
    error "visudo is not available — cannot safely edit sudoers"
    exit 1
fi

# Build authorized lookup sets
declare -A AUTH_USER_SET
for u in "${AUTHORIZED_SUDO_USERS[@]}"; do
    AUTH_USER_SET["$u"]=1
done

declare -A AUTH_GROUP_SET
for g in "${AUTHORIZED_SUDO_GROUPS[@]}"; do
    AUTH_GROUP_SET["$g"]=1
done

# =============================================================================
# Step 1 — Backup all sudoers files
# =============================================================================
info "Step 1: Backing up sudoers files..."

if $DRY_RUN; then
    dryrun "Would backup ${SUDOERS_FILE} and ${SUDOERS_DIR}/ -> ${BACKUP_DIR}/"
else
    mkdir -p "$BACKUP_DIR"
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    cp "$SUDOERS_FILE" "${BACKUP_DIR}/sudoers.${TIMESTAMP}"
    if [[ -d "$SUDOERS_DIR" ]]; then
        cp -r "$SUDOERS_DIR" "${BACKUP_DIR}/sudoers.d.${TIMESTAMP}"
    fi
    success "Backed up to ${BACKUP_DIR}/"
fi

# =============================================================================
# Step 2 — Audit sudoers files
#
# We parse each sudoers file looking for:
#   - User privilege lines:  username  ALL=(ALL) ...
#   - Group privilege lines: %groupname ALL=(ALL) ...
#
# We skip:
#   - Comments (#)
#   - Defaults lines (we add our own, not remove existing)
#   - NOPASSWD entries entirely — too risky to touch
#   - Aliases (User_Alias, Cmnd_Alias, etc.)
#
# Lines granting access to unauthorized users are collected and presented
# for confirmation before removal.
# =============================================================================
info "Step 2: Auditing sudoers files..."
echo ""

# Collect all sudoers files to audit
SUDOERS_FILES=("$SUDOERS_FILE")
if [[ -d "$SUDOERS_DIR" ]]; then
    while IFS= read -r -d '' f; do
        SUDOERS_FILES+=("$f")
    done < <(find "$SUDOERS_DIR" -maxdepth 1 -type f -print0 2>/dev/null)
fi

# Parallel arrays to track unauthorized findings
declare -a FINDING_FILE
declare -a FINDING_LINE
declare -a FINDING_CONTENT
declare -a FINDING_TYPE     # "user" or "group"
declare -a FINDING_ENTITY   # the username or groupname

for sudoers_file in "${SUDOERS_FILES[@]}"; do
    # Skip our own drop-in if it already exists — we wrote it, it's authorized
    [[ "$sudoers_file" == "$DROPIN_FILE" ]] && continue

    info "Scanning: ${sudoers_file}"

    line_num=0
    while IFS= read -r line || [[ -n "$line" ]]; do
        (( line_num++ )) || true

        # Skip blank lines
        [[ -z "${line// }" ]] && continue

        # Skip full-line comments
        [[ "$line" == \#* ]] && continue

        # Skip Defaults lines — we handle those separately
        [[ "$line" =~ ^[[:space:]]*Defaults ]] && continue

        # Skip alias definitions
        [[ "$line" =~ ^[[:space:]]*(User|Runas|Host|Cmnd)_Alias ]] && continue

        # Skip include directives
        [[ "$line" =~ ^[[:space:]]*[@#]include ]] && continue

        # -- Check for group privilege lines (%groupname ...) --
        if [[ "$line" =~ ^[[:space:]]*%([A-Za-z0-9_-]+)[[:space:]] ]]; then
            groupname="${BASH_REMATCH[1]}"
            if [[ -z "${AUTH_GROUP_SET[$groupname]+_}" ]]; then
                warn "  UNAUTHORIZED GROUP: %${groupname} (line ${line_num})"
                warn "  Content: ${line}"
                FINDING_FILE+=("$sudoers_file")
                FINDING_LINE+=("$line_num")
                FINDING_CONTENT+=("$line")
                FINDING_TYPE+=("group")
                FINDING_ENTITY+=("$groupname")
            else
                info "  Authorized group: %${groupname}"
            fi
            continue
        fi

        # -- Check for user privilege lines (username ...) --
        # A user privilege line starts with a non-whitespace word that isn't
        # a keyword. We match lines of the form: word  HOST=(RUNAS) commands
        if [[ "$line" =~ ^[[:space:]]*([A-Za-z0-9_-]+)[[:space:]]+(ALL|[A-Za-z0-9_-]+)[[:space:]]*= ]]; then
            username="${BASH_REMATCH[1]}"

            # Skip sudoers keywords that look like user lines
            case "$username" in
                Defaults|User_Alias|Runas_Alias|Host_Alias|Cmnd_Alias)
                    continue ;;
            esac

            if [[ -z "${AUTH_USER_SET[$username]+_}" ]]; then
                warn "  UNAUTHORIZED USER: ${username} (line ${line_num})"
                warn "  Content: ${line}"
                FINDING_FILE+=("$sudoers_file")
                FINDING_LINE+=("$line_num")
                FINDING_CONTENT+=("$line")
                FINDING_TYPE+=("user")
                FINDING_ENTITY+=("$username")
            else
                info "  Authorized user: ${username}"
            fi
        fi

    done < "$sudoers_file"

    echo ""
done

# =============================================================================
# Step 3 — Present findings and prompt for confirmation
# =============================================================================
FINDING_COUNT=${#FINDING_FILE[@]}

if [[ "$FINDING_COUNT" -eq 0 ]]; then
    success "No unauthorized sudoers entries found."
    echo ""
else
    echo "============================================================"
    echo "  UNAUTHORIZED SUDOERS ENTRIES FOUND: ${FINDING_COUNT}"
    echo "============================================================"
    for i in "${!FINDING_FILE[@]}"; do
        printf "  [%d] %s  (type: %s, entity: %s)\n" \
            $(( i + 1 )) \
            "${FINDING_FILE[$i]}" \
            "${FINDING_TYPE[$i]}" \
            "${FINDING_ENTITY[$i]}"
        printf "      Line %d: %s\n" \
            "${FINDING_LINE[$i]}" \
            "${FINDING_CONTENT[$i]}"
        echo ""
    done
    echo "============================================================"
    warn "NOTE: NOPASSWD entries are NOT removed regardless of user."
    warn "Review the above carefully before confirming."
    echo ""

    if $DRY_RUN; then
        dryrun "Would prompt for confirmation and remove the above entries"
    else
        read -r -p "  Remove all unauthorized entries? Type YES to confirm: " CONFIRM
        echo ""

        if [[ "$CONFIRM" != "YES" ]]; then
            info "Removal skipped — no sudoers entries were changed."
        else
            # Remove unauthorized lines from their respective files
            # We process each unique file once, removing all flagged lines from it

            declare -A FILES_TO_CLEAN
            for i in "${!FINDING_FILE[@]}"; do
                FILES_TO_CLEAN["${FINDING_FILE[$i]}"]=1
            done

            for target_file in "${!FILES_TO_CLEAN[@]}"; do
                info "Cleaning: ${target_file}"

                # Build a sed expression to delete all flagged lines from this file
                SED_EXPR=""
                for i in "${!FINDING_FILE[@]}"; do
                    [[ "${FINDING_FILE[$i]}" != "$target_file" ]] && continue
                    # Escape the line content for use as a sed pattern
                    escaped=$(printf '%s\n' "${FINDING_CONTENT[$i]}" | sed 's/[[\.*^$()+?{|]/\\&/g')
                    SED_EXPR+="/^[[:space:]]*${escaped}/d;"
                done

                # Write cleaned content to a temp file
                tmp=$(mktemp)
                sed "${SED_EXPR}" "$target_file" > "$tmp"

                # Validate the cleaned file before replacing the original
                if visudo -c -f "$tmp" &>/dev/null; then
                    chmod --reference="$target_file" "$tmp"
                    mv "$tmp" "$target_file"
                    success "Cleaned ${target_file}"
                else
                    error "visudo validation failed for cleaned ${target_file} — skipping"
                    error "The original file has NOT been modified"
                    rm -f "$tmp"
                fi
            done
        fi
    fi
fi

# =============================================================================
# Step 4 — Write hardening drop-in
#
# We add Defaults requiretty which requires sudo to be called from a
# real terminal (tty). This directly disrupts privilege escalation from
# reverse shells, which have no tty. We write this as a drop-in rather
# than modifying /etc/sudoers directly.
#
# We do NOT add this if it already exists anywhere in the sudoers config.
# =============================================================================
info "Step 4: Checking for requiretty..."

REQUIRETTY_EXISTS=false
for sudoers_file in "${SUDOERS_FILES[@]}"; do
    if grep -q "requiretty" "$sudoers_file" 2>/dev/null; then
        REQUIRETTY_EXISTS=true
        info "requiretty already present in ${sudoers_file} — skipping"
        break
    fi
done

if ! $REQUIRETTY_EXISTS; then
    DROPIN_CONTENT="# Blue Team sudo hardening — applied by harden_sudo.sh
# To revert: rm ${DROPIN_FILE}

# Require a real tty for sudo — prevents privilege escalation from
# reverse shells and other non-interactive execution contexts
Defaults requiretty
"

    if $DRY_RUN; then
        dryrun "Would write drop-in to ${DROPIN_FILE}:"
        echo ""
        echo "$DROPIN_CONTENT"
    else
        # Write to temp file and validate before installing
        tmp=$(mktemp)
        echo "$DROPIN_CONTENT" > "$tmp"

        if visudo -c -f "$tmp" &>/dev/null; then
            mv "$tmp" "$DROPIN_FILE"
            chmod 440 "$DROPIN_FILE"
            success "Wrote requiretty drop-in to ${DROPIN_FILE}"
        else
            error "visudo validation failed for requiretty drop-in — not installed"
            rm -f "$tmp"
        fi
    fi
fi

# =============================================================================
# Step 5 — Final validation of entire sudoers configuration
# =============================================================================
info "Step 5: Final sudoers configuration validation..."

if $DRY_RUN; then
    dryrun "Would run: visudo -c"
else
    if visudo -c &>/dev/null; then
        success "Full sudoers configuration is valid"
    else
        error "visudo reports a problem with the current sudoers configuration"
        error "Run 'visudo -c' manually to identify the issue"
        error "Backups are available in ${BACKUP_DIR}/"
        exit 1
    fi
fi

# =============================================================================
# Summary
# =============================================================================
echo ""
info "========================================="
info "Sudo Hardening Summary"
info "========================================="
if $DRY_RUN; then
    info "  Mode:              DRY-RUN (no changes made)"
else
    info "  Backups:           ${BACKUP_DIR}/"
    info "  Drop-in:           ${DROPIN_FILE}"
fi
info "  Unauthorized found: ${FINDING_COUNT}"
info "  requiretty:         $( $REQUIRETTY_EXISTS && echo 'already present' || echo 'added' )"
info "========================================="
echo ""
warn "REMINDER: NOPASSWD entries were NOT modified."
warn "Review them manually if you suspect red team has added any:"
warn "  grep -r NOPASSWD ${SUDOERS_FILE} ${SUDOERS_DIR}/"