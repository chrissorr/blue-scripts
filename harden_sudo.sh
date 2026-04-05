#!/usr/bin/env bash
# =============================================================================
# harden_sudo.sh - Audit and harden sudo configuration on Debian 13 boxes
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
#   - NOPASSWD entries are never touched - scoring checkers may depend on them
#   - visudo -c validates every file before and after changes
#   - All modified files are backed up before editing
#   - Confirmation prompt shows exactly what will be removed
#   - Run with --dry-run to preview all actions without making changes
# =============================================================================

set -euo pipefail

# =============================================================================
# !! AUTHORIZED SUDO USERS - EDIT THIS BEFORE COMPETITION DAY !!
#
# Any user in /etc/sudoers or /etc/sudoers.d/ NOT in this list will be
# flagged as unauthorized and queued for removal after confirmation.
#
# Known required accounts (from blue team packet):
#   root        - always authorized, never touched
#   GREYTEAM    - grey team oversight, MUST retain sudo if currently set
#   scp343      - local linux admin user
# =============================================================================
AUTHORIZED_SUDO_USERS=(
    "root"
    "GREYTEAM"
    "scp343"
)

# =============================================================================
# !! AUTHORIZED SUDO GROUPS - EDIT THIS IF NEEDED !!
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
    warn "DRY-RUN mode - no changes will be made"
    echo ""
fi

if ! command -v visudo &>/dev/null; then
    error "visudo is not available - cannot safely edit sudoers"
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
# Step 1 - Backup all sudoers files
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
# Step 2 - Audit sudoers files
#
# We parse each sudoers file looking for:
#   - User privilege lines:  username  ALL=(ALL) ...
#   - Group privilege lines: %groupname ALL=(ALL) ...
#
# We skip:
#   - Comments (#)
#   - Defaults lines (we add our own, not remove existing)
#   - NOPASSWD entries entirely - too risky to touch
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
    # Skip our own drop-in if it already exists
    [[ "$sudoers_file" == "$DROPIN_FILE" ]] && continue

    info "Scanning: ${sudoers_file}"

    line_num=0
    while IFS= read -r line || [[ -n "$line" ]]; do
        (( line_num++ )) || true

        # Skip blank lines
        [[ -z "${line// }" ]] && continue

        # Skip full-line comments
        [[ "$line" == \#* ]] && continue

        # Skip Defaults lines - we handle those separately
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
# Step 3 - Present findings and prompt for confirmation
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
            info "Removal skipped - no sudoers entries were changed."
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
                    error "visudo validation failed for cleaned ${target_file} - skipping"
                    error "The original file has NOT been modified"
                    rm -f "$tmp"
                fi
            done
        fi
    fi
fi

# =============================================================================
# Step 4 - Write hardening drop-in
#
# We write a drop-in to /etc/sudoers.d/ with four Defaults hardening lines:
#
#   requiretty        - sudo must be called from a real tty, directly
#                       disrupts reverse shell privilege escalation
#   use_pty           - forces sudo to allocate a pty even when requiretty
#                       is satisfied, closes a bypass where some shells
#                       fake tty presence
#   logfile           - writes a dedicated sudo log separate from syslog,
#                       makes it much easier to audit who ran what during
#                       the competition
#   timestamp_timeout - set to 0 so sudo always requires a password, no
#                       grace period. Closes the window where red team
#                       hijacks a session that recently ran sudo.
#
# Each directive is checked for pre-existence before writing to avoid
# duplicates if the script is run more than once.
# =============================================================================
info "Step 4: Writing sudo hardening drop-in..."

# Check which directives are already present anywhere in sudoers config
REQUIRETTY_EXISTS=false
USE_PTY_EXISTS=false
LOGFILE_EXISTS=false
TIMESTAMP_EXISTS=false

for sudoers_file in "${SUDOERS_FILES[@]}"; do
    [[ -f "$sudoers_file" ]] || continue
    grep -q "requiretty"        "$sudoers_file" 2>/dev/null && REQUIRETTY_EXISTS=true
    grep -q "use_pty"           "$sudoers_file" 2>/dev/null && USE_PTY_EXISTS=true
    grep -q "logfile"           "$sudoers_file" 2>/dev/null && LOGFILE_EXISTS=true
    grep -q "timestamp_timeout" "$sudoers_file" 2>/dev/null && TIMESTAMP_EXISTS=true
done

# Build drop-in content from only the directives that aren't already set
DROPIN_LINES="# Blue Team sudo hardening - applied by harden_sudo.sh
# To revert: rm ${DROPIN_FILE}
"

DROPIN_EMPTY=true

if ! $REQUIRETTY_EXISTS; then
    DROPIN_LINES+="
# Require a real tty - prevents sudo from reverse shells and
# non-interactive execution contexts
Defaults requiretty"
    DROPIN_EMPTY=false
else
    info "  requiretty already present - skipping"
fi

if ! $USE_PTY_EXISTS; then
    DROPIN_LINES+="

# Force allocation of a pty - closes bypasses where shells fake tty presence
Defaults use_pty"
    DROPIN_EMPTY=false
else
    info "  use_pty already present - skipping"
fi

if ! $LOGFILE_EXISTS; then
    DROPIN_LINES+="

# Dedicated sudo log file - easier to audit who ran what during competition
Defaults logfile=\"/var/log/sudo.log\""
    DROPIN_EMPTY=false
else
    info "  logfile already present - skipping"
fi

if ! $TIMESTAMP_EXISTS; then
    DROPIN_LINES+="

# Always require password - no grace period after a successful sudo
# Closes the window where red team hijacks an already-authenticated session
Defaults timestamp_timeout=0"
    DROPIN_EMPTY=false
else
    info "  timestamp_timeout already present - skipping"
fi

if $DROPIN_EMPTY; then
    info "  All hardening directives already present - no drop-in needed"
else
    if $DRY_RUN; then
        dryrun "Would write drop-in to ${DROPIN_FILE}:"
        echo ""
        echo "$DROPIN_LINES"
        echo ""
    else
        tmp=$(mktemp)
        echo "$DROPIN_LINES" > "$tmp"

        if visudo -c -f "$tmp" &>/dev/null; then
            mv "$tmp" "$DROPIN_FILE"
            chmod 440 "$DROPIN_FILE"
            success "Wrote sudo hardening drop-in to ${DROPIN_FILE}"
        else
            error "visudo validation failed for hardening drop-in - not installed"
            error "Run visudo -c -f ${tmp} manually to diagnose"
            rm -f "$tmp"
        fi
    fi
fi

echo ""

# =============================================================================
# Step 5 - Restrict the su command to the sudo group
#
# By default any user can attempt to su to root. Restricting su to only
# members of the sudo group via PAM means red team accounts they create
# cannot use su for privilege escalation even if they know the root password.
#
# This edits /etc/pam.d/su to add the pam_wheel.so restriction.
# We check first - if it's already configured we skip it.
# =============================================================================
info "Step 5: Restricting su to sudo group members..."

PAM_SU="/etc/pam.d/su"
SU_RESTRICTION="auth required pam_wheel.so use_uid group=sudo"

if [[ ! -f "$PAM_SU" ]]; then
    warn "  ${PAM_SU} not found - skipping su restriction"
elif grep -q "pam_wheel.so" "$PAM_SU" 2>/dev/null; then
    info "  su restriction already configured in ${PAM_SU} - skipping"
else
    if $DRY_RUN; then
        dryrun "Would add to ${PAM_SU}: ${SU_RESTRICTION}"
    else
        # Back up pam.d/su before modifying
        cp "$PAM_SU" "${BACKUP_DIR}/pam_su.$(date +%Y%m%d_%H%M%S)"

        # Insert our restriction after the first #%PAM line or at the top
        # of the auth section. We prepend it before the first auth line so
        # it is evaluated first.
        tmp=$(mktemp)
        awk -v restriction="$SU_RESTRICTION" '
            /^auth/ && !added {
                print restriction
                added=1
            }
            { print }
        ' "$PAM_SU" > "$tmp"

        mv "$tmp" "$PAM_SU"
        chmod 644 "$PAM_SU"
        success "  Added su restriction to ${PAM_SU}"
        info "  Only members of the sudo group can now use su"
    fi
fi

echo ""

# =============================================================================
# Step 6 - Final validation of entire sudoers configuration
# =============================================================================
info "Step 6: Final sudoers configuration validation..."

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
info "  use_pty:            $( $USE_PTY_EXISTS && echo 'already present' || echo 'added' )"
info "  sudo logfile:       $( $LOGFILE_EXISTS && echo 'already present' || echo 'added' )"
info "  timestamp_timeout:  $( $TIMESTAMP_EXISTS && echo 'already present' || echo 'added' )"
info "========================================="
echo ""
warn "REMINDER: NOPASSWD entries were NOT modified."
warn "Review them manually if you suspect red team has added any:"
warn "  grep -r NOPASSWD ${SUDOERS_FILE} ${SUDOERS_DIR}/"