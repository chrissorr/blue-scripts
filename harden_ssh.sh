#!/usr/bin/env bash
# =============================================================================
# harden_ssh.sh - Harden SSH configuration on Debian 13 boxes
#
# Usage:
#   sudo ./harden_ssh.sh [--dry-run]
#
# What it does:
#   1. Backs up the current sshd_config before making any changes
#   2. Applies hardened SSH settings via a drop-in config file
#   3. Audits all users' authorized_keys for unrecognized keys
#   4. Restarts sshd to apply changes (skipped in dry-run)
#
# Safety:
#   - Always backs up sshd_config before touching it
#   - Uses a drop-in file in sshd_config.d/ rather than editing sshd_config
#     directly - easier to revert, less risk of corrupting existing config
#   - Validates sshd config before restarting to prevent locking everyone out
#   - AllowUsers is set explicitly - update ALLOWED_USERS before running
#   - Run with --dry-run first to preview all changes
#
# !! READ BEFORE RUNNING !!
#   Populate ALLOWED_USERS and TEAM_PUBKEYS before competition day.
#   Incorrect AllowUsers will lock out legitimate users immediately.
# =============================================================================

set -euo pipefail

# =============================================================================
# !! ALLOWED USERS - EDIT THIS BEFORE COMPETITION DAY !!
#
# Every user listed here will be permitted to SSH into the box.
# Any user NOT listed here will be denied at the SSH level regardless
# of whether their account exists on the system.
#
# =============================================================================
ALLOWED_USERS=(
    "cyberrange"
    "GREYTEAM"
    "scp073"
    "scp343"
    "ntf"
)

# =============================================================================
# !! TEAM PUBLIC KEYS - EDIT THIS BEFORE COMPETITION DAY !!
#
# Paste the full contents of each allowed .pub file as a separate
# entry. Example:
#   "ssh-ed25519 AAAA... user@hostname"
# =============================================================================
TEAM_PUBKEYS=(

)

# =============================================================================
# Configuration
# =============================================================================
DRY_RUN=false
SSHD_CONFIG="/etc/ssh/sshd_config"
DROPIN_DIR="/etc/ssh/sshd_config.d"
DROPIN_FILE="${DROPIN_DIR}/99-blueteam-hardening.conf"
BACKUP_DIR="/root/ssh_backups"

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

if ! command -v sshd &>/dev/null; then
    error "sshd is not installed or not in PATH"
    exit 1
fi

# =============================================================================
# Step 1 - Backup existing sshd_config
# =============================================================================
info "Step 1: Backing up existing SSH configuration..."

if $DRY_RUN; then
    dryrun "Would backup ${SSHD_CONFIG} -> ${BACKUP_DIR}/sshd_config.$(date +%Y%m%d_%H%M%S)"
else
    mkdir -p "$BACKUP_DIR"
    BACKUP_FILE="${BACKUP_DIR}/sshd_config.$(date +%Y%m%d_%H%M%S)"
    cp "$SSHD_CONFIG" "$BACKUP_FILE"
    success "Backed up sshd_config -> ${BACKUP_FILE}"
fi

# =============================================================================
# Step 2 - Enforce SSH host key file permissions
#
# Private host keys must be 600 root:root - readable only by root.
# Public host keys should be 644 root:root - world-readable is fine and
# expected since clients need the public key to verify the host.
# Incorrect permissions on private keys will cause sshd to refuse to start.
# =============================================================================
info "Step 2: Enforcing SSH host key permissions..."

while IFS= read -r -d '' keyfile; do
    if [[ "$keyfile" == *.pub ]]; then
        expected_mode="644"
    else
        expected_mode="600"
    fi

    current_mode=$(stat -c '%a' "$keyfile")
    current_owner=$(stat -c '%U:%G' "$keyfile")

    if [[ "$current_mode" != "$expected_mode" ]] || [[ "$current_owner" != "root:root" ]]; then
        warn "  ${keyfile} - mode: ${current_mode} owner: ${current_owner} (expected: ${expected_mode} root:root)"
        if $DRY_RUN; then
            dryrun "  Would run: chown root:root ${keyfile} && chmod ${expected_mode} ${keyfile}"
        else
            chown root:root "$keyfile"
            chmod "$expected_mode" "$keyfile"
            success "  Fixed: ${keyfile}"
        fi
    else
        success "  ${keyfile} - OK"
    fi
done < <(find /etc/ssh -maxdepth 1 -name 'ssh_host_*' -print0 2>/dev/null)

echo ""

# =============================================================================
# Step 3 - Write drop-in hardening config
#
# We use a drop-in file in sshd_config.d/ rather than editing sshd_config
# directly. 
# This means:
#   - The original sshd_config is untouched
#   - Our changes are isolated to one file - easy to remove or revert
#   - If something goes wrong, rm the drop-in and restart sshd to recover
#   - sshd processes drop-in files in lexical order; 99- prefix ensures
#     our settings are applied last and override earlier defaults
# =============================================================================
info "Step 3: Writing hardened SSH drop-in config..."

# Build the AllowUsers line from our array
ALLOW_USERS_LINE="AllowUsers ${ALLOWED_USERS[*]}"

DROPIN_CONTENT="# =============================================================================
# Blue Team SSH Hardening - applied by harden_ssh.sh
# To revert: rm ${DROPIN_FILE} && systemctl restart sshd
# =============================================================================

# -- Authentication --

# Keep password auth enabled 
PasswordAuthentication yes

# Deny root login entirely - use a privileged user account instead
PermitRootLogin no

# Never allow empty passwords
PermitEmptyPasswords no

# Disable challenge-response auth (PAM-based, separate from password auth)
# Eliminates a secondary auth pathway red team could abuse
KbdInteractiveAuthentication no

# Disable GSSAPI authentication - not used on this network, removes
# a Kerberos-based auth pathway that has no legitimate use here
GSSAPIAuthentication no

# Disable host-based authentication - prevents trust relationships
# between hosts from being exploited for lateral movement
HostbasedAuthentication no

# Ignore .rhosts and .shosts files - these are ancient trust mechanisms
# that should never be used in a modern environment
IgnoreRhosts yes

# Ensure PAM is enabled so PAM controls (lockout, password policy)
# apply to SSH sessions as well as local logins
UsePAM yes

# -- Access Control --

# Only these users may authenticate via SSH
# Any user not listed is denied before authentication even begins
${ALLOW_USERS_LINE}

# -- Attack Surface Reduction --

# Disable X11 forwarding - no GUI needed, removes a tunneling vector
X11Forwarding no

# Disable all forwarding in one directive (TCP, agent, X11)
DisableForwarding yes

# Disable TCP forwarding - prevents SSH being used as a tunnel/proxy
AllowTcpForwarding no

# Disable agent forwarding - prevents key forwarding attacks
AllowAgentForwarding no

# Disable SSH tunneling
PermitTunnel no

# -- Cryptography --
# Restrict to modern, vetted algorithms only.
# These drop SSHv1 remnants, CBC-mode ciphers, MD5/SHA1 MACs,
# and weak key exchange algorithms that are exploitable.
#
# NOTE: If the scoring checker uses an outdated SSH client it may
# fail to connect after these are applied. Check journalctl -u sshd
# immediately after reloading if scoring drops.

# Key exchange - only Diffie-Hellman and ECDH with strong curves
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521

# Ciphers - AES-GCM and ChaCha20 only, all CBC-mode dropped
Ciphers chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com

# MACs - HMAC-SHA2 and ETM variants only, MD5 and SHA1 dropped
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512

# -- Session & Timeout --

# Check client liveness every 60 seconds
ClientAliveInterval 60

# Drop connection after 3 missed checks (3 minutes of silence = disconnect)
# Kills abandoned/dead shells red team may have left open
ClientAliveCountMax 3

# Limit authentication attempts per connection
# Reduces brute force effectiveness
MaxAuthTries 3

# Limit concurrent unauthenticated connections
# Mitigates connection flood attacks
MaxStartups 5

# -- Logging --

# Verbose logging - captures authentication attempts, key fingerprints
# Useful for intrusion detection during competition
LogLevel VERBOSE
"

if $DRY_RUN; then
    dryrun "Would create drop-in config at ${DROPIN_FILE}:"
    echo ""
    echo "$DROPIN_CONTENT"
    echo ""
else
    mkdir -p "$DROPIN_DIR"
    echo "$DROPIN_CONTENT" > "$DROPIN_FILE"
    chmod 600 "$DROPIN_FILE"
    success "Drop-in config written to ${DROPIN_FILE}"
fi

# =============================================================================
# Step 4 - Validate configuration before restarting
#
# sshd -t performs a full config test without actually restarting the daemon.
# If this fails, we abort rather than restarting into a broken config and
# locking everyone out.
# =============================================================================
info "Step 4: Validating SSH configuration..."

if $DRY_RUN; then
    dryrun "Would run: sshd -t"
else
    if sshd -t; then
        success "SSH configuration is valid"
    else
        error "SSH configuration validation FAILED"
        error "Removing broken drop-in file to prevent lockout..."
        rm -f "$DROPIN_FILE"
        error "Drop-in removed. sshd config is back to its previous state."
        error "Check ${DROPIN_FILE} syntax and re-run."
        exit 1
    fi
fi

# =============================================================================
# Step 5 - Audit authorized_keys files
#
# Check every user's ~/.ssh/authorized_keys for keys that don't belong
# to our team. We flag unauthorized keys but do NOT automatically remove them -
# removal is a manual decision to avoid accidentally removing a grey team key
# =============================================================================
info "Step 5: Auditing authorized_keys files..."
echo ""

# Build a lookup set of known team keys
declare -A KNOWN_KEYS
for key in "${TEAM_PUBKEYS[@]}"; do
    KNOWN_KEYS["$key"]=1
done

UNAUTH_FOUND=0

# Check root's authorized_keys
AUTH_TARGETS=("/root")

# Check all human user home directories
while IFS=: read -r _ _ uid _ _ home _; do
    [[ "$uid" -lt 1000 ]] && continue
    [[ "$uid" -eq 65534 ]] && continue
    [[ -d "$home" ]] && AUTH_TARGETS+=("$home")
done < /etc/passwd

for home in "${AUTH_TARGETS[@]}"; do
    AUTH_FILE="${home}/.ssh/authorized_keys"

    [[ -f "$AUTH_FILE" ]] || continue

    info "Checking ${AUTH_FILE}..."

    while IFS= read -r line || [[ -n "$line" ]]; do
        # Skip blank lines and comments
        [[ -z "$line" ]] && continue
        [[ "$line" == \#* ]] && continue

        if [[ ${#TEAM_PUBKEYS[@]} -eq 0 ]]; then
            # No team keys configured - flag everything as unverified
            warn "  UNVERIFIED KEY (no team keys configured): ${line:0:60}..."
            (( UNAUTH_FOUND++ )) || true
        elif [[ -z "${KNOWN_KEYS[$line]+_}" ]]; then
            warn "  UNAUTHORIZED KEY FOUND in ${AUTH_FILE}:"
            warn "  ${line:0:80}..."
            warn "  -> Manual review required. Remove if not a team or grey team key."
            (( UNAUTH_FOUND++ )) || true
        else
            success "  Recognized team key: ${line:0:60}..."
        fi

    done < "$AUTH_FILE"
done

echo ""
if [[ "$UNAUTH_FOUND" -gt 0 ]]; then
    warn "authorized_keys audit: ${UNAUTH_FOUND} unrecognized key(s) found - review manually"
else
    success "authorized_keys audit: all keys accounted for"
fi

# =============================================================================
# Step 6 - Restart sshd to apply changes
#
# We only reach this point if sshd -t passed. Do NOT use restart - use
# reload where possible so existing sessions aren't dropped. On Debian,
# systemctl reload sshd re-reads the config without killing active sessions.
# =============================================================================
info "Step 6: Reloading sshd..."

if $DRY_RUN; then
    dryrun "Would run: systemctl reload sshd"
else
    if systemctl reload sshd; then
        success "sshd reloaded successfully - new config is active"
    else
        warn "systemctl reload failed - attempting restart..."
        if systemctl restart sshd; then
            success "sshd restarted successfully"
        else
            error "sshd failed to restart - check: journalctl -u sshd"
            exit 1
        fi
    fi
fi

# =============================================================================
# Summary
# =============================================================================
echo ""
info "========================================="
info "SSH Hardening Summary"
info "========================================="
if $DRY_RUN; then
    info "  Mode:          DRY-RUN (no changes made)"
else
    info "  Backup:        ${BACKUP_FILE}"
    info "  Drop-in:       ${DROPIN_FILE}"
    info "  sshd status:   reloaded"
fi
info "  AllowUsers:    ${ALLOWED_USERS[*]}"
info "  Unauth keys:   ${UNAUTH_FOUND}"
info "========================================="
echo ""