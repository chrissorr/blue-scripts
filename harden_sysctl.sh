#!/usr/bin/env bash
# =============================================================================
# harden_sysctl.sh - Kernel parameter hardening for Debian 13 boxes
#
# Usage:
#   sudo ./harden_sysctl.sh [--dry-run]
#
# What it does:
#   1. Writes a hardened sysctl drop-in to /etc/sysctl.d/99-blueteam.conf
#   2. Validates each parameter is recognized by the running kernel
#   3. Applies settings immediately with sysctl --system
#   4. Verifies each setting took effect after application
#
# Safety:
#   - Uses a drop-in file - never touches /etc/sysctl.conf directly
#   - Validates each parameter exists before writing the file
#   - Verifies applied values match expected values after application
#   - Fully reversible: rm /etc/sysctl.d/99-blueteam.conf && sysctl --system
#   - Run with --dry-run to preview all parameters without applying
#
# Parameters applied cover:
#   - Network hardening (IP forwarding, redirects, spoofing, SYN floods)
#   - Kernel hardening (ASLR, ptrace, dmesg, pointer exposure)
#   - Filesystem hardening (hardlinks, symlinks, SUID core dumps)
# =============================================================================

set -euo pipefail

# =============================================================================
# Sysctl parameters to enforce
#
# Format: "parameter=value:comment"
# Comment is printed during the run and written into the drop-in file.
#
# These are all CIS Debian 13 Level 1 recommendations unless noted.
# None of these should affect service availability on a web/database box.
# =============================================================================
SYSCTL_PARAMS=(
    # -- Network: IP Forwarding --
    # This box is not a router. Forwarding packets between interfaces
    # enables red team to use it as a pivot point into other subnets.
    "net.ipv4.ip_forward=0:Disable IPv4 packet forwarding"
    "net.ipv4.conf.all.forwarding=0:Disable forwarding on all IPv4 interfaces"
    "net.ipv4.conf.default.forwarding=0:Disable forwarding on new IPv4 interfaces"
    "net.ipv6.conf.all.forwarding=0:Disable IPv6 packet forwarding"
    "net.ipv6.conf.default.forwarding=0:Disable forwarding on new IPv6 interfaces"

    # -- Network: ICMP Redirects --
    # ICMP redirects can be used to manipulate routing tables and redirect
    # traffic through an attacker-controlled host. We neither send nor accept.
    "net.ipv4.conf.all.send_redirects=0:Do not send ICMP redirects"
    "net.ipv4.conf.default.send_redirects=0:Do not send ICMP redirects on new interfaces"
    "net.ipv4.conf.all.accept_redirects=0:Ignore incoming ICMP redirects (IPv4)"
    "net.ipv4.conf.default.accept_redirects=0:Ignore ICMP redirects on new IPv4 interfaces"
    "net.ipv6.conf.all.accept_redirects=0:Ignore incoming ICMP redirects (IPv6)"
    "net.ipv6.conf.default.accept_redirects=0:Ignore ICMP redirects on new IPv6 interfaces"
    "net.ipv4.conf.all.secure_redirects=0:Reject secure ICMP redirects (still a redirect)"
    "net.ipv4.conf.default.secure_redirects=0:Reject secure redirects on new interfaces"

    # -- Network: Source Routing --
    # Source-routed packets let the sender specify the route through the network.
    # This is almost never legitimate and is commonly used in spoofing attacks.
    "net.ipv4.conf.all.accept_source_route=0:Reject source-routed IPv4 packets"
    "net.ipv4.conf.default.accept_source_route=0:Reject source routing on new IPv4 interfaces"
    "net.ipv6.conf.all.accept_source_route=0:Reject source-routed IPv6 packets"
    "net.ipv6.conf.default.accept_source_route=0:Reject source routing on new IPv6 interfaces"

    # -- Network: Router Advertisements --
    # IPv6 router advertisements can be used to redirect traffic or perform
    # MitM attacks. This box does not need to accept them.
    "net.ipv6.conf.all.accept_ra=0:Ignore IPv6 router advertisements"
    "net.ipv6.conf.default.accept_ra=0:Ignore router advertisements on new interfaces"

    # -- Network: Spoofing & Bogus Packets --
    # Reverse path filtering drops packets whose source address has no route
    # back through the interface it arrived on - catches spoofed packets.
    # Log martians records packets with impossible source addresses for detection.
    "net.ipv4.conf.all.rp_filter=1:Enable reverse path filtering (anti-spoofing)"
    "net.ipv4.conf.default.rp_filter=1:Enable reverse path filtering on new interfaces"
    "net.ipv4.conf.all.log_martians=1:Log packets with impossible source addresses"
    "net.ipv4.conf.default.log_martians=1:Log martian packets on new interfaces"
    "net.ipv4.icmp_ignore_bogus_error_responses=1:Ignore bogus ICMP error responses"
    "net.ipv4.icmp_echo_ignore_broadcasts=1:Ignore broadcast ICMP echo (Smurf attack mitigation)"

    # -- Network: SYN Flood Protection --
    # SYN cookies prevent SYN flood attacks from exhausting connection state.
    # This is particularly relevant for the Apache box under scoring pressure.
    "net.ipv4.tcp_syncookies=1:Enable SYN cookies for SYN flood protection"

    # -- Kernel: Memory & Exploit Mitigations --
    # ASLR randomizes memory layout on every execution, making memory
    # corruption exploits significantly harder to reliably target.
    # Value 2 = full randomization (stack, heap, mmap, VDSO).
    "kernel.randomize_va_space=2:Enable full ASLR"

    # Restrict dmesg to root only. The kernel ring buffer contains kernel
    # addresses, driver info, and boot messages useful for exploit development.
    "kernel.dmesg_restrict=1:Restrict dmesg to root only"

    # Restrict kernel pointer exposure in /proc and other interfaces.
    # Value 2 = hide pointers from all users including root (requires CAP_SYSLOG).
    "kernel.kptr_restrict=2:Hide kernel pointers from unprivileged users"

    # -- Kernel: ptrace Scope --
    # ptrace allows a process to inspect and control another process's memory
    # and execution. This is a common privilege escalation vector.
    # Value 1 = only a parent process may ptrace its children (Yama LSM).
    "kernel.yama.ptrace_scope=1:Restrict ptrace to parent-child relationships"

    # -- Filesystem: Link Protections --
    # Without these, unprivileged users can create hardlinks to SUID files
    # or symlinks in shared directories that redirect privileged operations.
    # Both are classic local privilege escalation techniques.
    "fs.protected_hardlinks=1:Prevent hardlink attacks on SUID files"
    "fs.protected_symlinks=1:Prevent symlink attacks in shared directories"

    # -- Filesystem: Core Dumps --
    # Prevent SUID processes from creating core dumps. Core dumps from
    # privileged processes can expose sensitive memory contents including
    # credentials, keys, and other secrets.
    "fs.suid_dumpable=0:Disable core dumps from SUID processes"
)

# =============================================================================
# Configuration
# =============================================================================
DRY_RUN=false
DROPIN_FILE="/etc/sysctl.d/99-blueteam.conf"
BACKUP_DIR="/root/sysctl_backups"

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

if ! command -v sysctl &>/dev/null; then
    error "sysctl is not available"
    exit 1
fi

# =============================================================================
# Step 1 - Backup existing drop-in if present
# =============================================================================
info "Step 1: Checking for existing sysctl drop-in..."

if $DRY_RUN; then
    if [[ -f "$DROPIN_FILE" ]]; then
        dryrun "Would backup existing ${DROPIN_FILE}"
    else
        dryrun "No existing drop-in found - would create fresh"
    fi
else
    if [[ -f "$DROPIN_FILE" ]]; then
        mkdir -p "$BACKUP_DIR"
        BACKUP_FILE="${BACKUP_DIR}/99-blueteam.conf.$(date +%Y%m%d_%H%M%S)"
        cp "$DROPIN_FILE" "$BACKUP_FILE"
        success "Backed up existing drop-in -> ${BACKUP_FILE}"
    else
        info "No existing drop-in found - will create fresh"
    fi
fi

# =============================================================================
# Step 2 - Validate all parameters are recognized by the kernel
#
# Before writing anything, we check that every parameter in our list is
# a real sysctl key on this kernel. Parameters that don't exist on the
# running kernel would cause sysctl --system to emit errors (though it
# continues). We skip unrecognized parameters and warn rather than failing.
#
# This also catches cases where a kernel module needed for a parameter
# (e.g. kernel.yama.ptrace_scope requires the Yama LSM) is not loaded.
# =============================================================================
info "Step 2: Validating parameters against running kernel..."
echo ""

VALID_PARAMS=()
SKIP_COUNT=0

for entry in "${SYSCTL_PARAMS[@]}"; do
    param="${entry%%=*}"
    # Strip the comment from the value (everything after the last colon
    # that follows the equals sign)
    rest="${entry#*=}"
    value="${rest%%:*}"
    comment="${rest#*:}"

    if sysctl "$param" &>/dev/null; then
        success "  Recognized: ${param}"
        VALID_PARAMS+=("${param}=${value}:${comment}")
    else
        warn "  NOT FOUND on this kernel: ${param} - skipping"
        (( SKIP_COUNT++ )) || true
    fi
done

echo ""
info "  ${#VALID_PARAMS[@]} parameters valid, ${SKIP_COUNT} skipped"
echo ""

if [[ "${#VALID_PARAMS[@]}" -eq 0 ]]; then
    error "No valid parameters found - nothing to apply"
    exit 1
fi

# =============================================================================
# Step 3 - Write drop-in file
#
# We write only the validated parameters. The file is structured with
# section comments matching our parameter groupings for readability.
# =============================================================================
info "Step 3: Writing sysctl drop-in..."

# Build file content
DROPIN_CONTENT="# =============================================================================
# Blue Team kernel hardening - applied by harden_sysctl.sh
# CIS Debian 13 Benchmark - Level 1 recommendations
#
# To revert:
#   rm ${DROPIN_FILE}
#   sysctl --system
# =============================================================================

"

for entry in "${VALID_PARAMS[@]}"; do
    param="${entry%%=*}"
    rest="${entry#*=}"
    value="${rest%%:*}"
    comment="${rest#*:}"
    DROPIN_CONTENT+="# ${comment}
${param} = ${value}

"
done

if $DRY_RUN; then
    dryrun "Would write to ${DROPIN_FILE}:"
    echo ""
    echo "$DROPIN_CONTENT"
else
    echo "$DROPIN_CONTENT" > "$DROPIN_FILE"
    chmod 644 "$DROPIN_FILE"
    success "Drop-in written to ${DROPIN_FILE}"
fi

# =============================================================================
# Step 4 - Apply settings
#
# sysctl --system reads all drop-in files in /etc/sysctl.d/ in lexical
# order and applies them. Our 99- prefix ensures our settings are applied
# last and win any conflicts with distro defaults.
#
# We capture stderr to detect any errors during application.
# =============================================================================
info "Step 4: Applying sysctl settings..."
echo ""

if $DRY_RUN; then
    dryrun "Would run: sysctl --system"
else
    SYSCTL_ERRORS=0

    while IFS= read -r line; do
        if [[ "$line" == *"error"* ]] || [[ "$line" == *"No such file"* ]]; then
            warn "  ${line}"
            (( SYSCTL_ERRORS++ )) || true
        else
            info "  ${line}"
        fi
    done < <(sysctl --system 2>&1)

    echo ""
    if [[ "$SYSCTL_ERRORS" -gt 0 ]]; then
        warn "${SYSCTL_ERRORS} error(s) during application - review output above"
    else
        success "All settings applied without errors"
    fi
fi

# =============================================================================
# Step 5 - Verify applied values
#
# After applying, we read each parameter back from the live kernel and
# confirm the value matches what we intended. This catches cases where
# a parameter was accepted syntactically but silently not applied.
# =============================================================================
info "Step 5: Verifying applied values..."
echo ""

if $DRY_RUN; then
    dryrun "Would verify each parameter value from live kernel"
else
    VERIFY_PASS=0
    VERIFY_FAIL=0

    for entry in "${VALID_PARAMS[@]}"; do
        param="${entry%%=*}"
        rest="${entry#*=}"
        expected_value="${rest%%:*}"

        actual_value=$(sysctl -n "$param" 2>/dev/null || echo "ERROR")

        if [[ "$actual_value" == "$expected_value" ]]; then
            success "  ${param} = ${actual_value}"
            (( VERIFY_PASS++ )) || true
        else
            warn "  MISMATCH: ${param} expected=${expected_value} actual=${actual_value}"
            (( VERIFY_FAIL++ )) || true
        fi
    done

    echo ""
    if [[ "$VERIFY_FAIL" -gt 0 ]]; then
        warn "${VERIFY_FAIL} parameter(s) did not apply as expected"
        warn "This may indicate a kernel module is not loaded or a conflicting setting"
        warn "Check: sysctl -a | grep <parameter>"
    else
        success "All ${VERIFY_PASS} parameters verified successfully"
    fi
fi

# =============================================================================
# Summary
# =============================================================================
echo ""
info "========================================="
info "Sysctl Hardening Summary"
info "========================================="
if $DRY_RUN; then
    info "  Mode:         DRY-RUN (no changes made)"
    info "  Would apply:  ${#VALID_PARAMS[@]} parameters"
    info "  Skipped:      ${SKIP_COUNT} (not found on this kernel)"
else
    info "  Drop-in:      ${DROPIN_FILE}"
    info "  Applied:      ${#VALID_PARAMS[@]} parameters"
    info "  Skipped:      ${SKIP_COUNT} (not found on this kernel)"
    info "  Verified OK:  ${VERIFY_PASS:-0}"
    info "  Mismatches:   ${VERIFY_FAIL:-0}"
fi
info "========================================="
echo ""
info "To revert all changes:"
info "  rm ${DROPIN_FILE} && sysctl --system"