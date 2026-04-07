#!/usr/bin/env bash
# =============================================================================
# harden_firewall.sh - UFW firewall configuration for Debian 13 boxes
#
# Usage:
#   sudo ./harden_firewall.sh [--dry-run]
#
# What it does:
#   1. Installs UFW if not present
#   2. Resets UFW to a clean state before applying rules
#   3. Sets default deny inbound, default deny outbound
#   4. Allows inbound: SSH (22), HTTP (80), HTTPS (443)
#   5. Allows outbound: DNS (53), HTTP (80), HTTPS (443), NTP (123 UDP)
#   6. Allows all traffic on the loopback interface
#   7. Enables UFW and verifies the ruleset
#
# Safety:
#   - Grey team subnet is explicitly allowed inbound and outbound
#     before any default deny is applied - they can never be blocked
#   - Established/related connections are allowed so active sessions
#     are not dropped when the firewall is enabled
#   - SSH is allowed BEFORE enabling UFW - cannot lock ourselves out
#   - Run --dry-run to print the full UFW command sequence without
#     executing anything
#
# !! READ BEFORE RUNNING !!
#   Check EXTRA_INBOUND_PORTS against the grey team packet before running.
#   If the scoring checker connects on a port not in our allowlist,
#   we will lose 30 points per check until the port is opened.
#   UFW rules take effect immediately when UFW is enabled.
#
# Competition rules compliance:
#   - We do NOT block entire subnets (rule #8)
#   - We do NOT restrict grey team IPs (rule #8)
#   - Grey team subnet 10.10.10.200/24 is explicitly whitelisted
# =============================================================================

set -euo pipefail

# =============================================================================
# !! EXTRA INBOUND PORTS - FILL IN BEFORE COMPETITION DAY !!
#
# Add any ports the scoring checker or legitimate services need beyond
# SSH (22), HTTP (80), and HTTPS (443). Check the grey team packet
# carefully before running this script.
#
# Format: "port/protocol" e.g. "3306/tcp" for MySQL, "5432/tcp" for Postgres
# =============================================================================
EXTRA_INBOUND_PORTS=(
    # "3306/tcp"   # MySQL/MariaDB - add if scoring checks DB directly
    # "5432/tcp"   # PostgreSQL
    # "8080/tcp"   # Alternative HTTP
)

# =============================================================================
# !! GREY TEAM SUBNET - VERIFY AGAINST PACKET BEFORE RUNNING !!
#
# All traffic from this subnet is explicitly allowed inbound and outbound.
# This must never be blocked regardless of any other rule.
# From the blue team packet topology: grey team is at 10.10.10.200/24
# =============================================================================
GREYTEAM_SUBNET="10.10.10.200/24"

# =============================================================================
# Configuration
# =============================================================================
DRY_RUN=false

# Standard inbound ports - do not remove these
INBOUND_PORTS=(
    "22/tcp"    # SSH
    "80/tcp"    # HTTP
    "443/tcp"   # HTTPS
)

# Outbound allowlist - services this box legitimately needs to reach
# Keeping this tight directly disrupts reverse shell callbacks
OUTBOUND_RULES=(
    "53/tcp"    # DNS over TCP (zone transfers, large responses)
    "53/udp"    # DNS over UDP (standard queries)
    "80/tcp"    # HTTP outbound (apt, package managers)
    "443/tcp"   # HTTPS outbound (apt, package managers, updates)
    "123/udp"   # NTP - clock sync, affects log timestamps
    "3306/tcp"  # MySQL - allow outbound to database box
)

# =============================================================================
# Helpers
# =============================================================================
info()    { echo "[*] $*"; }
success() { echo "[+] $*"; }
warn()    { echo "[!] $*" >&2; }
error()   { echo "[-] $*" >&2; }
dryrun()  { echo "[DRY-RUN] $*"; }

# Wrapper that either runs a ufw command or prints it in dry-run mode
ufw_cmd() {
    if $DRY_RUN; then
        dryrun "ufw $*"
    else
        ufw "$@"
    fi
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
    warn "DRY-RUN mode - no changes will be made"
    echo ""
fi

# =============================================================================
# Step 1 - Install UFW if not present
# =============================================================================
info "Step 1: Checking UFW installation..."

if command -v ufw &>/dev/null; then
    success "UFW is already installed"
else
    warn "UFW not found - installing..."
    if $DRY_RUN; then
        dryrun "Would run: apt-get install -y ufw"
    else
        apt-get install -y ufw &>/dev/null \
            && success "UFW installed" \
            || { error "UFW installation failed"; exit 1; }
    fi
fi

echo ""

# =============================================================================
# Step 2 - Reset UFW to clean state
#
# We reset before applying rules to guarantee a known clean baseline.
# This removes any rules that may have been added manually or by a
# previous run of this script, preventing duplicate or conflicting rules.
#
# Reset disables UFW while clearing rules - it will NOT interrupt
# existing connections since the kernel netfilter rules are removed
# along with UFW's management of them.
# =============================================================================
info "Step 2: Resetting UFW to clean state..."

if $DRY_RUN; then
    dryrun "ufw --force reset"
else
    ufw --force reset &>/dev/null
    success "UFW reset to clean state"
fi

echo ""

# =============================================================================
# Step 3 - Set default policies
#
# Default deny inbound: any connection not explicitly allowed is dropped.
# Default deny outbound: any outbound connection not explicitly allowed
# is dropped. This directly disrupts reverse shell callbacks - red team
# shells can connect inbound (they'll hit our SSH rules) but cannot
# call back out to arbitrary attacker IPs and ports.
#
# Default deny routed: this box does not route packets between interfaces.
# =============================================================================
info "Step 3: Setting default policies..."

ufw_cmd default deny incoming
ufw_cmd default deny outgoing
ufw_cmd default deny routed

echo ""

# =============================================================================
# Step 4 - Allow loopback interface
#
# Loopback (127.0.0.1/::1) traffic must always be allowed. Many services
# communicate with themselves over loopback - Apache to local sockets,
# database connections from localhost, etc. Blocking loopback breaks
# almost everything.
# =============================================================================
info "Step 4: Allowing loopback traffic..."

ufw_cmd allow in on lo
ufw_cmd allow out on lo

echo ""

# =============================================================================
# Step 5 - Allow grey team subnet unconditionally
#
# Grey team must always be able to reach this box from any direction.
# We add these rules BEFORE enabling UFW so there is zero window where
# grey team could be blocked.
#
# Competition rule #8 explicitly prohibits restricting Overseer IPs.
# This is our hardcoded compliance with that rule.
# =============================================================================
info "Step 5: Explicitly allowing grey team subnet (${GREYTEAM_SUBNET})..."

ufw_cmd allow in from "$GREYTEAM_SUBNET"
ufw_cmd allow out to "$GREYTEAM_SUBNET"

success "Grey team subnet ${GREYTEAM_SUBNET} - fully whitelisted"
echo ""

# =============================================================================
# Step 6 - Allow established and related connections
#
# This is critical. Without this rule, enabling the firewall would
# immediately terminate all existing SSH sessions and other connections
# because return traffic for those sessions would be dropped.
#
# UFW handles this via before.rules but we make it explicit here.
# =============================================================================
info "Step 6: Allowing established/related connections..."

if $DRY_RUN; then
    dryrun "ufw allow in established,related (via before.rules - handled by UFW)"
else
    # UFW's default before.rules handles ESTABLISHED,RELATED via iptables
    # We verify the before.rules file contains the expected stateful rules
    if grep -q "ESTABLISHED,RELATED" /etc/ufw/before.rules 2>/dev/null; then
        success "Stateful connection tracking confirmed in UFW before.rules"
    else
        warn "ESTABLISHED,RELATED rule not found in before.rules - adding manually"
        # Prepend to before.rules INPUT chain
        sed -i '/^-A ufw-before-input/i -A ufw-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT' \
            /etc/ufw/before.rules
    fi
fi

echo ""

# =============================================================================
# Step 7 - Allow inbound ports
#
# We allow SSH first - this is the most important rule. If SSH is not
# allowed before UFW is enabled we lock ourselves out immediately.
# =============================================================================
info "Step 7: Configuring inbound rules..."

# Combine standard and extra ports
ALL_INBOUND=("${INBOUND_PORTS[@]}" "${EXTRA_INBOUND_PORTS[@]}")

for port_proto in "${ALL_INBOUND[@]}"; do
    port="${port_proto%%/*}"
    proto="${port_proto##*/}"

    case "$port" in
        22)   label="SSH" ;;
        80)   label="HTTP" ;;
        443)  label="HTTPS" ;;
        *)    label="custom" ;;
    esac

    ufw_cmd allow in proto "$proto" to any port "$port"
    info "  Allowed inbound: ${port}/${proto} (${label})"
done

echo ""

# =============================================================================
# Step 8 - Allow outbound ports
#
# We allow only the minimum required for legitimate service operation.
# Everything else is denied - including the arbitrary high ports that
# reverse shells use to call back to attacker infrastructure.
# =============================================================================
info "Step 8: Configuring outbound rules..."

for port_proto in "${OUTBOUND_RULES[@]}"; do
    port="${port_proto%%/*}"
    proto="${port_proto##*/}"

    case "$port" in
        53)   label="DNS" ;;
        80)   label="HTTP" ;;
        443)  label="HTTPS" ;;
        123)  label="NTP" ;;
        *)    label="custom" ;;
    esac

    ufw_cmd allow out proto tcp to 10.10.10.102 port 3306
    ufw_cmd allow out proto "$proto" to any port "$port"
    info "  Allowed outbound: ${port}/${proto} (${label})"
done

echo ""

# =============================================================================
# Step 9 - Enable UFW
#
# We enable with --force to suppress the interactive prompt.
# At this point SSH is already in the allowlist so enabling cannot
# lock us out.
# =============================================================================
info "Step 9: Enabling UFW..."

if $DRY_RUN; then
    dryrun "ufw --force enable"
else
    ufw --force enable \
        && success "UFW enabled" \
        || { error "UFW failed to enable - check: ufw status verbose"; exit 1; }
fi

echo ""

# =============================================================================
# Step 10 - Verify ruleset
# =============================================================================
info "Step 10: Verifying active ruleset..."
echo ""

if $DRY_RUN; then
    dryrun "Would run: ufw status verbose"
else
    ufw status verbose
    echo ""
    success "Firewall is active - ruleset shown above"
fi

# =============================================================================
# Summary
# =============================================================================
echo ""
info "============================================================"
info "Firewall Hardening Summary"
info "============================================================"
if $DRY_RUN; then
    info "  Mode:             DRY-RUN (no changes made)"
fi
info "  Default inbound:  DENY"
info "  Default outbound: DENY"
info "  Grey team subnet: ${GREYTEAM_SUBNET} - FULLY ALLOWED"
info "  Inbound allowed:  ${ALL_INBOUND[*]}"
info "  Outbound allowed: ${OUTBOUND_RULES[*]}"
if [[ "${#EXTRA_INBOUND_PORTS[@]}" -eq 0 ]]; then
    warn "  Extra inbound:    NONE - verify grey team packet for additional ports"
else
    info "  Extra inbound:    ${EXTRA_INBOUND_PORTS[*]}"
fi
info "============================================================"
echo ""
warn "IMPORTANT: If scoring drops after running this script:"
warn "  1. Check what port the grey team checker is connecting on:"
warn "     journalctl -u ufw | tail -50"
warn "  2. Open the port immediately:"
warn "     ufw allow in proto tcp to any port <PORT>"
warn "  3. Or disable the firewall temporarily:"
warn "     ufw disable"
echo ""
warn "To remove all firewall rules and disable:"
warn "  ufw --force reset && ufw disable"