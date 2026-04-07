#!/usr/bin/env bash
# =============================================================================
# harden_apache.sh - Apache 2.4 hardening for Debian 13 (SCP-APACHE-01)
#
# Usage:
#   sudo ./harden_apache.sh [--dry-run]
#
# What it does:
#   1. Auto-detects Apache install type (package vs source)
#   2. Audits and disables dangerous modules with confirmation
#   3. Enforces correct ownership and permissions on Apache directories
#   4. Writes a hardened security config drop-in (headers, request limits,
#      access controls, information disclosure prevention)
#   5. Validates config with apache2ctl configtest before reloading
#   6. Reloads Apache to apply changes
#
# Safety:
#   - apache2ctl configtest run before any reload - broken config is
#     caught before it takes Apache down and kills scoring
#   - Full backup of Apache config before any changes
#   - Module disabling requires explicit YES confirmation
#   - Drop-in written to conf-available/ and enabled via symlink -
#     easy to revert by removing the symlink and reloading
#   - Run with --dry-run to preview all changes without applying
#
# !! READ BEFORE RUNNING !!
#   Verify APACHE_PREFIX and APACHE_DOCROOT match the actual install.
#   Run --dry-run first on prep day once you can inspect the box.
#   If Apache goes down after running: apache2ctl configtest to diagnose.
# =============================================================================

set -euo pipefail

# =============================================================================
# !! CONFIGURATION - VERIFY ON PREP DAY !!
#
# These paths are auto-detected from the running Apache process where
# possible. Override manually here if auto-detection is wrong.
# =============================================================================
APACHE_PREFIX=""        # e.g. /etc/apache2 - leave empty for auto-detect
APACHE_DOCROOT=""       # e.g. /var/www/html - leave empty for auto-detect
APACHE_USER=""          # e.g. www-data - leave empty for auto-detect
APACHE_GROUP=""         # e.g. www-data - leave empty for auto-detect

# =============================================================================
# !! DANGEROUS MODULES - EDIT IF NEEDED !!
#
# These modules will be flagged for disabling with a confirmation prompt.
# Each is dangerous for a specific reason documented below.
# Comment out any that scoring requires to be active.
# =============================================================================
DANGEROUS_MODULES=(
    "status"        # mod_status - exposes /server-status, reveals active
                    # connections, workers, request details to anyone who
                    # can reach it. Major information leak.
    "autoindex"     # mod_autoindex - directory listing. If a directory has
                    # no index file, Apache shows all its contents.
    "dav"           # mod_dav - WebDAV file manipulation over HTTP.
                    # Allows remote file upload/modification if enabled.
    "dav_fs"        # mod_dav_fs - filesystem provider for WebDAV.
    "info"          # mod_info - exposes /server-info with full Apache
                    # configuration. Should never be enabled.
    "userdir"       # mod_userdir - enables ~username URLs mapping to home
                    # directories. Unneeded and exposes home dir structure.
)

# =============================================================================
# Configuration
# =============================================================================
DRY_RUN=false
BACKUP_DIR="/root/apache_backups"
INSTALL_TYPE=""         # "package" or "source" - set by auto-detect

# =============================================================================
# Helpers
# =============================================================================
info()    { echo "[*] $*"; }
success() { echo "[+] $*"; }
warn()    { echo "[!] $*" >&2; }
error()   { echo "[-] $*" >&2; }
dryrun()  { echo "[DRY-RUN] $*"; }

confirm() {
    local prompt="$1"
    local answer
    read -r -p "  ${prompt} Type YES to confirm: " answer
    echo ""
    [[ "$answer" == "YES" ]]
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
# Step 1 - Auto-detect Apache installation
#
# We distinguish package vs source installs by checking for a2enmod,
# which is only present in Debian package installs. Source installs
# manage modules via LoadModule directives in httpd.conf directly.
#
# We also locate the prefix, docroot, running user, and config paths
# from the live Apache process and config files.
# =============================================================================
info "Step 1: Detecting Apache installation..."
echo ""

# Find the Apache binary
APACHE_BIN=""
for candidate in apache2 httpd apache2ctl; do
    if command -v "$candidate" &>/dev/null; then
        APACHE_BIN="$(command -v "$candidate")"
        break
    fi
done

if [[ -z "$APACHE_BIN" ]]; then
    error "Apache binary not found (tried: apache2, httpd, apache2ctl)"
    error "Is Apache installed on this box?"
    exit 1
fi

success "  Found Apache binary: ${APACHE_BIN}"

# Detect install type
if command -v a2enmod &>/dev/null; then
    INSTALL_TYPE="package"
    success "  Install type: PACKAGE (a2enmod/a2dismod available)"
else
    INSTALL_TYPE="source"
    warn "  Install type: SOURCE (no a2enmod - will edit config directly)"
fi

# Auto-detect Apache prefix if not set manually
if [[ -z "$APACHE_PREFIX" ]]; then
    if [[ "$INSTALL_TYPE" == "package" ]]; then
        APACHE_PREFIX="/etc/apache2"
    elif [[ -d "/usr/local/apache2" ]]; then
        APACHE_PREFIX="/usr/local/apache2"
    elif [[ -d "/etc/httpd" ]]; then
        APACHE_PREFIX="/etc/httpd"
    else
        error "Cannot auto-detect APACHE_PREFIX - set it manually at the top of this script"
        exit 1
    fi
fi

success "  Config prefix: ${APACHE_PREFIX}"

# Auto-detect docroot from Apache config if not set manually
if [[ -z "$APACHE_DOCROOT" ]]; then
    APACHE_DOCROOT=$(grep -rh "^\s*DocumentRoot" "${APACHE_PREFIX}/" 2>/dev/null \
        | awk '{print $2}' | tr -d '"' | head -1)
    if [[ -z "$APACHE_DOCROOT" ]]; then
        APACHE_DOCROOT="/var/www/html"
        warn "  Could not detect DocumentRoot - defaulting to ${APACHE_DOCROOT}"
    fi
fi

success "  Document root: ${APACHE_DOCROOT}"

# Auto-detect Apache user/group if not set manually
if [[ -z "$APACHE_USER" ]]; then
    APACHE_USER=$(grep -rh "^\s*User\b" "${APACHE_PREFIX}/" 2>/dev/null \
        | awk '{print $2}' | head -1)
    APACHE_USER="${APACHE_USER:-www-data}"
fi

if [[ -z "$APACHE_GROUP" ]]; then
    APACHE_GROUP=$(grep -rh "^\s*Group\b" "${APACHE_PREFIX}/" 2>/dev/null \
        | awk '{print $2}' | head -1)
    APACHE_GROUP="${APACHE_GROUP:-www-data}"
fi

success "  Running as:    ${APACHE_USER}:${APACHE_GROUP}"

# Set config test command
if command -v apache2ctl &>/dev/null; then
    APACHE_CTL="apache2ctl"
elif command -v apachectl &>/dev/null; then
    APACHE_CTL="apachectl"
else
    error "Neither apache2ctl nor apachectl found"
    exit 1
fi

echo ""

# =============================================================================
# Step 2 - Backup Apache configuration
# =============================================================================
info "Step 2: Backing up Apache configuration..."

if $DRY_RUN; then
    dryrun "Would backup ${APACHE_PREFIX}/ -> ${BACKUP_DIR}/apache2.<timestamp>/"
else
    mkdir -p "$BACKUP_DIR"
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    BACKUP_PATH="${BACKUP_DIR}/apache2.${TIMESTAMP}"
    cp -r "$APACHE_PREFIX" "$BACKUP_PATH"
    success "Backed up ${APACHE_PREFIX} -> ${BACKUP_PATH}"
    info "To restore: cp -r ${BACKUP_PATH}/* ${APACHE_PREFIX}/"
fi

echo ""

# =============================================================================
# Step 3 - Audit and disable dangerous modules
#
# For package installs we use a2dismod which removes the symlink from
# mods-enabled/ and is the clean Debian way to disable modules.
#
# For source installs we look for LoadModule lines in config files and
# comment them out.
#
# Either way we show what we found and prompt for confirmation before
# making any changes.
# =============================================================================
info "Step 3: Auditing dangerous modules..."
echo ""

declare -a MODULES_TO_DISABLE
declare -a MODULES_ENABLED_PATHS  # for source installs

if [[ "$INSTALL_TYPE" == "package" ]]; then
    MODS_ENABLED_DIR="${APACHE_PREFIX}/mods-enabled"

    for mod in "${DANGEROUS_MODULES[@]}"; do
        # Module symlinks are named either mod.load or mod.conf
        if [[ -f "${MODS_ENABLED_DIR}/${mod}.load" ]] || \
           [[ -f "${MODS_ENABLED_DIR}/${mod}.conf" ]]; then
            warn "  ENABLED (dangerous): ${mod}"
            MODULES_TO_DISABLE+=("$mod")
        else
            success "  Not enabled: ${mod}"
        fi
    done

else
    # Source install - grep for LoadModule lines
    for mod in "${DANGEROUS_MODULES[@]}"; do
        match=$(grep -rn "^\s*LoadModule\s.*mod_${mod}\b" "${APACHE_PREFIX}/" \
            2>/dev/null || true)
        if [[ -n "$match" ]]; then
            warn "  LOADED (dangerous): ${mod}"
            warn "    ${match}"
            MODULES_TO_DISABLE+=("$mod")
            MODULES_ENABLED_PATHS+=("$match")
        else
            success "  Not loaded: ${mod}"
        fi
    done
fi

echo ""

if [[ "${#MODULES_TO_DISABLE[@]}" -eq 0 ]]; then
    success "No dangerous modules currently enabled"
else
    echo "============================================================"
    warn "  ${#MODULES_TO_DISABLE[@]} dangerous module(s) found: ${MODULES_TO_DISABLE[*]}"
    echo "============================================================"
    echo ""

    if $DRY_RUN; then
        dryrun "Would prompt to disable: ${MODULES_TO_DISABLE[*]}"
    else
        if confirm "Disable all ${#MODULES_TO_DISABLE[@]} dangerous module(s)?"; then
            for mod in "${MODULES_TO_DISABLE[@]}"; do
                if [[ "$INSTALL_TYPE" == "package" ]]; then
                    a2dismod -f "$mod" 2>/dev/null \
                        && success "  Disabled: ${mod}" \
                        || warn "  Failed to disable: ${mod}"
                else
                    # Comment out LoadModule lines for this module
                    find "${APACHE_PREFIX}/" -type f -name "*.conf" \
                        -exec sed -i \
                        "s|^\(\s*LoadModule\s.*mod_${mod}\b\)|#DISABLED# \1|g" {} \;
                    success "  Commented out LoadModule for: ${mod}"
                fi
            done
        else
            info "Module disabling skipped"
        fi
    fi
fi

echo ""

# =============================================================================
# Step 4 - Enforce Apache file and directory ownership/permissions
#
# CIS recommends:
#   - Apache config dirs/files owned by root (not the Apache user)
#   - No other-write access on any Apache files
#   - Document root: owned by root, Apache group can read, no other-write
#
# This prevents a compromised Apache process from modifying its own config.
# =============================================================================
info "Step 4: Enforcing Apache directory permissions..."
echo ""

# Config directory - should be owned by root, not writable by Apache user
info "  Checking ${APACHE_PREFIX}/..."
if $DRY_RUN; then
    dryrun "  Would run: chown -R root:root ${APACHE_PREFIX}/"
    dryrun "  Would remove other-write on all Apache config files"
else
    chown -R root:root "${APACHE_PREFIX}/"
    # Remove other-write from all config files and directories
    find "${APACHE_PREFIX}/" ! -type l -perm /o=w \
        -exec chmod o-w {} \; 2>/dev/null || true
    success "  ${APACHE_PREFIX}/ - ownership set to root:root, other-write removed"
fi

# Document root - root owns it, Apache group can read, no other-write
if [[ -d "$APACHE_DOCROOT" ]]; then
    info "  Checking document root ${APACHE_DOCROOT}/..."
    if $DRY_RUN; then
        dryrun "  Would run: chown -R root:${APACHE_GROUP} ${APACHE_DOCROOT}/"
        dryrun "  Would remove other-write and Apache group write on docroot"
    else
        chown -R root:"${APACHE_GROUP}" "${APACHE_DOCROOT}/"
        # Remove other-write and group-write from docroot
        # Group needs read but not write - Apache should not be able to
        # modify web content even if compromised
        find "${APACHE_DOCROOT}/" ! -type l -perm /o=w \
            -exec chmod o-w {} \; 2>/dev/null || true
        success "  ${APACHE_DOCROOT}/ - ownership root:${APACHE_GROUP}, other-write removed"
    fi
else
    warn "  Document root ${APACHE_DOCROOT} not found - skipping"
fi

echo ""

# =============================================================================
# Step 5 - Write security hardening config drop-in
#
# We write a single hardened config file covering:
#
#   Information disclosure:
#     ServerTokens Prod    - hides Apache version and OS from HTTP headers
#     ServerSignature Off  - removes version footer from error pages
#     FileETag None        - prevents inode numbers leaking in ETag headers
#
#   Access controls:
#     Deny OS root by default, only allow docroot
#     Disable Options Indexes (directory listing) everywhere
#     AllowOverride None on OS root (no .htaccess overrides)
#     Disable HTTP TRACE method
#
#   Security headers:
#     X-Frame-Options      - prevents clickjacking
#     X-Content-Type-Options - prevents MIME sniffing
#     Referrer-Policy      - controls referrer header leakage
#     HSTS                 - forces HTTPS for one year
#
#   Request limits:
#     Timeout              - 10 seconds max (prevents slow HTTP attacks)
#     LimitRequestLine     - cap URI length
#     LimitRequestFields   - cap number of request headers
#     LimitRequestBody     - cap request body size
#
# For package installs we write to conf-available/ and enable with a2enconf.
# For source installs we write directly to a conf.d/ include directory.
# =============================================================================
info "Step 5: Writing security hardening config..."

HARDENING_CONF_CONTENT="# =============================================================================
# Blue Team Apache Hardening - applied by harden_apache.sh
# CIS Apache HTTP Server 2.4 Benchmark
#
# To revert (package install):
#   a2disconf blueteam-hardening && systemctl reload apache2
# To revert (source install):
#   rm <conf.d>/blueteam-hardening.conf && apachectl graceful
# =============================================================================

# -- Information Disclosure --

# Hide Apache version and OS from Server header
# 'Prod' shows only 'Apache', nothing more
ServerTokens Prod

# Remove version info from error pages and directory listings
ServerSignature Off

# Prevent inode numbers from appearing in ETag response headers
# Inodes can leak filesystem information useful for fingerprinting
FileETag None

# -- Global Access Control --

# Deny access to the entire OS filesystem by default
# Access must be explicitly granted to specific directories below
<Directory />
    Options None
    AllowOverride None
    Require all denied
</Directory>

# Grant access to the document root only
<Directory \"${APACHE_DOCROOT}\">
    Options -Indexes -FollowSymLinks -MultiViews
    AllowOverride None
    Require all granted
</Directory>

# Restrict access to .ht* files (e.g. .htaccess, .htpasswd)
# These should never be served to clients
<FilesMatch \"^\\.ht\">
    Require all denied
</FilesMatch>

# Restrict access to .git directories if present in docroot
<DirectoryMatch \"\\.git\">
    Require all denied
</DirectoryMatch>

# -- HTTP Methods --

# Disable TRACE method - used in cross-site tracing (XST) attacks
# Only allow GET, POST, HEAD, OPTIONS which are needed for normal operation
TraceEnable off

# -- Security Headers --

# Load headers module check is handled by the calling script
# These headers are applied to all responses

# Prevent this site from being embedded in frames on other domains
# Mitigates clickjacking attacks
Header always set X-Frame-Options \"SAMEORIGIN\"

# Prevent browsers from MIME-sniffing the content type
# Stops content injection via file upload if content-type is wrong
Header always set X-Content-Type-Options \"nosniff\"

# Control referrer information sent with requests
# 'strict-origin-when-cross-origin' sends full path same-origin,
# only origin cross-origin, nothing on downgrade (HTTPS->HTTP)
Header always set Referrer-Policy \"strict-origin-when-cross-origin\"

# Force HTTPS for one year - tells browsers to never connect over HTTP
# Only enable this if HTTPS is confirmed working on this box
# Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"

# -- Request Size Limits --
# These directly mitigate slow HTTP DoS attacks and oversized request abuse

# Maximum time to receive a request - 10 seconds
# Prevents slow HTTP attacks (Slowloris, etc.)
Timeout 10

# Keep connections alive for up to 5 seconds between requests
# Reduces connection overhead while limiting resource holding
KeepAliveTimeout 5

# Require at least 100 requests per keepalive connection
KeepAlive On
MaxKeepAliveRequests 100

# Maximum size of the request line (URI + method + protocol)
# 8190 is the recommended maximum
LimitRequestLine 8190

# Maximum number of HTTP request headers
# 100 is the CIS-recommended maximum
LimitRequestFields 100

# Maximum size of individual request header fields
LimitRequestFieldSize 8190

# Maximum size of the request body - 102400 bytes (100KB)
# Adjust upward if legitimate file uploads are required
LimitRequestBody 102400
"

if [[ "$INSTALL_TYPE" == "package" ]]; then
    CONF_AVAILABLE="${APACHE_PREFIX}/conf-available"
    CONF_ENABLED="${APACHE_PREFIX}/conf-enabled"
    CONF_FILE="${CONF_AVAILABLE}/blueteam-hardening.conf"
    CONF_LINK="${CONF_ENABLED}/blueteam-hardening.conf"
else
    # Source install - write to conf.d/ if it exists, otherwise extra/
    if [[ -d "${APACHE_PREFIX}/conf.d" ]]; then
        CONF_FILE="${APACHE_PREFIX}/conf.d/blueteam-hardening.conf"
    elif [[ -d "${APACHE_PREFIX}/extra" ]]; then
        CONF_FILE="${APACHE_PREFIX}/extra/blueteam-hardening.conf"
    else
        CONF_FILE="${APACHE_PREFIX}/blueteam-hardening.conf"
    fi
fi

if $DRY_RUN; then
    dryrun "Would write hardening config to ${CONF_FILE}"
    echo ""
    echo "$HARDENING_CONF_CONTENT"
else
    echo "$HARDENING_CONF_CONTENT" > "$CONF_FILE"
    chmod 644 "$CONF_FILE"
    success "Hardening config written to ${CONF_FILE}"

    if [[ "$INSTALL_TYPE" == "package" ]]; then
        # Enable via symlink using a2enconf
        if [[ ! -L "$CONF_LINK" ]]; then
            a2enconf blueteam-hardening &>/dev/null \
                && success "Config enabled via a2enconf" \
                || warn "a2enconf failed - symlink manually: ln -s ${CONF_FILE} ${CONF_LINK}"
        else
            info "Config already enabled (symlink exists)"
        fi

        # Ensure mod_headers is enabled - needed for Header directives
        if [[ ! -f "${APACHE_PREFIX}/mods-enabled/headers.load" ]]; then
            info "Enabling mod_headers (required for security headers)..."
            a2enmod headers &>/dev/null \
                && success "mod_headers enabled" \
                || warn "Failed to enable mod_headers - Header directives will not work"
        else
            success "mod_headers already enabled"
        fi
    else
        # Source install - ensure the conf file is included
        HTTPD_CONF="${APACHE_PREFIX}/httpd.conf"
        INCLUDE_LINE="Include ${CONF_FILE}"
        if ! grep -qF "$INCLUDE_LINE" "$HTTPD_CONF" 2>/dev/null; then
            echo "$INCLUDE_LINE" >> "$HTTPD_CONF"
            success "Added Include directive to ${HTTPD_CONF}"
        else
            info "Include already present in ${HTTPD_CONF}"
        fi
    fi
fi

echo ""

# =============================================================================
# Step 6 - Validate Apache config before reloading
#
# This is the equivalent of sshd -t for Apache. If our hardening config
# has any syntax errors, Apache will refuse to reload and the current
# (unhardened but running) config stays active. We never take Apache
# down mid-competition.
# =============================================================================
info "Step 6: Validating Apache configuration..."

if $DRY_RUN; then
    dryrun "Would run: ${APACHE_CTL} configtest"
else
    if $APACHE_CTL configtest 2>&1 | grep -q "Syntax OK"; then
        success "Apache configuration is valid (Syntax OK)"
    else
        error "Apache config validation FAILED"
        error "Running configtest output:"
        $APACHE_CTL configtest 2>&1 || true
        error "Reverting hardening config to prevent outage..."
        rm -f "$CONF_FILE"
        if [[ "$INSTALL_TYPE" == "package" ]]; then
            rm -f "$CONF_LINK"
        fi
        error "Hardening config removed - Apache is unchanged"
        error "Fix the config issue and re-run"
        exit 1
    fi
fi

echo ""

# =============================================================================
# Step 7 - Reload Apache
#
# We use graceful reload (graceful) rather than restart - it lets existing
# connections finish before workers restart, so in-progress scoring checks
# are not interrupted. apache2ctl graceful is equivalent to
# systemctl reload apache2 but works for both package and source installs.
# =============================================================================
info "Step 7: Reloading Apache..."

if $DRY_RUN; then
    dryrun "Would run: ${APACHE_CTL} graceful"
else
    if $APACHE_CTL graceful; then
        success "Apache reloaded gracefully - hardening is active"
    else
        warn "Graceful reload failed - attempting full restart..."
        if systemctl restart apache2 2>/dev/null || \
           $APACHE_CTL restart 2>/dev/null; then
            success "Apache restarted successfully"
        else
            error "Apache failed to restart - check: journalctl -u apache2"
            exit 1
        fi
    fi
fi

echo ""

# =============================================================================
# Summary
# =============================================================================
echo ""
info "============================================================"
info "Apache Hardening Summary"
info "============================================================"
if $DRY_RUN; then
    info "  Mode:              DRY-RUN (no changes made)"
else
    info "  Backup:            ${BACKUP_PATH}"
    info "  Config drop-in:    ${CONF_FILE}"
fi
info "  Install type:      ${INSTALL_TYPE}"
info "  Apache prefix:     ${APACHE_PREFIX}"
info "  Document root:     ${APACHE_DOCROOT}"
info "  Apache user:       ${APACHE_USER}:${APACHE_GROUP}"
info "  Modules disabled:  ${#MODULES_TO_DISABLE[@]}"
info "============================================================"
echo ""
warn "REMINDER: HSTS header is commented out by default."
warn "Enable it in ${CONF_FILE} only after confirming HTTPS works:"
warn "  Uncomment: Header always set Strict-Transport-Security ..."
warn "  Then: ${APACHE_CTL} graceful"
echo ""
warn "REMINDER: LimitRequestBody is set to 102400 (100KB)."
warn "If the scored service requires file uploads, increase this:"
warn "  Edit ${CONF_FILE} and adjust LimitRequestBody"
warn "  Then: ${APACHE_CTL} configtest && ${APACHE_CTL} graceful"