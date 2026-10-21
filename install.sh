#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# PingWAF Installation Script
# ─────────────────────────────────────────────────────────────────────────────
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/shuaiZend/PingWAF/main/install.sh | bash
#   ./install.sh [--version X.Y.Z] [--mode all-in-one|server|agent]
#
# Options:
#   --version     Install a specific version (default: latest)
#   --mode        Operating mode: all-in-one, server, agent (default: all-in-one)
#   --server-url  Control plane gRPC URL (agent mode)
#   --api-key     Agent enrollment token (agent mode)
#   --no-systemd  Skip systemd service creation
#   --help        Show this help message
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ─── Colors & Helpers ─────────────────────────────────────────────────────────
BOLD="$(tput bold 2>/dev/null || printf '')"
RED="$(tput setaf 1 2>/dev/null || printf '')"
GREEN="$(tput setaf 2 2>/dev/null || printf '')"
YELLOW="$(tput setaf 3 2>/dev/null || printf '')"
BLUE="$(tput setaf 4 2>/dev/null || printf '')"
NO_COLOR="$(tput sgr0 2>/dev/null || printf '')"

info()    { printf '%s\n' "${BLUE}>${NO_COLOR} $*"; }
success() { printf '%s\n' "${GREEN}✓${NO_COLOR} $*"; }
warn()    { printf '%s\n' "${YELLOW}! $*${NO_COLOR}"; }
error()   { printf '%s\n' "${RED}✗ $*${NO_COLOR}" >&2; }
fatal()   { error "$@"; exit 1; }

has() { command -v "$1" >/dev/null 2>&1; }

# ─── Constants ────────────────────────────────────────────────────────────────
REPO="shuaiZend/PingWAF"
BINARY_NAME="pingwaf"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/pingwaf"
DATA_DIR="/var/lib/pingwaf"
SERVICE_NAME="pingwaf"
SUPPORTED_PLATFORMS="linux/amd64 linux/arm64"

# ─── Default Configuration ────────────────────────────────────────────────────
VERSION=""
MODE="all-in-one"
SKIP_SYSTEMD=false
DB_URL="postgres://pingwaf:pingwaf@localhost:5432/pingwaf"
SERVER_URL=""
API_KEY=""

# ─── Argument Parsing ─────────────────────────────────────────────────────────
show_help() {
    cat <<EOF
PingWAF Installation Script

Usage: $(basename "$0") [OPTIONS]

Options:
  --version VERSION     Install a specific version (default: latest release)
  --mode MODE           Operating mode: all-in-one, server, agent
  --server-url URL      Control plane gRPC URL (agent mode)
  --api-key KEY         Agent enrollment token (agent mode)
  --no-systemd          Skip systemd service file creation
  --db-url URL          PostgreSQL connection string
  --help                Show this help message

Environment Variables:
  PINGWAF_VERSION       Same as --version
  PINGWAF_MODE          Same as --mode
  PINGWAF_SERVER_URL    Same as --server-url
  PINGWAF_API_KEY       Same as --api-key
  PINGWAF_DB_URL        Same as --db-url

Examples:
  # Install latest, all-in-one mode
  curl -fsSL https://raw.githubusercontent.com/shuaiZend/PingWAF/main/install.sh | bash

  # Install a node as an agent, pointing at the control plane
  # (the control plane serves gRPC over TLS by default — use https:// and
  # download its CA from Settings -> Control plane HTTPS, then set it in
  # /etc/pingwaf/pingwaf.toml as agent.server_ca_cert)
  ./install.sh --mode agent --server-url https://10.0.0.1:9090 --api-key pwk_xxx

  # Install specific version as agent only
  ./install.sh --version 0.25.0 --mode agent

  # Custom database URL
  ./install.sh --db-url "postgres://user:pass@db-host:5432/pingwaf"

After installation:
  Config: /etc/pingwaf/pingwaf.toml   (edit it, then: systemctl restart pingwaf)
  Data:   /var/lib/pingwaf
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)    VERSION="$2"; shift 2 ;;
        --mode)       MODE="$2"; shift 2 ;;
        --db-url)     DB_URL="$2"; shift 2 ;;
        --server-url) SERVER_URL="$2"; shift 2 ;;
        --api-key)    API_KEY="$2"; shift 2 ;;
        --no-systemd) SKIP_SYSTEMD=true; shift ;;
        --help|-h)    show_help; exit 0 ;;
        *)            fatal "Unknown option: $1 (use --help for usage)" ;;
    esac
done

# Environment variable fallbacks
VERSION="${VERSION:-${PINGWAF_VERSION:-}}"
MODE="${MODE:-${PINGWAF_MODE:-all-in-one}}"
DB_URL="${DB_URL:-${PINGWAF_DB_URL:-$DB_URL}}"
# Agent mode reads its settings from the command line or the environment, so
# these are what the systemd unit is built from.
SERVER_URL="${SERVER_URL:-${PINGWAF_SERVER_URL:-}}"
API_KEY="${API_KEY:-${PINGWAF_API_KEY:-}}"

# Validate mode
case "$MODE" in
    all-in-one|server|agent) ;;
    *) fatal "Invalid mode: $MODE (must be: all-in-one, server, agent)" ;;
esac

# Agents talk to the control plane, never to PostgreSQL.
if [[ "$MODE" == "agent" ]]; then
    SERVER_URL="${SERVER_URL:-http://127.0.0.1:9090}"
    if [[ -z "$API_KEY" ]]; then
        warn "No --api-key given: start the agent with PINGWAF_API_KEY set, or it cannot register."
    fi
    if [[ "$SERVER_URL" == http:* ]]; then
        warn "The control plane serves gRPC over TLS by default; a plain http:// server-url only works when the control plane sets grpc_tls_mode = \"off\". For TLS use https:// and configure agent.server_ca_cert with the control plane's certificate."
    fi
fi

# ─── Platform Detection ───────────────────────────────────────────────────────
detect_os() {
    local os
    os="$(uname -s)"
    case "$os" in
        Linux*)  echo "linux" ;;
        Darwin*) echo "darwin" ;;
        *)       fatal "Unsupported operating system: $os" ;;
    esac
}

detect_arch() {
    local arch
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64)  echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        *)             fatal "Unsupported architecture: $arch" ;;
    esac
}

OS="$(detect_os)"
ARCH="$(detect_arch)"
PLATFORM="${OS}/${ARCH}"

info "Detected platform: ${PLATFORM}"

if [[ "$OS" == "darwin" ]]; then
    fatal "Prebuilt binaries are published for Linux only. On macOS, build from source (see README.md)."
fi

if ! echo "$SUPPORTED_PLATFORMS" | grep -q "$PLATFORM"; then
    fatal "Platform $PLATFORM is not supported. Supported: $SUPPORTED_PLATFORMS"
fi

# ─── Version Resolution ───────────────────────────────────────────────────────
get_latest_version() {
    local url="https://api.github.com/repos/${REPO}/releases/latest"
    if has curl; then
        curl -fsSL "$url" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/'
    elif has wget; then
        wget -qO- "$url" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/'
    else
        fatal "Neither curl nor wget found. Please install one of them."
    fi
}

if [[ -z "$VERSION" ]]; then
    info "Fetching latest release version..."
    VERSION="$(get_latest_version)"
    if [[ -z "$VERSION" ]]; then
        fatal "Failed to determine latest version. Use --version to specify manually."
    fi
fi

# Strip leading 'v' if present
VERSION="${VERSION#v}"
info "Installing PingWAF v${VERSION}"

# ─── Download ─────────────────────────────────────────────────────────────────
# Releases ship both .tar.xz (primary, smaller) and .tar.gz (compatibility
# fallback). Prefer xz; skip straight to .tar.gz when xz(1) is not installed,
# and fall back on a failed download (e.g. releases that predate .tar.xz).
fetch_asset() {
    local ext url
    for ext in tar.xz tar.gz; do
        if [[ "$ext" == "tar.xz" ]] && ! has xz; then
            info "xz(1) not found — falling back to the .tar.gz asset."
            continue
        fi
        ASSET_NAME="pingwaf-${OS}-${ARCH}.${ext}"
        url="https://github.com/${REPO}/releases/download/v${VERSION}/${ASSET_NAME}"
        info "Downloading ${ASSET_NAME}..."
        info "URL: ${url}"
        if has curl; then
            if curl -fsSL "$url" -o "${TMPDIR}/${ASSET_NAME}"; then
                return 0
            fi
        elif has wget; then
            if wget -q "$url" -O "${TMPDIR}/${ASSET_NAME}"; then
                return 0
            fi
        else
            fatal "Neither curl nor wget found. Please install one of them."
        fi
        warn "Download failed for ${ASSET_NAME} — trying the next format."
    done
    fatal "Download failed. Check that version v${VERSION} exists and has a pingwaf-${OS}-${ARCH} asset."
}

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

ASSET_NAME=""
fetch_asset

# ─── Extract & Install Binary ─────────────────────────────────────────────────
info "Extracting..."
case "$ASSET_NAME" in
    *.tar.xz) tar -xJf "${TMPDIR}/${ASSET_NAME}" -C "$TMPDIR" ;;
    *.tar.gz) tar -xzf "${TMPDIR}/${ASSET_NAME}" -C "$TMPDIR" ;;
    *)        fatal "Unexpected asset name: ${ASSET_NAME}" ;;
esac

# Find the binary
BINARY_PATH="$(find "$TMPDIR" -name "$BINARY_NAME" -type f | head -n1)"
if [[ -z "$BINARY_PATH" ]]; then
    # Fallback: first executable file
    BINARY_PATH="$(find "$TMPDIR" -type f -perm +111 | head -n1)"
fi
if [[ -z "$BINARY_PATH" ]]; then
    fatal "Binary not found in archive."
fi

chmod +x "$BINARY_PATH"

# The release binaries are linked against the glibc of the runner that built
# them (Ubuntu 24.04 today), so an older distro gets as far as systemd before
# failing with a versioned-symbol error. Catch that here instead, while the
# message can still name the cause.
if ! "$BINARY_PATH" --version >/dev/null 2>&1; then
    smoke_error="$("$BINARY_PATH" --version 2>&1 | head -n1 || true)"
    fatal "The downloaded binary cannot run on this system: ${smoke_error}
       Release assets are built on Ubuntu 24.04 and need glibc 2.39 or newer.
       On older distributions (CentOS/RHEL, Debian 11, Ubuntu 20.04, Alpine,
       ...) build from source instead: https://github.com/${REPO}/blob/main/docs/quick-start.md#path-2-build-from-source"
fi

info "Installing binary to ${INSTALL_DIR}/${BINARY_NAME}..."
if [[ -w "$INSTALL_DIR" ]]; then
    mv "$BINARY_PATH" "${INSTALL_DIR}/${BINARY_NAME}"
elif has sudo; then
    sudo mv "$BINARY_PATH" "${INSTALL_DIR}/${BINARY_NAME}"
else
    fatal "No write permission to ${INSTALL_DIR} and sudo not available."
fi

success "Binary installed: ${INSTALL_DIR}/${BINARY_NAME}"

# ─── Create Directories ───────────────────────────────────────────────────────
create_dirs() {
    local cmd=""
    if [[ -w "/" ]]; then
        cmd=""
    elif has sudo; then
        cmd="sudo"
    else
        warn "Cannot create system directories without sudo."
        return
    fi

    $cmd mkdir -p "$CONFIG_DIR" "$DATA_DIR" "${DATA_DIR}/cache" "${DATA_DIR}/certs"

    # Create pingwaf user if on Linux
    if [[ "$OS" == "linux" ]]; then
        if ! id -u pingwaf >/dev/null 2>&1; then
            $cmd useradd -r -m -d "$DATA_DIR" -s /usr/sbin/nologin pingwaf 2>/dev/null || \
            $cmd adduser -r -d "$DATA_DIR" -s /sbin/nologin pingwaf 2>/dev/null || true
        fi
        $cmd chown -R pingwaf:pingwaf "$CONFIG_DIR" "$DATA_DIR" 2>/dev/null || true
    fi
}

if [[ "$OS" == "linux" ]]; then
    info "Creating directories..."
    create_dirs
    success "Created ${CONFIG_DIR} and ${DATA_DIR}"
fi

# ─── Write Default Configuration ─────────────────────────────────────────────
write_config() {
    local config_file="${CONFIG_DIR}/pingwaf.toml"
    if [[ -f "$config_file" ]]; then
        warn "Config file already exists at ${config_file}, skipping."
        return
    fi

    local cmd=""
    [[ -w "$CONFIG_DIR" ]] || cmd="sudo"

    # Keys are the command-line flags with dashes replaced by underscores, and
    # the file only fills in what the environment and the command line leave
    # alone (see docs/deployment.md). Settings without a flag — registration,
    # CORS, Elasticsearch, passkeys — stay in the environment.
    local agent_server_url="# agent mode only; all-in-one talks to its own loopback gRPC"
    if [[ "$MODE" == "agent" ]]; then
        agent_server_url="server_url = \"${SERVER_URL}\""
    fi
    $cmd tee "$config_file" >/dev/null <<EOF
# PingWAF Configuration
# Generated by install.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Mode: ${MODE}
#
# This file is read when PINGWAF_CONFIG points at it (the systemd unit sets
# that). Precedence: this file, then PINGWAF_* environment variables, then
# command-line flags. Unknown keys are reported at startup and ignored.

[server]
db_url = "${DB_URL}"
admin_addr = "0.0.0.0:9080"
grpc_addr = "0.0.0.0:9090"
# gRPC control plane TLS: "tls" (default) serves agents over TLS, reusing the
# dashboard certificate — self-signed on first boot unless grpc_tls_cert/key
# are configured. "off" serves plaintext and is logged as degraded.
# grpc_tls_mode = "tls"
# Dashboard + REST API over HTTPS (passkeys require a secure origin).
# A self-signed certificate is generated on first boot; upload a real one in
# Settings -> Control plane HTTPS. Add the hostname you use to reach the
# dashboard so the generated certificate covers it:
# tls_sans = ["waf.example.com"]
tls_enabled = true
jwt_secret = "$(head -c 32 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 32)"
admin_email = "admin@pingwaf.local"
admin_password = "pingwaf123"
serve_frontend = true

# Used by the all-in-one mode and by agents; a server ignores this section.
[agent]
${agent_server_url}
cache_dir = "${DATA_DIR}/cache"
heartbeat_interval_secs = 30
log_batch_size = 100
log_flush_interval_secs = 5
max_body_log_size = 8192
fail_open = true
metrics_ship_interval_secs = 30

# Everything else comes from the environment, e.g.
#   PINGWAF_ALLOW_REGISTRATION=false     PINGWAF_CORS_ORIGINS=https://ui.example.com
#   PINGWAF_JWT_EXPIRATION_HOURS=12      PINGWAF_DB_MAX_CONNECTIONS=20
#   PINGWAF_METRIC_RETENTION_DAYS=30     PINGWAF_WEBHOOK_URL=https://hooks.example.com
#   PINGWAF_PASSKEY_ENABLED=true         PINGWAF_ES_ENABLED=true
EOF

    if [[ -n "$cmd" ]]; then
        $cmd chown pingwaf:pingwaf "$config_file" 2>/dev/null || true
        $cmd chmod 640 "$config_file"
    fi

    success "Configuration written to ${config_file}"
}

if [[ "$OS" == "linux" ]]; then
    write_config
fi

# ─── Systemd Service ──────────────────────────────────────────────────────────
install_systemd() {
    if [[ "$SKIP_SYSTEMD" == "true" ]]; then
        info "Skipping systemd service installation (--no-systemd)."
        return
    fi

    if [[ "$OS" != "linux" ]]; then
        info "macOS detected — skipping systemd. Use launchd or run directly."
        return
    fi

    if ! has systemctl; then
        warn "systemctl not found — skipping service installation."
        return
    fi

    local service_file="/etc/systemd/system/${SERVICE_NAME}.service"
    local exec_start="${INSTALL_DIR}/${BINARY_NAME} ${MODE}"

    # Settings come from the generated file first, then these environment
    # variables, then the unit's command line. There is no SIGHUP reload: a
    # changed unit or config file takes effect with `systemctl restart`.
    local unit_after="After=network.target postgresql.service"
    local unit_wants="Wants=postgresql.service"
    local agent_env="Environment=PINGWAF_CONFIG=${CONFIG_DIR}/pingwaf.toml"
    if [[ "$MODE" == "agent" ]]; then
        unit_after="After=network-online.target"
        unit_wants="Wants=network-online.target"
        agent_env="Environment=PINGWAF_CONFIG=${CONFIG_DIR}/pingwaf.toml
Environment=PINGWAF_SERVER_URL=${SERVER_URL}
Environment=PINGWAF_API_KEY=${API_KEY}
Environment=PINGWAF_CACHE_DIR=${DATA_DIR}/cache"
    else
        # The dashboard is served over HTTPS with a self-signed certificate
        # until a real one is uploaded. Add the hostname it is reached under so
        # the generated certificate covers it:
        # Environment=PINGWAF_TLS_SANS=waf.example.com
        agent_env="Environment=PINGWAF_CONFIG=${CONFIG_DIR}/pingwaf.toml
Environment=PINGWAF_TLS_ENABLED=true"
    fi

    info "Creating systemd service..."

    local cmd=""
    [[ -w "/etc/systemd/system" ]] || cmd="sudo"

    $cmd tee "$service_file" >/dev/null <<EOF
[Unit]
Description=PingWAF - High Performance Web Application Firewall
Documentation=https://github.com/${REPO}
${unit_after}
${unit_wants}

[Service]
Type=simple
User=pingwaf
Group=pingwaf
ExecStart=${exec_start}
Restart=always
RestartSec=5
LimitNOFILE=65536
${agent_env}
# Log level; the default keeps sqlx's per-statement log out of the way:
Environment=RUST_LOG=info,sqlx=warn

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${DATA_DIR} ${CONFIG_DIR}
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

    $cmd systemctl daemon-reload
    success "Systemd service installed: ${SERVICE_NAME}.service"

    # An agent only contributes once it is running, so start it here — this is
    # what makes the dashboard's one-line enrolment command enough on its own.
    # Server modes stay manual: they need PostgreSQL ready and an attended
    # first boot.
    if [[ "$MODE" == "agent" ]]; then
        info "Starting the agent service..."
        if $cmd systemctl enable --now "$SERVICE_NAME"; then
            success "Service enabled and started: ${SERVICE_NAME}"
        else
            warn "The service did not start — inspect: journalctl -u ${SERVICE_NAME} -e"
            warn "After fixing, start it with: sudo systemctl enable --now ${SERVICE_NAME}"
        fi
        return
    fi

    info "To start PingWAF:"
    echo "  sudo systemctl enable --now ${SERVICE_NAME}"
    echo "  sudo systemctl status ${SERVICE_NAME}"
}

install_systemd

# ─── PostgreSQL Check ─────────────────────────────────────────────────────────
check_postgres() {
    info "Checking PostgreSQL availability..."

    if has psql; then
        if psql "$DB_URL" -c "SELECT 1" >/dev/null 2>&1; then
            success "PostgreSQL connection successful."
        else
            warn "psql found but cannot connect to: ${DB_URL}"
            echo ""
            echo "  To set up PostgreSQL:"
            echo "    1. Install: sudo apt install postgresql-16"
            echo "    2. Create user & database:"
            echo "       sudo -u postgres createuser pingwaf"
            echo "       sudo -u postgres createdb -O pingwaf pingwaf"
            echo "       sudo -u postgres psql -c \"ALTER USER pingwaf PASSWORD 'pingwaf';\""
            echo ""
        fi
    else
        warn "PostgreSQL client (psql) not found."
        echo ""
        echo "  PingWAF requires PostgreSQL 14+. Install it with:"
        echo ""
        if [[ "$OS" == "linux" ]]; then
            if has apt-get; then
                echo "    sudo apt install postgresql-16"
            elif has dnf; then
                echo "    sudo dnf install postgresql-server"
            elif has yum; then
                echo "    sudo yum install postgresql-server"
            else
                echo "    (install PostgreSQL from your distribution's package manager)"
            fi
        else
            echo "    brew install postgresql@16"
        fi
        echo ""
        echo "  Then create the database:"
        echo "    sudo -u postgres createuser pingwaf"
        echo "    sudo -u postgres createdb -O pingwaf pingwaf"
        echo "    sudo -u postgres psql -c \"ALTER USER pingwaf PASSWORD 'pingwaf';\""
        echo ""
    fi
}

if [[ "$MODE" == "agent" ]]; then
    info "Agent mode: skipping the PostgreSQL check, nodes keep no database."
else
    check_postgres
fi

# ─── Firewall Hints ───────────────────────────────────────────────────────────
print_firewall_hints() {
    if [[ "$OS" != "linux" ]]; then return; fi

    echo ""
    if [[ "$MODE" == "agent" ]]; then
        info "Firewall ports:"
        echo "    80/tcp   — HTTP traffic (proxied sites)"
        echo "    443/tcp  — HTTPS traffic (proxied sites)"
        echo "  Outbound to the control plane (${SERVER_URL}) must be allowed."
        echo ""
        if has ufw; then
            echo "  With UFW:"
            echo "    sudo ufw allow 80/tcp"
            echo "    sudo ufw allow 443/tcp"
        fi
        return
    fi

    info "Firewall ports to open:"
    echo "    80/tcp   — HTTP traffic (proxied sites)"
    echo "    443/tcp  — HTTPS traffic (proxied sites)"
    echo "    9080/tcp — Admin dashboard & REST API (HTTPS)"
    echo "    9090/tcp — gRPC control plane (agent connections)"
    echo ""
    if has ufw; then
        echo "  With UFW:"
        echo "    sudo ufw allow 80/tcp"
        echo "    sudo ufw allow 443/tcp"
        echo "    sudo ufw allow 9080/tcp"
        echo "    sudo ufw allow 9090/tcp"
    fi
}

print_firewall_hints

# ─── Success ──────────────────────────────────────────────────────────────────
echo ""
echo "${BOLD}${GREEN}═══════════════════════════════════════════════════════════════${NO_COLOR}"
echo "${BOLD}${GREEN}  PingWAF v${VERSION} installed successfully!${NO_COLOR}"
echo "${BOLD}${GREEN}═══════════════════════════════════════════════════════════════${NO_COLOR}"
echo ""
echo "  Binary:    ${INSTALL_DIR}/${BINARY_NAME}"
if [[ "$OS" == "linux" ]]; then
    echo "  Config:    ${CONFIG_DIR}/pingwaf.toml"
    echo "  Data:      ${DATA_DIR}/"
    echo "  Service:   systemctl {start|stop|restart|status} ${SERVICE_NAME}"
fi

if [[ "$MODE" == "agent" ]]; then
    echo ""
    echo "  Next steps:"
    echo "    1. Confirm the node appears under Nodes in the dashboard"
    if [[ "$OS" == "linux" ]]; then
        echo "    2. If it does not: systemctl status ${SERVICE_NAME} && journalctl -u ${SERVICE_NAME} -e"
    else
        echo "    2. If it does not, run the agent in the foreground to see the error"
    fi
    echo "    3. Point another control plane at it by editing ${CONFIG_DIR}/pingwaf.toml"
    echo ""
else
    echo ""
    echo "  Quick start:"
    echo "    ${BINARY_NAME} ${MODE} --db-url \"${DB_URL}\""
    echo ""
    echo "  Dashboard: https://localhost:9080  (self-signed certificate)"
    echo "  Default credentials:"
    echo "    Email:    admin@pingwaf.local"
    echo "    Password: pingwaf123"
    echo ""
    echo "  ${YELLOW}⚠ Change the default admin password and JWT secret in production!${NO_COLOR}"
    echo ""
    echo "  Next steps:"
    echo "    1. Ensure PostgreSQL is running and accessible"
    echo "    2. Edit ${CONFIG_DIR}/pingwaf.toml, then: sudo systemctl restart ${SERVICE_NAME}"
    echo "    3. Start the service: sudo systemctl enable --now ${SERVICE_NAME}"
    echo "    4. Open the dashboard and add your first site"
    echo ""
fi
