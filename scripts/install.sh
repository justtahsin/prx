#!/usr/bin/env bash
#
# Installs the prx server on this machine: build, install, configure, start.
#
# Usage:
#   sudo ./scripts/install.sh                 # port 443, first user "default"
#   sudo ./scripts/install.sh --port 8443 --user ali --sni www.bing.com
#
# Re-running is safe: an existing configuration is kept and only the binaries
# and the service are refreshed.

set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
CONFIG_DIR="/etc/prx"
CONFIG="$CONFIG_DIR/server.json"

PORT=443
USER_NAME="default"
SNI=""
HOST=""
FALLBACK=""

die() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
info() { printf '\033[36m==>\033[0m %s\n' "$*"; }

usage() {
    cat <<'EOF'
Usage: sudo ./scripts/install.sh [options]

  --port <n>        port to listen on (default 443)
  --user <name>     name of the first user (default "default")
  --sni <name>      SNI to put in generated links
  --host <addr>     public address for links (detected when omitted)
  --fallback <addr> hand unauthenticated visitors to this web server,
                    e.g. 127.0.0.1:8080 (default: built-in decoy page)
  -h, --help        this message
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --port)     PORT="${2:?--port needs a value}"; shift 2 ;;
        --user)     USER_NAME="${2:?--user needs a value}"; shift 2 ;;
        --sni)      SNI="${2:?--sni needs a value}"; shift 2 ;;
        --host)     HOST="${2:?--host needs a value}"; shift 2 ;;
        --fallback) FALLBACK="${2:?--fallback needs a value}"; shift 2 ;;
        -h|--help)  usage; exit 0 ;;
        *)          die "unknown option: $1 (try --help)" ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "run this with sudo"

cd "$(dirname "$0")/.."

command -v go >/dev/null 2>&1 || die "Go is not installed. Install Go 1.24+ and run this again."

info "building"
make build VERSION="${VERSION:-0.1.0}" >/dev/null

info "installing to $PREFIX/bin"
install -Dm755 bin/prxd "$PREFIX/bin/prxd"
install -Dm755 bin/prx  "$PREFIX/bin/prx"

if [ -f "$CONFIG" ]; then
    info "keeping the existing configuration at $CONFIG"
else
    info "creating the configuration and the first user"
    args=(-c "$CONFIG" -listen ":$PORT" -user "$USER_NAME")
    [ -n "$SNI" ]      && args+=(-sni "$SNI")
    [ -n "$HOST" ]     && args+=(-host "$HOST")
    [ -n "$FALLBACK" ] && args+=(-fallback "$FALLBACK")
    "$PREFIX/bin/prxd" init "${args[@]}"
fi

info "installing the systemd service"
"$PREFIX/bin/prxd" install -c "$CONFIG"

# A firewall that silently drops the port is the most common reason a fresh
# install appears not to work, so say something rather than leave it to be
# discovered later.
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    if ! ufw status | grep -q "^$PORT"; then
        printf '\n\033[33mnote:\033[0m ufw is active and port %s is not open. Run: ufw allow %s/tcp\n' "$PORT" "$PORT"
    fi
fi

cat <<EOF

Done.

  prxd user add <name>    add a user and print their link
  prxd link <name>        print an existing user's link again
  systemctl status prxd   check the service
  journalctl -u prxd -f   follow the log

On the client machine:

  prx '<link>'            SOCKS5 on 127.0.0.1:1080, HTTP on 127.0.0.1:1081
  prx test '<link>'       check that the tunnel works
EOF
