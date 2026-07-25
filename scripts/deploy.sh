#!/usr/bin/env bash
#
# Installs the prx server on a remote host over SSH and prints a connection
# link for a new user.
#
# Usage:
#   ./scripts/deploy.sh root@vps.example.com
#   ./scripts/deploy.sh root@vps.example.com --port 8443 --user phone
#
# Nothing needs to be installed on the remote host: the binary is
# cross-compiled here for whatever architecture it reports.
#
# Re-running is safe. An existing configuration is left alone, the binary is
# refreshed and the service restarted.

set -euo pipefail

PORT=443
USER_NAME="phone"
SNI=""
FALLBACK=""

die() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
info() { printf '\033[36m==>\033[0m %s\n' "$*"; }
note() { printf '\033[33mnote:\033[0m %s\n' "$*"; }

usage() {
    cat <<'EOF'
Usage: ./scripts/deploy.sh <user@host> [options]

  --port <n>        port the server listens on (default 443)
  --user <name>     user to create and print a link for (default "phone")
  --sni <name>      SNI to put in the generated link
  --fallback <addr> hand unauthenticated visitors to this web server
  -h, --help        this message

The remote host needs SSH access and systemd. Everything else is handled.
EOF
}

[ $# -gt 0 ] || { usage; exit 1; }
TARGET="$1"; shift
case "$TARGET" in -h|--help) usage; exit 0 ;; esac

while [ $# -gt 0 ]; do
    case "$1" in
        --port)     PORT="${2:?--port needs a value}"; shift 2 ;;
        --user)     USER_NAME="${2:?--user needs a value}"; shift 2 ;;
        --sni)      SNI="${2:?--sni needs a value}"; shift 2 ;;
        --fallback) FALLBACK="${2:?--fallback needs a value}"; shift 2 ;;
        -h|--help)  usage; exit 0 ;;
        *)          die "unknown option: $1 (try --help)" ;;
    esac
done

cd "$(dirname "$0")/.."
command -v go >/dev/null 2>&1 || die "Go is not installed here (it is not needed on the server)"

SSH=(ssh -o BatchMode=no -o ConnectTimeout=15 "$TARGET")

info "checking $TARGET"
REMOTE_ARCH="$("${SSH[@]}" 'uname -m' 2>/dev/null)" || die "cannot reach $TARGET over SSH"
case "$REMOTE_ARCH" in
    x86_64|amd64)   GOARCH=amd64 ;;
    aarch64|arm64)  GOARCH=arm64 ;;
    armv7l|armv7)   GOARCH=arm ;;
    *)              die "unsupported server architecture: $REMOTE_ARCH" ;;
esac
info "server is linux/$GOARCH"

info "building prxd for linux/$GOARCH"
mkdir -p bin
GOOS=linux GOARCH="$GOARCH" CGO_ENABLED=0 \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION:-0.1.0}" \
    -o "bin/prxd-linux-$GOARCH" ./cmd/prxd

info "uploading"
scp -q "bin/prxd-linux-$GOARCH" "$TARGET:/tmp/prxd.new"

info "installing"
# The remote side runs as one script so a dropped connection cannot leave a
# half-installed server behind.
"${SSH[@]}" "PORT='$PORT' SNI='$SNI' FALLBACK='$FALLBACK' USER_NAME='$USER_NAME' bash -s" <<'REMOTE'
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "the SSH user must be root or use sudo" >&2; exit 1; }

install -Dm755 /tmp/prxd.new /usr/local/bin/prxd
rm -f /tmp/prxd.new

if [ ! -f /etc/prx/server.json ]; then
    args=(-c /etc/prx/server.json -listen ":$PORT" -user "$USER_NAME" -no-qr)
    [ -n "$SNI" ] && args+=(-sni "$SNI")
    [ -n "$FALLBACK" ] && args+=(-fallback "$FALLBACK")
    /usr/local/bin/prxd init "${args[@]}" >/dev/null
    echo "created /etc/prx/server.json"
else
    echo "kept the existing /etc/prx/server.json"
fi

/usr/local/bin/prxd install -c /etc/prx/server.json >/dev/null
systemctl restart prxd
sleep 1
systemctl is-active --quiet prxd || { journalctl -u prxd -n 20 --no-pager >&2; exit 1; }
echo "prxd is running"

# Open the port where a firewall is obviously in charge. Silence here is
# fine; a cloud provider's own firewall is outside this script's reach.
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw allow "$PORT/tcp" >/dev/null 2>&1 && echo "opened $PORT/tcp in ufw"
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port="$PORT/tcp" >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 && echo "opened $PORT/tcp in firewalld"
fi
REMOTE

info "fetching the link for \"$USER_NAME\""
LINK="$("${SSH[@]}" "/usr/local/bin/prxd user add '$USER_NAME' -c /etc/prx/server.json -no-qr 2>/dev/null | grep '^prx://' || /usr/local/bin/prxd link '$USER_NAME' -c /etc/prx/server.json -no-qr | grep '^prx://'")"
[ -n "$LINK" ] || die "the server did not return a link"

echo
echo "$LINK"
echo

if command -v qrencode >/dev/null 2>&1; then
    qrencode -t ANSIUTF8 "$LINK"
else
    note "install qrencode to see a scannable QR code here, or open this link on the phone directly"
fi

cat <<EOF

Test it from this machine:

  ./bin/prx test '$LINK'

On the phone: open the prx app, paste the link, press Connect.
If your provider has its own firewall, port $PORT/tcp must be open there too.
EOF
