#!/bin/bash
set -euo pipefail

# Run moq-chat end-to-end with guest login via Moat
#
# Prerequisites:
#   - PostgreSQL running with moat database
#   - c4m-private.pem and c4m-public.pem in current directory (or specify paths)
#   - moq-relay-ietf built with --features auth-cat
#   - moq-chat web app at ../moq-web/apps/moq-chat (or CHAT_DIR env var)
#
# Usage: ./run-moq-chat-e2e.sh
#
# This starts:
#   1. Moat token service (port 3200)
#   2. MoQ relay with C4M auth (port 4443)
#   3. moq-chat vite dev server (port 5174)
#
# Then open https://localhost:5174 in your browser.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MOAT_DIR="${MOAT_DIR:-$(dirname "$SCRIPT_DIR")}"
RELAY_DIR="${RELAY_DIR:-$(dirname "$MOAT_DIR")/moq-rs}"
CHAT_DIR="${CHAT_DIR:-$(dirname "$MOAT_DIR")/moq-web/apps/moq-chat}"

# Key paths
PRIVATE_KEY="${C4M_PRIVATE_KEY:-$MOAT_DIR/c4m-private.pem}"
PUBLIC_KEY="${C4M_PUBLIC_KEY:-$MOAT_DIR/c4m-public.pem}"

# Database
DB_URL="${MOAT_DATABASE_URL:-postgres://moat:moat@127.0.0.1:5432/moat}"

# Ports
MOAT_PORT=3200
RELAY_PORT=4443
CHAT_PORT=5174

echo "=== MoQ Chat E2E Setup ==="
echo ""
echo "  Moat dir:   $MOAT_DIR"
echo "  Relay dir:  $RELAY_DIR"
echo "  Chat dir:   $CHAT_DIR"
echo "  Private key: $PRIVATE_KEY"
echo "  Public key:  $PUBLIC_KEY"
echo "  Database:    $DB_URL"
echo ""

# Generate keys if missing
if [ ! -f "$PRIVATE_KEY" ]; then
  echo "[*] Generating ES256 key pair..."
  openssl ecparam -genkey -name prime256v1 -noout | \
    openssl pkcs8 -topk8 -nocrypt -out "$PRIVATE_KEY"
  openssl ec -in "$PRIVATE_KEY" -pubout -out "$PUBLIC_KEY" 2>/dev/null
  echo "  Created: $PRIVATE_KEY, $PUBLIC_KEY"
fi

# Cleanup function
PIDS=()
cleanup() {
  echo ""
  echo "[*] Shutting down..."
  for pid in "${PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  echo "  Done."
}
trap cleanup EXIT INT TERM

# --- Start Moat ---
echo "[1/3] Starting Moat (token service) on :$MOAT_PORT..."
cd "$MOAT_DIR"
if [ ! -f "./target/release/moat" ]; then
  echo "  Building moat..."
  cargo build --release 2>&1 | tail -1
fi
./target/release/moat \
  --bind "0.0.0.0:$MOAT_PORT" \
  --database-url "$DB_URL" \
  --c4m-private-key "$PRIVATE_KEY" \
  --c4m-issuer moat \
  --c4m-audience moq-relay \
  > moat.log 2>&1 &
PIDS+=($!)
sleep 2

# Verify
if ! curl -sf "http://localhost:$MOAT_PORT/health" > /dev/null; then
  echo "  ERROR: Moat failed to start. Check moat.log"
  cat moat.log
  exit 1
fi
echo "  OK"

# --- Start Relay ---
echo "[2/3] Starting MoQ relay on :$RELAY_PORT..."
cd "$RELAY_DIR"
if [ ! -f "./target/release/moq-relay-ietf" ]; then
  echo "  Building relay..."
  cargo build --release --features auth-cat --bin moq-relay-ietf 2>&1 | tail -1
fi

# Generate TLS cert if needed
if [ ! -f cert.pem ] || [ ! -f key.pem ]; then
  echo "  Generating self-signed TLS cert..."
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout key.pem -out cert.pem -days 365 -nodes \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
fi

./target/release/moq-relay-ietf \
  --bind "[::]:$RELAY_PORT" \
  --tls-cert cert.pem \
  --tls-key key.pem \
  --auth-cat-public-key "$PUBLIC_KEY" \
  --auth-cat-issuer moat \
  --auth-cat-audience moq-relay \
  > relay.log 2>&1 &
PIDS+=($!)
sleep 2
echo "  OK"

# --- Create default room ---
echo "[*] Creating default room..."
ROOM_EXISTS=$(curl -sf "http://localhost:$MOAT_PORT/v1/rooms" | python3 -c "
import sys, json
rooms = json.load(sys.stdin)
print('yes' if any(r['name'] == 'general' for r in rooms) else 'no')
" 2>/dev/null || echo "no")

if [ "$ROOM_EXISTS" = "no" ]; then
  curl -sf -X POST "http://localhost:$MOAT_PORT/v1/rooms" \
    -H "Content-Type: application/json" \
    -d '{"name": "general", "namespace_prefix": "chat/general"}' > /dev/null
  echo "  Created 'general' room"
else
  echo "  'general' room already exists"
fi

# --- Start moq-chat ---
echo "[3/3] Starting moq-chat dev server on :$CHAT_PORT..."
cd "$CHAT_DIR"

# Set env vars for vite
export VITE_TOKEN_SERVICE_URL="http://localhost:$MOAT_PORT/v1"
export VITE_RELAY_URL="https://localhost:$RELAY_PORT"

if [ ! -d node_modules ]; then
  echo "  Installing dependencies..."
  npm install 2>&1 | tail -1
fi

npx vite --port $CHAT_PORT --host > chat-dev.log 2>&1 &
PIDS+=($!)
sleep 3
echo "  OK"

echo ""
echo "=== All services running ==="
echo ""
echo "  Moat (token service): http://localhost:$MOAT_PORT"
echo "  Moat Web UI:          http://localhost:$MOAT_PORT/"
echo "  MoQ Relay:            https://localhost:$RELAY_PORT"
echo "  MoQ Chat:             https://localhost:$CHAT_PORT"
echo ""
echo "Open https://localhost:$CHAT_PORT in your browser."
echo "Click 'Join as Guest' to get started."
echo ""
echo "Flow:"
echo "  1. Guest login → local identity (no server auth needed)"
echo "  2. Select room → Moat mints a scoped C4M token"
echo "  3. Connect to relay → C4M token verified via ES256 public key"
echo "  4. Publish/subscribe media over QUIC"
echo ""
echo "Press Ctrl+C to stop all services."
echo ""

# Wait for any child to exit
wait
