#!/bin/bash
set -euo pipefail

# Demo: Two guests (Alice publishes, Bob subscribes) via Moat + MoQ relay
#
# Usage: ./demo-2-guests.sh [moat_url] [relay_url]
#
# Defaults assume running on the same host as the services.

MOAT_URL="${1:-http://localhost:3200}"
RELAY_URL="${2:-https://localhost:4443}"
ROOM_NAME="demo-$(date +%s)"
NAMESPACE_PREFIX="conference/$ROOM_NAME"

echo "=== Moat + MoQ Relay: 2-Guest Demo ==="
echo "  Moat:      $MOAT_URL"
echo "  Relay:     $RELAY_URL"
echo "  Room:      $ROOM_NAME"
echo "  Namespace: $NAMESPACE_PREFIX"
echo ""

# --- Step 1: Create room ---
echo "[1/7] Creating room..."
ROOM_RESP=$(curl -sf -X POST "$MOAT_URL/v1/rooms" \
  -H "Content-Type: application/json" \
  -d "{\"name\": \"$ROOM_NAME\", \"namespace_prefix\": \"$NAMESPACE_PREFIX\"}")
ROOM_ID=$(echo "$ROOM_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
echo "  Room ID: $ROOM_ID"

# --- Step 2: Guest login — Alice ---
echo "[2/7] Alice: guest login..."
ALICE_RESP=$(curl -sf -X POST "$MOAT_URL/v1/auth/guest" \
  -H "Content-Type: application/json" \
  -d '{"display_name": "Alice"}')
ALICE_ID=$(echo "$ALICE_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['user_id'])")
ALICE_SESSION=$(echo "$ALICE_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['session_token'])")
echo "  Alice ID: $ALICE_ID"

# --- Step 3: Guest login — Bob ---
echo "[3/7] Bob: guest login..."
BOB_RESP=$(curl -sf -X POST "$MOAT_URL/v1/auth/guest" \
  -H "Content-Type: application/json" \
  -d '{"display_name": "Bob"}')
BOB_ID=$(echo "$BOB_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['user_id'])")
BOB_SESSION=$(echo "$BOB_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['session_token'])")
echo "  Bob ID: $BOB_ID"

# --- Step 4: Add members to room ---
echo "[4/7] Adding members to room..."
curl -sf -X POST "$MOAT_URL/v1/rooms/$ROOM_ID/members" \
  -H "Content-Type: application/json" \
  -d "{\"user_id\": \"$ALICE_ID\", \"role\": \"publisher\"}" > /dev/null
echo "  Alice → publisher"

curl -sf -X POST "$MOAT_URL/v1/rooms/$ROOM_ID/members" \
  -H "Content-Type: application/json" \
  -d "{\"user_id\": \"$BOB_ID\", \"role\": \"subscriber\"}" > /dev/null
echo "  Bob → subscriber"

# --- Step 5: Mint tokens ---
echo "[5/7] Minting C4M tokens..."
ALICE_TOKEN_RESP=$(curl -sf -X POST "$MOAT_URL/v1/token" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ALICE_SESSION" \
  -d "{\"room_id\": \"$ROOM_ID\", \"role\": \"publisher\"}")
ALICE_TOKEN=$(echo "$ALICE_TOKEN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
ALICE_TOKEN_TYPE=$(echo "$ALICE_TOKEN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['token_type'])")
ALICE_EXPIRES=$(echo "$ALICE_TOKEN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['expires_in'])")
echo "  Alice token: ${ALICE_TOKEN:0:40}... (type=$ALICE_TOKEN_TYPE, expires=${ALICE_EXPIRES}s)"

BOB_TOKEN_RESP=$(curl -sf -X POST "$MOAT_URL/v1/token" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $BOB_SESSION" \
  -d "{\"room_id\": \"$ROOM_ID\", \"role\": \"subscriber\"}")
BOB_TOKEN=$(echo "$BOB_TOKEN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
BOB_TOKEN_TYPE=$(echo "$BOB_TOKEN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['token_type'])")
BOB_EXPIRES=$(echo "$BOB_TOKEN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['expires_in'])")
echo "  Bob token:   ${BOB_TOKEN:0:40}... (type=$BOB_TOKEN_TYPE, expires=${BOB_EXPIRES}s)"

# --- Step 6: Alice publishes ---
echo "[6/7] Alice: publishing to $NAMESPACE_PREFIX/alice/audio ..."
echo ""
echo "  Run in terminal 1:"
echo "  ---"
echo "  moq-clock-ietf \\"
echo "    --name \"$NAMESPACE_PREFIX/alice/audio\" \\"
echo "    --tls-disable-verify \\"
echo "    --auth-token \"$ALICE_TOKEN\" \\"
echo "    --auth-token-type $ALICE_TOKEN_TYPE \\"
echo "    $RELAY_URL"
echo ""

# --- Step 7: Bob subscribes ---
echo "[7/7] Bob: subscribing to $NAMESPACE_PREFIX ..."
echo ""
echo "  Run in terminal 2:"
echo "  ---"
echo "  moq-sub \\"
echo "    --namespace \"$NAMESPACE_PREFIX\" \\"
echo "    --tls-disable-verify \\"
echo "    --auth-token \"$BOB_TOKEN\" \\"
echo "    --auth-token-type $BOB_TOKEN_TYPE \\"
echo "    $RELAY_URL"
echo ""

echo "=== Setup complete ==="
echo ""
echo "Summary:"
echo "  Room:          $ROOM_NAME ($ROOM_ID)"
echo "  Alice (pub):   $ALICE_ID"
echo "  Bob (sub):     $BOB_ID"
echo "  Namespace:     $NAMESPACE_PREFIX"
echo "  Token type:    $ALICE_TOKEN_TYPE (C4M)"
echo ""
echo "The commands above connect to the relay with C4M auth tokens."
echo "Alice's token scopes: ClientSetup + Publisher on '$NAMESPACE_PREFIX/*'"
echo "Bob's token scopes:   ClientSetup + Subscriber on '$NAMESPACE_PREFIX/*'"
