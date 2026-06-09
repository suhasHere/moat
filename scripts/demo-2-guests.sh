#!/bin/bash
set -euo pipefail

# Demo: Two guests (Alice publishes, Bob subscribes) via Moat + MoQ relay
#
# Usage: ./demo-2-guests.sh [moat_url] [relay_url]
#   Run on the same host as Moat and relay, or pass URLs.
#
# What this does:
#   1. Creates a room
#   2. Alice: guest login → add to room as publisher → mint token
#   3. Bob: guest login → add to room as subscriber → mint token
#   4. Prints the commands to run Alice (publisher) and Bob (subscriber)

MOAT_URL="${1:-http://localhost:3200}"
RELAY_URL="${2:-https://localhost:4443}"
ROOM_NAME="demo-$(date +%s)"
NAMESPACE="conference/$ROOM_NAME"

echo "=== Moat + MoQ: 2-Guest Demo ==="
echo "  Moat:      $MOAT_URL"
echo "  Relay:     $RELAY_URL"
echo "  Room:      $ROOM_NAME"
echo "  Namespace: $NAMESPACE"
echo ""

# Helper
json_field() { python3 -c "import sys,json; print(json.load(sys.stdin)['$1'])"; }

# --- Step 1: Create room ---
echo "[1/6] Creating room '$ROOM_NAME'..."
ROOM_RESP=$(curl -sf -X POST "$MOAT_URL/v1/rooms" \
  -H "Content-Type: application/json" \
  -d "{\"name\": \"$ROOM_NAME\", \"namespace_prefix\": \"$NAMESPACE\"}")
ROOM_ID=$(echo "$ROOM_RESP" | json_field id)
echo "  Room ID: $ROOM_ID"
echo ""

# --- Step 2: Alice guest login ---
echo "[2/6] Alice: guest login..."
ALICE_RESP=$(curl -sf -X POST "$MOAT_URL/v1/auth/guest" \
  -H "Content-Type: application/json" \
  -d '{"display_name": "Alice"}')
ALICE_ID=$(echo "$ALICE_RESP" | json_field user_id)
ALICE_SESSION=$(echo "$ALICE_RESP" | json_field session_token)
echo "  User ID: $ALICE_ID"
echo ""

# --- Step 3: Bob guest login ---
echo "[3/6] Bob: guest login..."
BOB_RESP=$(curl -sf -X POST "$MOAT_URL/v1/auth/guest" \
  -H "Content-Type: application/json" \
  -d '{"display_name": "Bob"}')
BOB_ID=$(echo "$BOB_RESP" | json_field user_id)
BOB_SESSION=$(echo "$BOB_RESP" | json_field session_token)
echo "  User ID: $BOB_ID"
echo ""

# --- Step 4: Add to room ---
echo "[4/6] Adding members to room..."
curl -sf -X POST "$MOAT_URL/v1/rooms/$ROOM_ID/members" \
  -H "Content-Type: application/json" \
  -d "{\"user_id\": \"$ALICE_ID\", \"role\": \"publisher\"}" > /dev/null
echo "  Alice → publisher"

curl -sf -X POST "$MOAT_URL/v1/rooms/$ROOM_ID/members" \
  -H "Content-Type: application/json" \
  -d "{\"user_id\": \"$BOB_ID\", \"role\": \"subscriber\"}" > /dev/null
echo "  Bob   → subscriber"
echo ""

# --- Step 5: Mint Alice's token ---
echo "[5/6] Minting Alice's publisher token..."
ALICE_TOKEN_RESP=$(curl -sf -X POST "$MOAT_URL/v1/token" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ALICE_SESSION" \
  -d "{\"room_id\": \"$ROOM_ID\", \"role\": \"publisher\"}")
ALICE_TOKEN=$(echo "$ALICE_TOKEN_RESP" | json_field token)
echo "  Token: ${ALICE_TOKEN:0:50}..."
echo ""

# --- Step 6: Mint Bob's token ---
echo "[6/6] Minting Bob's subscriber token..."
BOB_TOKEN_RESP=$(curl -sf -X POST "$MOAT_URL/v1/token" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $BOB_SESSION" \
  -d "{\"room_id\": \"$ROOM_ID\", \"role\": \"subscriber\"}")
BOB_TOKEN=$(echo "$BOB_TOKEN_RESP" | json_field token)
echo "  Token: ${BOB_TOKEN:0:50}..."
echo ""

echo "============================================"
echo "=== READY — Run these in separate terminals:"
echo "============================================"
echo ""
echo "--- Terminal 1: Alice (publisher) ---"
echo ""
echo "  ./target/release/moq-clock-ietf \\"
echo "    --name \"$NAMESPACE/alice/audio\" \\"
echo "    --tls-disable-verify \\"
echo "    --auth-token \"$ALICE_TOKEN\" \\"
echo "    --auth-token-type 6501485 \\"
echo "    $RELAY_URL"
echo ""
echo "--- Terminal 2: Bob (subscriber) ---"
echo ""
echo "  ./target/release/moq-sub \\"
echo "    --namespace \"$NAMESPACE\" \\"
echo "    --tls-disable-verify \\"
echo "    --auth-token \"$BOB_TOKEN\" \\"
echo "    --auth-token-type 6501485 \\"
echo "    $RELAY_URL"
echo ""
echo "============================================"
echo ""
echo "Or use the anonymous shortcut (no login needed):"
echo ""
echo "  curl -s -X POST $MOAT_URL/v1/token/anonymous \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -d '{\"room_id\": \"$ROOM_NAME\", \"role\": \"publisher\"}'"
echo ""
