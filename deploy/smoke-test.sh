#!/usr/bin/env bash
# Smoke test rapide après `docker compose up -d`.
#
# Requiert : curl, jq.
#
# Sortie : série de ✓ et exit 0 si tout est vert, exit 1 sinon.

set -euo pipefail

RPC="${RPC:-http://127.0.0.1:8545/rpc}"
FAUCET="${FAUCET:-http://127.0.0.1:3001}"
EXPLORER="${EXPLORER:-http://127.0.0.1:8090}"

fail() { echo "✗ $1"; exit 1; }
ok()   { echo "✓ $1"; }

rpc() {
    local method="$1"; shift
    local params="$1"; shift
    curl -sf -X POST -H 'Content-Type: application/json' \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":$params,\"id\":1}" \
        "$RPC"
}

# 1. Attente node-0 (jusqu'à 60s).
echo "Attente du RPC node-0..."
for i in $(seq 1 60); do
    if rpc "sango_blockNumber" "[]" >/dev/null 2>&1; then break; fi
    sleep 1
done
rpc "sango_blockNumber" "[]" >/dev/null 2>&1 || fail "node-0 RPC injoignable après 60s"
ok "node-0 RPC joignable"

# 2. Hauteur.
BLOCK=$(rpc "sango_blockNumber" "[]" | jq -r .result)
[ "$BLOCK" != "null" ] || fail "blockNumber null"
ok "blockNumber = $BLOCK"

# 3. Validators.
VCOUNT=$(rpc "sango_getValidators" "[]" | jq '.result | length')
[ "$VCOUNT" -ge 4 ] || fail "attendu ≥ 4 validateurs, trouvé $VCOUNT"
ok "validators = $VCOUNT"

# 4. Faucet health.
FHEALTH=$(curl -sf "$FAUCET/health") || fail "faucet /health injoignable"
FBAL=$(echo "$FHEALTH" | jq -r .balance_base_units)
[ "$FBAL" != "null" ] || fail "faucet balance null"
ok "faucet balance = $FBAL base units"

# 5. Faucet drip (vers une adresse bidon).
DRIP=$(curl -sf -X POST -H 'Content-Type: application/json' \
    -d '{"address":"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}' \
    "$FAUCET/faucet") || fail "faucet POST /faucet a échoué"
DTX=$(echo "$DRIP" | jq -r .tx_hash)
[[ "$DTX" == 0x* ]] || fail "tx_hash mal formé: $DTX"
ok "faucet drip → $DTX"

# 6. Explorer home.
ETITLE=$(curl -sf "$EXPLORER/" | grep -o '<title>[^<]*</title>' | head -1) \
    || fail "explorer / injoignable"
[[ "$ETITLE" == *"Sango"* ]] || fail "explorer title inattendu: $ETITLE"
ok "explorer : $ETITLE"

# 7. Explorer health (JSON).
EHEALTH=$(curl -sf "$EXPLORER/health" | grep -o '"height": *[0-9]*' | head -1) \
    || fail "explorer /health injoignable"
ok "explorer health : $EHEALTH"

echo ""
echo "✓ Tous les checks sont verts."
