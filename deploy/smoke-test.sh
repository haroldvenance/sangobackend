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

# 5. Faucet drip.
#
# ## Adresse unique par exécution
#
# Le faucet a un cooldown par adresse (3600 s). Une adresse fixe
# rendrait le test non rejouable immédiatement. On dérive une
# adresse depuis le timestamp nanoseconde (hash SHA-256 tronqué
# à 40 chars hex = 20 bytes).
#
# ## 200 ou 429 : les deux sont OK
#
# Un drip (200) prouve que le faucet signe et envoie.
# Un 429 prouve qu'il rate-limite correctement.
# Les deux signifient « le faucet répond ».
ADDR_UNIQUE="0x$(printf '%s' "$(date +%s%N)" | sha256sum | head -c 40)"

HTTP_CODE=$(curl -s -o /tmp/faucet-drip.json -w '%{http_code}' \
    -X POST -H 'Content-Type: application/json' \
    -d "{\"address\":\"$ADDR_UNIQUE\"}" \
    "$FAUCET/faucet")

case "$HTTP_CODE" in
    200)
        DTX=$(jq -r .tx_hash < /tmp/faucet-drip.json)
        [[ "$DTX" == 0x* ]] || fail "tx_hash mal formé: $DTX"
        ok "faucet drip → $DTX"
        ;;
    429)
        ok "faucet drip → 429 (rate limit actif)"
        ;;
    *)
        cat /tmp/faucet-drip.json >&2
        fail "faucet drip: code HTTP inattendu $HTTP_CODE"
        ;;
esac

# 6. Explorer home.
ETITLE=$(curl -sf "$EXPLORER/" | grep -o '<title>[^<]*</title>' | head -1) \
    || fail "explorer / injoignable"
[[ "$ETITLE" == *"Sango"* ]] || fail "explorer title inattendu: $ETITLE"
ok "explorer : $ETITLE"

# 7. Explorer health.
#
# L'explorer renvoie du HTML avec le JSON échappé dans un <pre> :
#   <pre>&quot;height&quot;: 47</pre>
# On ne peut donc pas matcher directement `"height": N`.
EHEALTH_HTML=$(curl -sf "$EXPLORER/health") \
    || fail "explorer /health injoignable"
echo "$EHEALTH_HTML" | grep -q "Statut" \
    || fail "explorer /health ne contient pas 'Statut'"
EHEIGHT=$(echo "$EHEALTH_HTML" \
    | grep -oE '&quot;height&quot;: [0-9]+' \
    | head -1 \
    | grep -oE '[0-9]+$')
[ -n "$EHEIGHT" ] || fail "hauteur introuvable dans /health"
ok "explorer health : height=$EHEIGHT"

# 8. Prometheus /metrics sur node-0 (port metrics interne :9090,
#    NON publié sur l'hôte par défaut — on passe par node-0:9090 ou
#    via le port publié si surchargé).
#
# Par défaut, le port metrics n'est PAS publié sur l'hôte (voir
# docker-compose.yml). On teste via l'API Prometheus qui scrape les
# nœuds en interne.
PROM="${PROMETHEUS:-http://127.0.0.1:9090}"
PUP=$(curl -sf "$PROM/-/ready" >/dev/null && echo "up" || echo "down")
[ "$PUP" = "up" ] || fail "prometheus /-/ready injoignable"
ok "prometheus ready"

# Vérifier que Prometheus voit au moins un nœud.
TARGETS=$(curl -sf "$PROM/api/v1/targets" | jq -r '.data.activeTargets | length' 2>/dev/null || echo "0")
[ "$TARGETS" -ge 4 ] || fail "prometheus ne voit que $TARGETS targets (< 4)"
ok "prometheus targets = $TARGETS"

echo ""
echo "✓ Tous les checks sont verts."
