# Sango devnet — docker compose

Devnet 4 validateurs + faucet + explorer.

## Démarrage

    cd deploy
    docker compose build      # ~10 min la 1re fois
    docker compose up -d
    ./smoke-test.sh

## Ports

- RPC : 8545, 8555, 8565, 8575 (node-0..3)
- P2P QUIC : 9000..9003/udp
- Faucet : 3001
- Explorer : 8090

## Arrêt

    docker compose down       # garde les volumes
    docker compose down -v    # reset complet

## Config

- Genesis : configs/devnet-4v/node-{0..3}.json
- Faucet  : configs/faucet.json
- Explorer: configs/explorer.json
- Ports   : copier .env.example en .env

## Debug

    docker compose logs -f node-0
    docker compose ps

## Production

Retirer --mdns, ajouter --p2p-bootstrap explicites, TLS via
--rpc-tls-cert / --rpc-tls-key, seeds distinctes.
