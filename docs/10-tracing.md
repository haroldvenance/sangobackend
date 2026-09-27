
# Tracing — logs de debug

`sango-node` utilise `tracing` avec `EnvFilter`. Le niveau par défaut est
`info`.

## Variables d'environnement

| Variable | Effet |
|---|---|
| `RUST_LOG` | Niveau global (`error`, `warn`, `info`, `debug`, `trace`) |
| `RUST_LOG=<crate>=<niveau>` | Surcharge par crate |

Exemples :

```bash
# Tout en info (défaut)
cargo run -p sango-node -- --config examples/devnet.json ...

# Debug sur le node, le reste en warn
RUST_LOG=sango_node=debug,warn cargo run -p sango-node -- ...

# Debug partout (verbeux)
RUST_LOG=debug cargo run -p sango-node -- ...

# Traces du driver consensus uniquement
RUST_LOG=sango_node::driver=trace cargo run -p sango-node -- ...

Ce qu'on voit à debug

    collect_native_candidates : nombre de senders dans le mempool,
    nombre de txs sélectionnées, max_txs.

    prune_native_mempool : appel après chaque commit.

Ce qu'on voit à warn

    Transaction rejetée à la validation (native) : hash de la tx,
    raison (NonceMismatch, InsufficientBalance, etc.).

    Transaction rejetée à l'application (native ou EVM) : hash,
    raison.

C'est le point d'entrée pour débugger une tx « bloquée en mempool » :
bash

RUST_LOG=sango_node=debug cargo run -p sango-node -- ...
# ...
# WARN sango_node::node: native tx rejected at validation tx=0x1234… reason=SelfDelegation

Pas encore couvert

    Le service P2P (sango-p2p) utilise encore eprintln!.

    sango-consensus n'a pas de logs internes.

    sango-exec n'a pas de logs internes.

Pour V1 c'est suffisant pour débugger les txs. On étendra si besoin.