Troubleshooting — erreurs fréquentes

Cette page regroupe les erreurs les plus courantes, classées par
binaire. Si rien ne correspond, ouvre une issue avec :

    la commande exacte ;

    la sortie complète ;

    le chain_id (sango_chainId) ;

    la hauteur (sango_blockNumber).

Node — sango-node
Symptôme	Cause probable	Fix
Address already in use	Port 8545 (ou 9001) déjà pris	Tue le process, ou change --rpc-addr / --p2p-addr
failed to open data-dir	Mauvais chemin ou permissions	Vérifie le chemin, chmod
genesis parse error	JSON Genesis invalide	python3 -m json.tool examples/devnet.json
Nœud bloqué à #0	Timers de consensus non démarrés	Vérifie la config Genesis (validators)
--seeds + --no-p2p	Flags incompatibles	Enlève --seeds si --no-p2p
Wallet — sango-wallet
Message	Cause	Fix
keyfile already exists	new sur un fichier existant	Supprime ou change --keyfile
invalid passphrase	Mauvaise passphrase, ou JSON modifié	Retape la passphrase, keyfile-info
insufficient balance	Solde insuffisant	Demande au faucet
missing flag --to	Flag obligatoire oublié	Ajoute --to 0x…
rpc error [-32602]	Paramètre mal formé	Vérifie adresse, montant
rpc error [-32001]	Entité absente	Vérifie le hash / l'adresse
error sending request	RPC non joignable	Vérifie --rpc, sango_blockNumber
certificate verify failed	TLS avec CA inconnue	--rpc-tls-ca ou --rpc-tls-insecure (devnet)
RPC — erreurs JSON-RPC
Code	Signification	Piste
-32600	Requête invalide	Vérifie jsonrpc: "2.0"
-32601	Méthode inconnue	Faute de frappe ? sango_* vs eth_*
-32602	Paramètres invalides	Compte / type / format
-32603	Erreur interne	Regarde les logs du node
-32001	Entité absente	Hash / bloc / compte inexistant
-32010	Tx rejetée par le mempool	Nonce, balance, signature, chain_id
Faucet — sango-faucet
Symptôme	Cause	Fix
connection refused (RPC)	Node non lancé	Démarre le node d'abord
HTTP 429	Rate limit atteint	Attends, ou change d'adresse
HTTP 400	Adresse mal formée	0x + 40 hex exactement
HTTP 500	Compte faucet vide	Réapprovisionne via Genesis
Erreurs EVM
Message	Cause	Fix
nonce too low	Tx déjà incluse, ou nonce désync	Récupère eth_getTransactionCount
insufficient funds	Solde EVM insuffisant	Crédite le compte EVM
intrinsic gas too low	gas < 21 000	Passe --gas 21000 minimum
invalid chain id	chain_id EVM incorrect	Vérifie eth_chainId
invalid signature	Mauvais format de signature	Vérifie --tx-type (1559 par défaut)
Diagnostic rapide
bash

# Le node répond ?
curl -s -X POST http://127.0.0.1:8545/rpc \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","method":"sango_chainInfo","params":[],"id":1}' \
    | python3 -m json.tool

# Le faucet répond ?
curl -s -X POST http://127.0.0.1:3001/faucet \
    -H 'Content-Type: application/json' \
    -d '{"address":"0x…"}' \
    | python3 -m json.tool

Voir aussi

    RPC — table complète des codes d'erreur

    Wallet — erreurs spécifiques au CLI

    Devnet — redémarrer proprement