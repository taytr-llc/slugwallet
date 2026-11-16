# Independent network encoding fixtures

`bitcoin_encoding_inputs.json` contains already-public deterministic test
encodings from btcwallet v0.18.1, commit
`43f2950d2a065a7b3d4a4a1cf17ed1e84af6bcb4`. Each entry identifies its upstream
file and line. The BIP86 root and address examples originate in the published
BIP86 vectors. These fixture private encodings must never hold real funds.

`reencode_vectors.py` uses only the Python standard library. It validates the
original Base58Check or Bech32/Bech32m checksum, retains the key/script payload,
and recalculates the network version or human-readable prefix and checksum for
SLUG. It never calls the wallet implementation or treats its output as a golden.
The resulting `slug_encoding_vectors.json` also records the unchanged payload.
Coin type, derivation path, compression flag, witness version and key bytes do
not change.

Check the frozen vectors:

```sh
python3 waddrmgr/testdata/reencode_vectors.py --check
```

Running without `--check` regenerates the JSON. `--update-tests` additionally
replaces exact upstream mainnet literals in the named waddrmgr test files and
the transaction-fee address fixture in `wallet/createtx_test.go`;
it never edits runtime code. Wallet testnet fixtures remain testnet fixtures.
`TestSLUGImportAccount` loads independently converted counterparts to exercise
SLUG imports with explicit address type and foreign-network rejection.

The single SLUG HD public prefix identifies the network. It does not infer a
mixed BIP49+ receive/change schema or constitute a complete recovery export.
