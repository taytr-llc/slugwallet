# Public-fixture wallet foundation gate

Run from the wallet checkout with a normal production-PoW `slugd` binary:

```sh
SLUG_WALLET_NODE=/private/tmp/slug-set22-release-bin/slugd \
  ./integration/run-foundation.sh
```

This opt-in test uses an isolated temporary directory, one no-listen/no-DNS
node connected only to `127.0.0.1:0`, and authenticated loopback wallet RPC.
It never connects to the Railway seed, reads an existing wallet, or accesses
operator keys. Node and wallet shutdown are checked. All data and passphrases
are disposable, explicitly public fixtures.

The seed `000102030405060708090a0b0c0d0e0f` is the published
[BIP32 test vector 1](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vector-1).
`testdata/reference_addresses.py` independently implements secp256k1 arithmetic,
BIP32 HMAC derivation, Base58Check, and Bech32 with Python's standard library.
It checks the published master xpub before generating SLUG legacy and witness
receive/change vectors. It reads no Go implementation or wallet outputs.
Regenerate with no arguments; use `--check` to compare the committed JSON.
Coin type 0 is retained for this foundation, not chosen as a future custody rule.

The integration uses the loader only to create/open the fixture database from
that explicit raw seed. Address creation, balance, unlocking, spending, and
transaction history use the wallet's legacy RPC surface. It verifies:

- Exact independent first legacy and `slug` witness receive/change addresses.
- Network magic and genesis identity, normal Argon2id work, and a 10 SLUG reward.
- No spendable reward at 99 confirmations; 10 SLUG spendable at 100 confirmations.
- A signed spend accepted by the node, mined confirmation, and change balance.
- Close/reopen with unchanged balance and complete signed transaction bytes.
- Fresh seed restoration with a 20-address branch lookahead, recovered history
  and balance, followed by a second confirmed spend using the restored wallet.

This is raw-seed restoration evidence for a fixture wallet. It is not D48
login/custody/phrase export, gym identity derivation, encrypted recovery-file
export, user-issuance approval, or fighter transfer. No BIP39 phrase contract is
introduced. The test is deliberately excluded from cheap-PoW builds and normal
short unit-test runs; allow up to 15 minutes for the production-PoW gate.
