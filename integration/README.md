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

## Retained phrase and gym recovery gate (set 24)

The separate recovery gate uses the approved English 24-word phrase profile
with no additional BIP39 passphrase, plus its versioned recovery manifest:

```sh
SLUG_WALLET_NODE=/absolute/path/to/normal/slugd \
  ./integration/run-recovery.sh
```

This explicitly enables both `integration` and `recoveryintegration` build tags
and runs only `TestWalletRecoveryNormalPoW`. The set-23 raw-seed test is unchanged.
The published `zero256` entropy fixture and independently derived expected
addresses/public identities come from `recovery/testdata/recovery_v1.json`.
`testdata/reference_recovery_highwater.py` extends that independent Python
oracle with high-index vectors for every scope; it reads no Go outputs.
The launcher checks both independent oracles before running the gate.

The test issues receive/change addresses in all four supported scopes and
mines only to legacy receive index 25, beyond the ordinary 20-address lookahead.
It confirms a real spend under normal Argon2id, closes and reopens the wallet,
then exports the retained phrase and current high-water manifest after unlock.
It closes and renames the original database before restoring an empty database
using only the exported file. Exact balance, signed transaction history and
ownership of the independently derived addresses must survive; the restored
wallet must make a second confirmed spend that consumes recovered change from
the first spend. The exported file contains only
published test secrets and is created with owner-only permissions in a temporary
directory. The test never reads a real recovery file or wallet.

Legacy wallet RPC supplies addresses, balances, unlock, history and both
`sendtoaddress` spends. Taproot address generation uses the existing wallet API
because the legacy RPC lacks a taproot address option. Both spends are broadcast
to and confirmed by the normal isolated node.

Segwit and Taproot are inactive on the current chain. The first native-funded
attempt reached maturity but the node rejected its witness spend; this is a
separate activation issue. This gate therefore proves live legacy-funded
recovery, plus independent derivation/ownership/high-water restoration for the
other scopes. It does **not** claim a successful funded native-witness or
Taproot round trip. The helper accepts an explicit funding scope for a later
activation test, without changing any node rules. The inherited RPC selection
and change behavior is left intact until that separate workstream.

The same fixture also checks the original and restored gym public identity,
automatic signing through the worker's pinned callback, identical authorization
for identical evidence, a new schema-4 authority admission, and immutable receipt
replay. Production `prospect.Verify` runs outside the wallet signer. Its local
authority uses an explicitly synthetic all-ff prospect threshold and a
coinbase-only share anchored to the isolated node's current parent. These
fixture shares are never broadcast as blocks; the test does not calibrate a
production prospect target or claim full-block validity. The trusted-context
RPC adapter and block-winning broadcast ordering have separate integration
coverage.

This gate covers retained phrase export, fresh restoration and wallet-backed
gym signing for the bounded fixture profile. It does not establish hosted
login/custody, universal external-wallet compatibility, exclusive migration,
imported-key export or fighter transfer. Both node and wallet shutdown remain
checked by the shared fixture lifecycle.
