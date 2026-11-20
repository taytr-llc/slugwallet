# Changeset 74 — dedicated operator pool wallet

Schema 16 adds a separate encrypted HD wallet for operator settlement. It binds the independently selected wallet owner, operator profile, pool source and settlement configuration to the Phase A standard path `m/84'/0'/0'/0/0` (`slug-phase-a-operator-pool-native84-v1`). The fixed P2WPKH address is its complete inventory. Fresh creation and reopening require the exact guard, account/address indexes, genesis sync index and expected encrypted root relationships. Existing wallet schemas and migration rules remain unchanged; ordinary constructors and generic derivation, import, export, address allocation and spending refuse this purpose.

The owner privately retains its Loader and wallet. It starts locked; unlock is an explicit local operation with a positive lifetime of at most 24 hours. Cancellation and Close join admitted work before releasing keys or storage. Failed database or directory cleanup retains the original handle and a sticky error. Sign does not read a passphrase file or renew unlock authority.

The backend binds once to the original concrete settlement store. Signing requires that store's immediate, exact-request capability, valid only during its synchronous Sign call. Caller coin claims or copied configuration cannot authorize it. The concrete node checks inputs before the short local unlock lease. The original poolsettle store retains all batch, reservation, debit and immutable payee authority; this wallet creates no second accounting journal and performs no broadcast from Sign.

## Focused evidence

The independently generated Python 3.14/3.9 corpus is retained in the paired chain repository at `poolsettle/testdata/operator-wallet/reference-v1.json`, SHA256 `c1f2d725fcdbc3af7ba1b0a30f4dd4dfc6983352ffb0b4f72d83f7c09ac7b087`. Tests cover three fixed identities, nine exact signed transaction vectors through 256 inputs, malformed guard/transaction cases, closed inventory, generic-route refusal and concrete owner/backend lifetimes. The external fee-only refusal is a corpus consistency check because the signing API has no caller fee field.

`pool-wallet-focused-attempt3` passed normal 16.443s, race 117.595s and legacy controls 1.689s, with 5,840 inputs and the candidate compiler/profile unchanged and all process groups joined. These command passes are retained; the aggregate attempt remains failed at cheap-profile testing.

The failures remain separate evidence:

- Attempt1 exposed a test variable redeclaration and preflight's omission of the mandatory genesis index written by the inherited constructor. The corrected validator requires its exact key and hash and rejects missing, malformed, changed or extra height rows.
- Attempt2 exposed a test adapter mismatch: independent corpus outpoints used wire-order `hash_wire`, while the product Coin field expects display-order `txid`. The test now converts explicitly; reference bytes and product signing expectations are unchanged.
- Attempt3's cheap selector incorrectly ran normal-genesis positive vectors in a build with a different genesis. The corrected cheap test retains normal-guard rejection and uses a local, structurally valid cheap-genesis request to exercise the separate execution-profile refusal before any manager state is written. Wallet owner cheap refusal already passed.

`pool-wallet-cheap-vet-attempt1` passed both explicit cheap-profile refusals (3.329s) and vet (1.956s). Its 5,852 inputs and profile stayed unchanged; all process groups joined. The supplemental runner checks the retained normal/race/legacy evidence, unchanged production and executed normal test bodies, and exact cheap-only test delta; it does not repeat or relabel those earlier runs.

## Limits

This is paired operator custody engineering, not a hosted-gym wallet, recovery-v1 export, production issuance decision or D73 genesis/profile finalization. Published synthetic fixtures alone were used. The focused node model checks constructor identity; it does not establish mined funding, scheduled payout execution, TLS ingress, a long-running operator process or remote worker acceptance. Those paired runtime and actual-node gates remain separate. No real operator or official checkpoint private key was accessed.

The paired runtime subsequently passed `public-pool-actual-attempt3` using this
wallet at `40959793` and chain `4a3f20da`: two separate TLS miners, actual normal
PoW, maturity deferral, one scheduled payout, accepted lost-response recovery
after exact wallet/runtime reopen, and no duplicate payment. Both miners received
9.9 SLUG; the 240-atom fee came from the pool's cut. Standalone CLI reopen and
all owned process joins passed. The source-bound record is in the chain repo's
`docs/evidence/set74/operator-actual.json`. All six wallet modules also built
successfully. These isolated public fixtures do not establish real custody or
remote deployment, which remain separate work.
