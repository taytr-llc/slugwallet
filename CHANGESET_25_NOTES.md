# Change set 25: four-scope RPC spending at Phase-A activation

The user approved activation at block 62 in the paired SLUG chain. The wallet
keeps its chain identity, existing derivation modes, recovery schema and fixture
limits. This change supplies the wallet-side spending policy and verifies the
node is running the matching activation rules. It does not add real accounts,
custody, private-key output or public wallet RPC.

## Spending behavior

`sendtoaddress`, and `sendfrom`/`sendmany` resolving to account 0, select eligible
inputs from exactly default scopes 44/49/84/86. A larger coin in a custom scope
or another account cannot enter the selection. Account names are still resolved
in scope 44; nonzero named accounts and the imported account stay there. No account
number is treated as permission to spend a same-numbered account in another
scope. All RPC change comes from scope 44 as P2PKH, including mixed legacy,
nested witness, native witness and Taproot inputs.

`SendOutputsWithOptions` reuses the existing validation, signing, durable publish
and error path. Existing `SendOutputs`/`SendOutputsWithInput` signatures and
selection/change defaults remain unchanged. New creation options specify an
owned scope allowlist and a minimum block height; an explicitly empty scope list
selects nothing. Filters apply alongside account, confirmation, coinbase maturity,
locked-output and selected-outpoint checks.

The paired node must report explicit matching `always_active_height` values for
Segwit and Taproot, status consistent with the next block, and a block count/hash
matching a subsequent best-tip read. Missing metadata, an old node, RPC failure
or changing/inconsistent snapshots fail before signing or change creation.
Only pinned Phase-A network/genesis uses this fixed-height interpretation. Other
networks require their node's deployment status; they do not inherit height 62.

Before activation, supported witness inputs are excluded. Native witness,
Taproot and opaque P2SH payment destinations are rejected; the latter may conceal
a witness redeem script. Ordinary preactivation P2PKH sends retain finality
behavior. After activation, every Phase-A RPC spend receives locktime 61 and
sequence 0xfffffffe before signing. Consensus finality therefore forbids inclusion
at 61 and permits 62, even if the chain reorganizes below activation after the RPC
snapshot. This conservative floor also covers named/imported accounts and opaque
P2SH destinations. The sequence disables BIP68 relative locks and does not opt
into RBF. No fee-size change is introduced by these fixed-width fields.

## Validation

- RPC policy tests cover tips 60/61/62, missing upgrade metadata, wrong override,
  inconsistent/early status, tip advance/reorg, chain mismatch, RPC failure,
  actual other-network statuses, exact default/named/imported scope boundaries
  and premature witness/P2SH recipients.
- A real public-fixture wallet authors one signed transaction using all four
  input types, excludes larger custom-scope and other-account coins, produces
  P2PKH change, and passes script verification. Independent consensus finality
  checks reject it at 61 and accept 62. Tests also verify named-account isolation,
  preserved ordinary library finality, owned option slices, an empty allowlist
  and height/timestamp range separation.
- Focused normal policy tests pass in 0.408 s and mixed-scope wallet tests in 2.977 s.
  Focused races pass in 23.385 s for wallet authoring and 1.699 s for RPC policy.
  All six runtime modules pass build, full normal tests and vet; root suite wall
  time 112.300 s (wallet package 110.982 s). These broad checks preceded the paired
  RPC wire-format correction. Recompiling and rerunning focused wallet/RPC
  spending tests against the corrected client passes in 3.223 s/0.335 s.
- The first end-to-end activation attempts exposed inherited node serialization
  and client wire-format mismatches. The new readiness check refused the response
  before authoring a spend. The paired client now detects the documented response
  shape instead of guessing from backend version; its full race suite passes in
  5.174 s. The corrected client is exercised by the successful real-node gate.
- The four-scope normal production-PoW gate passes in 311.05 s (package 311.449 s):
  legacy 77.42 s, nested witness 72.60 s, native witness 89.46 s and Taproot 71.56 s.
  Every case verifies actual RPC signed input type, explicit P2PKH change,
  activation floor, retained phrase export after reopen, file-only fresh restore,
  exact balances/history, same gym identity/authorizations and authority admission,
  and a second confirmed spend requiring recovered change. The native case also
  preserves an actual witness transaction through GBT, Build, Proposal, mined
  submission and canonical observation. No fixture process remains afterward.
  Evidence: set25-wallet-activation-smoke.json/.log beside the checkouts.
- The shared local node executable was replaced by a logging-only build during
  that integration run. The evidence labels the mixed executable hashes; both
  builds contain the same reviewed consensus/RPC behavior. Remote CI will build
  one exact pinned executable for all cases; it has not yet run for set 25.

The separate activation integration uses four isolated normal-PoW fixture runs,
one per funded scope, with no direct-send workaround: wallet RPC sends,
close/reopen, retained export-only fresh restore, exact history/balance and a
second confirmed spend requiring recovered change. The native-witness case also
checks peer synchronization and a witness-bearing GBT candidate through proposal,
normal mining, submission and canonical observation. CI and README pin the paired
chain implementation `11664083bd87d33b7a127d7950cf170561543c3f`.

## Limits

This is the bounded fixture recovery profile, not production custody or broad
backup compatibility. Hosted login/account authority, secure user-facing phrase
reveal, real issuance decisions and fighter transfer remain separate work.
Upgraded nodes are required before mining past the activation boundary; old
software retaining the same network/genesis identity is not sufficient.
