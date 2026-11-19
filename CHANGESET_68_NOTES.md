# Set 68 — reviewed candidate withdrawals, wallet foundation

The additive candidate withdrawal seam prepares and persists an exact unsigned
transaction before any signature is produced. It is restricted to the existing
schema 9 recovery profile and the published zero256/incrementing256 fixture
identities. No manager migration, production profile, generic RPC, payment
publication, or new key authority is introduced.

`CreateCandidateWithdrawals` and `OpenCandidateWithdrawals` establish one exclusive
handle for an independently pinned app binding. `Prepare` atomically commits the
unsigned draft, consumed native84 internal change address, and prepared input
reservations in the same wallet database. Retrying the original operation returns
its original draft without advancing change again. `Sign` accepts only that saved
operation and digest, resamples the owned current inputs, and returns scratch
signatures over the exact unsigned bytes. It does not store signatures, add an
unmined wallet transaction, or send anything to a node.

The paired app journal remains the sole durable signed authorization. Its concrete
adapter must hold the exact reconciliation authority when calling privileged
`Retain` or `Abandon`. Retain permanently excludes the signed inputs; no depth or
clock releases them. A crash before retention leaves the prepared reservation
blocking new selection. Known unsigned abandon releases only that prepared
reservation and never rewinds the consumed change cursor. Abandoned records still
count against the 128-operation limit. Open does not initialize missing state;
`Empty` and `OperationIDs` provide audited setup and converse-journal checks.

Candidate selection visits at most 4096 mined-unspent rows, including skipped
rows, and selects at most 16 owned native84 inputs. Previous transaction parsing
is streamed before decoding any claimant-sized object arrays, with a 4 MiB
individual and 16 MiB aggregate bound. It copies only the selected native script.
Selection uses amount descending, displayed txid bytes, and numeric output index;
final transaction order is BIP69. The fixed candidate fee rate is 1000 atoms/kB,
with a 100000-atom total-fee ceiling. Ordinary selection and explicit PSBT/raw
signing also refuse prepared/retained inputs. These exclusions do not make old
binaries or exported wallet copies aware of the new namespace.

The handle rejects concurrent work, cancels and joins before wallet unload, and
suppresses stale/cancelled signing results. Wallet stop before commit rolls back;
a possible committed write followed by a stop/error reports uncertainty and
poisons that handle until reopen. Database/OS locks are not magically interrupted
by context cancellation: operations check after acquiring them and must be joined.
The app must register the exact saved change address on its existing wallet
notification connection outside account/DB leases before scratch signing.

## Verification

The frozen independent reference has 24 positive draft/signature cases, 13 negative
drafts, and 5 negative signed transactions. Its producer and original public
inputs are retained under `wallet/testdata/candidate-withdrawals/`; expected values
were not obtained from the implementation. Pure byte/digest/signature checks pass.
Eight concrete disposable wallet cases cover both published fixtures and all four
recipient types, matching exact independent unsigned and signed bytes. The
original retained public payout is inserted into the real wallet transaction store
for this authoring test; this does not claim a new node-validated spend.

Source-bound evidence is under the workspace `artifacts/set68/`:

- `wallet-attempt3`: normal focused suite passed in 44.220 seconds, 868 bound files
  unchanged. Includes atomic rollback/uncertainty/reopen, cancellation/join, 128
  operations, 16-of-17 selection, exact reservations, current-ledger checks, and
  count/byte/parser limits.
- `wallet-race-attempt1`: full focused race suite passed in 349.539 seconds, same
  868 inputs unchanged.
- `wallet-delta-attempt1`: final signing/lifetime/inventory changes and existing
  PSBT/dry-run/custom-change regressions passed in 16.732 seconds, 870 inputs
  unchanged.
- `wallet-delta-race-attempt1`: five affected signing/lifetime/inventory cases
  passed in 92.747 seconds, 872 inputs unchanged.
- `wallet-build-vet-attempt1`: all six runtime modules built and passed vet;
  955 bound files unchanged.
- `wallet-full-attempt1`: all six runtime modules passed full normal tests. The
  root module took 311.108 seconds wall (wallet package 260.413 seconds); txauthor
  1.538, txrules 0.235, txsizes 0.715, walletdb 1.693, and wtxmgr 3.728 seconds.
  Cheap-profile constructor refusal also passed in 2.920 seconds. All 955 bound
  files remained unchanged. Gofmt and diff checks pass.

The initial failed focused attempt remains preserved. Its fixture used the old
`NewTxRecord(raw)` constructor, which hashes full witness serialization for the
record key; the new reader correctly rejected the txid mismatch. The fixture now
uses the existing `NewTxRecordFromMsgTx` constructor with unchanged original bytes.
A later compile-only test import omitted the existing `/v2` suffix; that failure
is also retained. Neither correction weakened production checks or changed an
independent expected value.

The paired chain's `actual-withdrawal-attempt1` passed the real account/journal/
wallet/node composition in 22.976 seconds. Fresh fixture wallets restored the
original pool payout and each sent exactly 1 SLUG to the other fixture. Complete
drafts and signed bytes matched independent cases. A deliberately lost send
acknowledgment required close/reopen and an explicit same-byte retry: two
transmissions produced one debit. Live wallet notifications discovered both
change outputs; one normal-PoW block confirmed the transactions. Reopen retained
exact balances and signed-input exclusions. Each wallet paid 141 atoms once.
Original source data stayed unchanged; all owned processes stopped normally.

The complete six-package desktop suite and required chain smoke also passed.
Exact package qualification is recorded in the paired chain's
`CHANGESET_68_NOTES.md`. Production custody/genesis and the required joint design
review remain outside this wallet foundation.
