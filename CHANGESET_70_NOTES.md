# Change set 70 — bounded public wallet activity

Status: candidate qualification complete for both published Phase-A fixtures,
including all six wallet modules, actual funded-wallet capture and the exact
paired macOS package. This is not production custody or release approval.

## Behavior

`Wallet.CaptureOwnActivity` performs one bounded read transaction over the
schema-9 Phase-A wallet. `waddrmgr.ReadOwnActivityState` reads public retained
identity and the persisted sync stamp without loading private recovery fields,
unlocking, or allocating an address. `wtxmgr` selects recent confirmed and
unmined records from bounded index windows, validates storage crosslinks and
copies raw transactions plus owned-credit/debit integer facts.

The reader caps selection at 256 distinct records with an older-record witness,
raw transactions at 256 KiB each/8 MiB aggregate, and index traversal at the
frozen limits. It checks canonical transaction framing, bounded input/output/
witness data, duplicate inputs and checked monetary totals before decoding.
Amounts never pass through a floating history RPC. Metadata, transaction and
sync reads share the same database snapshot.

Reservations, unmined-input conflict bookkeeping and current spendability do
not redefine historical owned inputs. The paired desktop computes received,
spent, change, net amount and known fees, preserves immutable pages/details,
and checks exact node/wallet hash and height before and after capture. Its
original-view/source/root/gym fences and joined cancellation own disclosure and
lifetime; the low-level storage read is not account authentication.

No wallet mutation, schema migration, RPC allowlist extension, send permission,
key export, private-field read, new custody policy or production issuance is
introduced. Existing history/RPC APIs remain unchanged.

## Independent reference

The paired `WALLET_ACTIVITY.md` contract and 18 public historical inputs were
frozen before implementation. Reviewed Python producer sources were frozen
before deriving outputs. `wallet/testdata/own-activity` contains the portable
producer, locks, public inputs and corpus, with reproduction instructions.
Python 3.9 and portable repository-only reproduction match exactly.

Core corpus SHA256:
`4b3880f7facb9286502aa6a3bdcf38db7821a96e1d1b622f4d27a898a057598e`.
It contains 44 positive, 18 negative, 18 raw-framing, 27 storage and four
budget cases. Three fixture-parser negatives lose their JSON/hex distinctions
after conversion to typed binary data; the semantic Go adapter applies the
other 15. No implementation output was copied as expected data.

## Qualification

Artifacts are in `../artifacts/set70`, using the exact Go 1.27.4 candidate
no-CSE profile. All focused runs bind their sources and report them unchanged.

- `wallet-focused-attempt3`: normal manager/wallet 4.059 seconds, storage 1.765.
- `wallet-race-attempt1`: manager/wallet 26.321 seconds, storage 5.559.
- `wallet-cheap-attempt1`: manager/wallet 6.409 seconds, storage 2.437.
- `wallet-build-vet-attempt1`: all six runtime modules build and pass vet;
  1,076 inputs unchanged. The focused runs bind 992 inputs.
- `wallet-full-attempt1`: all six modules pass normal tests. Root 352.269 seconds;
  txauthor 1.787, txrules 0.233, txsizes 0.660, walletdb 1.630 and wtxmgr 4.609.
  Explicit tagged recovery/withdrawal refusal checks pass in 1.304 seconds.
  The same 1,076-input binding remains unchanged; runner and child processes exit.
- Paired `actual-activity-attempt1`: concrete normal-PoW node/wallet capture
  passes in 11.233 seconds. Both copied funded fixtures yield the three exact
  retained transactions at tip 110. Raw bytes, credit/debit data, integer amounts
  and output details match independent evidence. Repeated capture and complete
  semantic state remain equal; source wallets stay byte-identical and processes
  close cleanly. No new mining, payment, export or address allocation occurs.

The original recipient first-seen time for an incoming transaction is absent
from old reference data. Its current stored time is labeled as a bounded actual
observation; no independent timestamp prediction is claimed.

Initial collector/compile attempts and a successful profile check serialized
incorrectly as null are preserved. They are not counted as passes; fresh
successors establish the results above.

Paired final evidence: all six desktop normal packages pass in 197.915 seconds;
final controller race/cheap/candidate-flag vet pass in 12.312/2.709/1.021 seconds;
final native normal/race pass in 3.405/5.616 seconds. The earlier controller run
used the frozen wrapper but lacked recorded compiler hashes, and its plain vet
is diagnostic only. The final bound successor supplies those missing provenance
checks. Final native tests cover the cancellation/reservation source correction.
The macOS 0.5.9/build70 package builds in 17.816 seconds with paired sources
unchanged. The exact packaged helper passes in 127.719 seconds across both
name versions and fixture identities, initially and after reopen. Activity
capture, completed same-ID replay, explicit refresh, old-account refusal and
existing recovery/payment/league boundaries pass with clean process closure.
Native file selection uses held descriptors, not visible dialogs.
