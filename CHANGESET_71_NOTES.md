# Change set 71 — current hosted-fixture recovery

Status: implementation and qualification complete on the stacked
`slug-hosted-current-recovery` topic branch. The paired frozen contract,
independent references, focused checks, all six full wallet modules, actual
hosted recovery, normal packaged helper and required chain smoke passed.

The paired chain `HOSTED_CURRENT_RECOVERY.md` defines a separate hosted-fixture
vault and a concrete public schema-9 wallet capture. Current cursor checkpoints
remain separate from the original immutable vault envelopes and receipts.
Authorized current export combines retained recovery material with the captured
inventory, preserving the existing version-1 file and root/gym identity.

Use only the two published fixture wallets and published wrapper keys. Keep the
old vault APIs, installed wallet schemas and recovery formats unchanged. New
public capture must not fetch private retention or decrypt/copy account private
ciphertext; its bounded account-row parser skips the embedded encrypted span.
An opaque capture is tied to the actual retained wallet owner.

The new guarded vault acquires its operation permit before original-session
fences, and never falls back to local signing when the vault refuses. D72's hold
permits public viewing and gym signing while blocking recovery export and
withdrawals. Recovery bytes stay private until the bounded authorized file
publication. No real signup, provider/KMS deployment, production issuance,
continuous disaster-recovery or restored payment-journal authority is implied.

Contract SHA256:
`92b247a5c3f47e637ed0dbf09d08c8f580a881cc80ff114a4c22d2e119572a86`.
Independent producer sources and all 75 public inputs were locked before expected
outputs and implementation. Python 3.14.3 and 3.9.6 produced identical outputs.
Portable source/input reproduction lives in the paired chain checkout's
`testdata/hosted-current-recovery/reference`; each wallet consumer retains its
own expected file and SHA256.

The new public capture and affected own-activity tests passed normal (15.375s),
race (93.740s) and cheap-profile refusal (6.959s), with the exact candidate
compiler/profile and 940 inputs unchanged. The checks include both real public
fixture wallets, all 25 row and 38 inventory reference cases, one committed View,
private-read spies, cancellation, close/unload joins and unsupported schemas.
An earlier compile-only unused-import failure was corrected and preserved.

Vault focused attempt1 found a test-installation issue with duplicate serialized
LevelDB keys: Batch.Put collapses the duplicate before the store can inspect it.
The independent negative remains unchanged; its consumer rejects duplicate
fixture framing before installation. Attempt2 passed normal/race/cheap/vet and
affected legacy vault regressions. Final attempt4 passed normal (12.86s), race
(45.82s), cheap refusal (2.02s) and vet (0.34s), with 3610 inputs unchanged.
It includes bounded original-capture replay after later commits, changed-intent
refusal and historical-capture rejection for new export. Retained public
manifests use a separate 528,384-byte bound inside the 16-MiB work budget; this
implementation accounting did not rewrite the frozen corpus. The intermediate
attempt3 compile error is preserved. See `../artifacts/set71/vault-closeout.json`.
The joint D74 review remains a later release gate.

All six wallet modules also built and passed candidate-profile vet with 1102
inputs unchanged. Paired desktop focused normal/race/vet and all seven complete
desktop package suites passed; the normal macOS build71 bundle passed build and
strict ad hoc code-sign verification. The funded hosted recovery rehearsal passed
in 317.062s with 4281 unchanged source inputs. Both accounts exported exact
current 1/1 cursors after real change allocation and passed the production
schema12 verifier. A separate file-only restore recovered and spent the exact
change coin with the installed database unavailable and byte-identical.
Reset/hold, old-session/view denial, same-wallet restart, retained withdrawals
and missing-store refusal passed; the owned process group was empty with no
forced kill. The exact packaged helper also passed in 176.307s for both naming
versions and both accounts, including current exports, production file
verification, reset holds, exact restart and missing-store refusals. Its narrow
legacy Pool regression passed, and all eight process groups exited cleanly.
All six wallet modules passed their full normal suites in 377.462s total, plus
the existing cheap-profile refusal checks in 1.197s, with 1102 inputs unchanged.
The required paired smoke passed isolated mining, read-only seed sync,
report-only checkpoint finality, verification and clean restart/shutdown,
without public-chain mining. All 1770 compiled node/checkpoint/profile inputs
remain unchanged, so no live seed rollout is needed. Reports and preserved
attempts are in `../artifacts/set71`.
