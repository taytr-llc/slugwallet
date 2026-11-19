# Change set 69: bounded Phase A backup restoration

Candidate engineering qualification is complete for the two published Phase A
fixtures. This is disposable, file-only backup verification; it is not a release,
installed-wallet recovery or production-custody claim.

## Behavior

`Loader.BeginPhaseARecovery` starts a separate schema 12 scratch database from an
unchanged version 1 export. `OpenPhaseARecovery` resumes only with the
independently supplied original manifest, including its original imported
cursors. It never adopts mutable current cursors as the expected import identity.
Completed sessions can reopen without restarting their scan. Existing schema 9
APIs and schema 11/profile 2 constructors, namespaces and file formats remain
separate.

The private schema policy preserves coin 0 and mixed 49 (nested external, native
internal), four ordered scopes and eight branches. Each branch stops at 4,096;
lookahead is clipped to 20 and total raw inventory is 32,768. Steps derive at most
128 raw children or scan one bounded normal-work block. Pending state cannot
open as an ordinary wallet. Completion retains schema 12 and recovery version 1.
`CandidateWithdrawals` explicitly requires schema 9, so scratch verification
cannot acquire the installed app's withdrawal authority.

Original imported cursors, monotonic issued cursors and unused lookahead remain
separate. Pending reorgs rebuild the reconstruction ledger while retaining
previously discovered address inventory. The scanner computes normal header
hashes and checks their binding, transaction/Merkle binding and bounded storage
crosslinks against an identity-pinned full node; it is not a separate consensus
implementation.

Completed scanner rows are audited as an immutable reconstruction checkpoint,
separately from later live-wallet balances, spends, reorgs and address issuance.
Canonical retained outputs establish a minimum discovered issuance/coverage,
which must not exceed the current manager's issued cursor; orphan discoveries
may legitimately leave a longer contiguous prefix. Current derived cursors bound
that prefix above. Without an additional immutable completion-highwater record,
coherent truncation solely above the reconstructible floor cannot be proven. No
exact historical-inventory completeness claim is made from this structural audit.

## Ownership and cleanup

Schema 12 Begin/Open, session Close and the same Loader's ordinary ready-wallet
transition retain the first failed database close as an opaque
`PhaseARecoveryCleanupError`. Its Close reports the original sticky failure; it
never retries and interprets a later nil as successful cleanup. The loader and
failed database owner remain reserved, and callers must preserve scratch storage.
Successful close joins owned work and releases the loader. Schema 11 behavior is
unchanged. Failed ordinary-open publication also closes any acquired schema 12
manager, including an outer transaction-commit failure; the test asserts refusal
and safe reopen, while explicit manager key cleanup is established by source
review rather than direct memory instrumentation.

The UI cancel/logout/reset path still joins and removes only safely closed owned
scratch. Library close/reopen is resumable; app-restart recovery of a cancelled
UI task is not claimed. No background mining, wallet replacement, profile 2
issuance, hosted-vault checkpoint update, or withdrawal-journal/reservation
restore is introduced.

## Independent inputs and scope

Frozen Python address/progress references are under
`wallet/testdata/phase-a-recovery/`; they were generated and reproduced before
this implementation, including reproduction with two Python versions and from
the installed portable bundle. Expected values are not copied from new Go output.

- Address corpus SHA256:
  `1558bf4a134ab01acfe84fdbb2edc3e8af842b602cb5150feaa9ce2df26b9cf7`.
- Progress corpus SHA256:
  `fb0c9a5b1d59711ecb6d855534358f09175df5eb547c1bf88d0474b4b3515801`.

The old-source export intake used a binary compiled before these changes and
copies of the two published post-withdrawal wallets. Their live exported native
84 receive/change cursors are 1/1 at height 110. Actual acceptance used those
retained exports and original wallet state; it did not derive the expected state
from the new scanner.

Tests cover all 32,768 real manager derivations in 256 chunks against frozen
progress, genuine public derivation at mixed-49 boundaries, coherent forged
invalid-child refusal, exact original-manifest resume, pending/ready corruption,
canonical output lower bounds, retained orphan tails and later address issuance.
They also cover real process kills at initialization, an uncommitted derivation
and readiness; blocked-step cancellation and joined close; sticky database-close
failures; and 256 watch batches of 128 addresses with pre-I/O overflow refusal.
The scanner's normal-block behavior is additionally exercised by the paired
actual file-only restores.

## Final verification

Artifacts are retained under the workspace's `artifacts/set69/`. Required-profile
checks use `slug-go1274-no-cse-v1`, Go 1.27.4, and
`all=-d=ssa/generic_cse/off,ssa/lowered_cse/off`. Test/build commands use the
candidate wrapper; vet records the same flags and exact validated compiler,
linker and profile hashes. Every final run binds actual local compiled inputs,
reference files and contracts and reports them unchanged.

- `wallet-full-attempt3/result.json`: all six runtime modules passed normal
  tests. Root-module wall time was 345.328 s (wallet package 292.948 s; manager
  package 25.682 s). The five nested modules took 1.951, 0.236, 0.716, 1.917 and
  3.732 s. Explicit cheap-profile refusal passed in 5.130 s. All 1,041 bound
  inputs were unchanged.
- `wallet-build-vet-attempt2/result.json`: all six runtime modules built and
  passed vet; the same 1,041 bound inputs were unchanged.
- `wallet-final-race-attempt1/report.json`: all `TestPhaseA` and
  `TestRecoveryWatch` cases passed under the race detector in 359.849 s (manager
  package 66.279 s; wallet package 290.074 s), with 993 bound inputs unchanged.
  This includes the full capacity, real crash, cancellation and cleanup matrix.
- `wallet-monotonic-attempt1/report.json`: the final canonical/orphan audit
  regression passed normal tests in 10.326 s and race tests in 47.871 s before
  the full runs; 993 inputs were unchanged.
- `wallet-future-version-attempt1/report.json`: the inherited unknown-version
  test passed in 2.116 s after the test-only correction described below.
- Paired `actual-backup-attempt1` passed in 53.377 s. Both old-source
  post-withdrawal fixture exports completed fresh bounded restores and ready
  reopens against the retained owned normal chain. Original inputs remained
  unchanged; no new transaction was submitted.
- Paired desktop qualification passed all six desktop packages in 207.119 s,
  built package 0.5.8/build 69 in 15.637 s, and passed the exact packaged helper
  in 121.448 s for both fixture identities, descriptor versions 1/2 and initial
  and reopened backup flows. These are separate source-bound paired reports.

The final full/build-vet binding is
`fddbb4aa9d825193965d3029f0b0314c119bc23e5b3e16333379901949520b19`.
The final race binding is
`3cb266b5c585d7e2d4e033e230f47d7a6a8a1a7880a45be201c6b3736573d7a2`.
Different inventories reflect the explicitly recorded package scopes.

## Preserved failures and diagnostic runs

Earlier plain-Go runs (`wallet-attempt1`, `wallet-attempt2`, and
`wallet-final-delta-attempt1`) did not use the required no-CSE candidate wrapper.
Their original reports remain unchanged, with `profile-assessment.json` sidecars
classifying them as diagnostics only. Their successful timings are not counted
as candidate qualification; the final wrapper-based full and race runs above
supersede them. Authoring compile failures are also retained in
`wallet-compile-diagnostics.md`.

`wallet-full-attempt1` failed because the sandbox denied an inherited loopback
HTTP listener. The interrupted subprocess was joined and absence of owned test
children was confirmed before an authorized retry. Its log and diagnosis remain.
`wallet-full-attempt2` completed with one inherited test failure: its supposed
future manager version was `ResumableManagerVersion + 1`, now the supported
schema 12. Only that fixture input changed to `PhaseAManagerVersion + 1` (13);
the expected `ErrUpgrade` and all assertions remain unchanged. Exact before/after
bytes and the one-line diff are in `test-fixture-closeout/`. This test-only change
after packaging altered no production/package bytes. Fresh full attempt 3 and
build/vet attempt 2 qualify the corrected test source. All failed attempts remain
available and are not counted as passes.
