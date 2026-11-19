# Set 69 — bounded restoration of current Phase-A backups

Final proposal for root freeze, November 19, 2026. Reviewed engineering choices;
NOT yet frozen, implemented, or used to produce expected outputs. This proposal
follows the approved recovery design and existing fixture authority. It makes
no new spec decision.

## Concrete result and boundary

Replace the Pool Pilot verifier's synchronous address reconstruction with an
explicit bounded recovery session for its existing version-1 Phase-A recovery
file. Keep the existing file format, 24-word/empty-passphrase contract, chain,
coin-0 paths, root and gym identity, account enrollment, recipient and UI route.
The original live wallet is never migrated, replaced, repinned, or repaired from
this operation. Schema 11 and all profile-2 APIs/fixtures retain their behavior.

The live schema-9 `ExportRecovery` already reads all eight issued cursors from
one committed wallet database snapshot. Set68's change allocation and unsigned
reservation commit together. Consumed change therefore belongs in a later export,
including change consumed by an abandoned or dust-change draft. This set does
not fix an imagined immutable live export. It makes restoration of that actual
current export bounded and restartable at the library boundary.

The hosted fixture vault remains a separate immutable initial snapshot. Updating
its manifest in place would affect both purpose-separated envelope bindings.
No vault overwrite, custody authority, provider integration or arbitrary stale
backup guarantee is included here.

A recovery file contains seed/profile/address metadata, not Set68's signed app
journal, unsigned reservations, dispatch history or permanent exclusions. A
successful verification does not establish complete payment-authority recovery.
The verifier never installs the scratch wallet or recreates an installed
withdrawal namespace. Pending sessions cannot sign or open as ordinary wallets.
A completed scratch wallet may be opened only by the existing verification
integration for its public comparison and gym proof; no new product send or
installation route is added. Candidate withdrawal Create/Open must explicitly
refuse schema 12 rather than accidentally treating profile version 1 as schema 9.

## Proposed public wallet API

```go
func (l *Loader) BeginPhaseARecovery(
    ctx context.Context, publicPass, privatePass []byte,
    bundle recovery.Export,
) (*RecoverySession, error)

func (l *Loader) OpenPhaseARecovery(
    ctx context.Context, publicPass []byte,
    expected recovery.Manifest,
) (*RecoverySession, error)
```

Both use the existing `RecoverySession.Status`, `Step(ctx, source)` and `Close`
shape, with an immutable private profile selector established only by a validated
schema-12 loader/manager. There is no caller-selected profile flag, schema setter,
arbitrary source identity, path list or cursor override. Existing
`BeginCandidateRecovery`/`OpenCandidateRecovery` retain exact profile-2 semantics.
Existing v1 `RestoreRecoveryWallet` remains available and unchanged.

Begin validates the complete v1 export, all four ordered account descriptions,
the selected published fixture identity, chain and work plan before creating a
directory/database. Only the two public fixtures are enabled. It owns bounded
copies of passphrases/manifest fields and clears temporary seed/key material.
Caller-owned exports still require caller cleanup. Begin requires an absent
owned wallet database and either an absent directory or a precreated empty owned
directory. It refuses a nonempty partial directory; Begin never means resume. Its initial pending state commits atomically; cancellation
or I/O failure may leave a new owned partial directory. A subsequent Begin never
overwrites it. Open may resume only a complete audited pending state under the
same expected manifest; an incomplete first transaction is not repairable by
inspection. The caller may remove only its own closed disposable scratch and
start a new verification. There is no automatic fallback to a different profile
or to the old synchronous loader after refusal.

Open takes an independently retained expected PUBLIC manifest. It owns and
validates it before filesystem work, then requires canonical equality with the
ORIGINAL imported manifest stored by Begin. Imported cursors remain part of this
identity after discovery advances issued cursors. Do not compare the expected
manifest with the mutable issued-cursor overlay or derive expected trust from
inspection of the pending database. Open needs no mnemonic/private decryption. An already-complete same session may
reopen to report Ready; it never resets its progress. Wrong identity, missing
progress, foreign schema or corrupt state refuses without repair or creation.

## Explicit storage and compatibility

Use new manager schema 12, retaining recovery payload version 1 and the exact
unchanged v1 public/private payload grammar. Keep schema 12 after completion;
never downgrade it to 9 or convert it to 11. Old binaries reject the unsupported
manager version. Current ordinary manager/wallet Open rejects pending schema 12
before private access/startup, and accepts completed schema 12 only after the
manager progress and scanner completion cross-audit succeed. No migrations of
existing schemas 8/9/10/11 occur.

The manager's validated schema selects a private policy describing: recovery
version, exact ordered scopes, branch scripts, cursor ceiling, namespace, retained
fixture identity and bounded KDF policy. It cannot be selected by a scanner row
or a caller flag. Profile 1 uses coin 0 and four account-0 scopes 44/49/84/86.
Scope 49 is nested witness externally and native witness internally; neither
branch may inherit profile-2 scope assumptions. All root/gym and account keys
must match the original v1 file and independently published fixture tuple.

Use distinct schema-12 progress/invalid-child/scanner namespaces:
`slug-phase-a-progress-v1`, `slug-phase-a-invalid-children-v1`, and
`slug-phase-a-scanner-v1`. Keep schema-11 namespace bytes unchanged. Reuse the
scanner algorithm and codecs through private policy dispatch; do not duplicate
the entire scanner or broaden the old CandidateRecoveryPlan parser.

Manager progress retains the existing fixed 236-byte layout: LE32
version/ready/address-count followed by eight ordered records of seven LE32
values (purpose, coin, branch, imported-next, issued-next, derived-next,
target-next). The schema-12 namespace and manager version select the exact
coin-0 validation policy. Scanner metadata retains the existing ordered bounded
JSON fields: version, phase, height, hash, time, target_height, target_hash,
transactions, outputs, transaction_bytes. Script/transaction/output keys retain
the established deterministic codecs, under the separate scanner namespace.
These names and codec rules are the reviewed contract for schema 12.

The retained original recovery manifest is immutable. Progress, script rows,
issued cursor changes, discovered ledger effects and scan checkpoint update
atomically in the same wallet database transaction. Reopen checks the complete
bounded crosslinks, key/row grammar, exact scopes, invalid-child proofs, cached
counts/balances and scanner/manager phase agreement. Missing or conflicting
established rows are corruption, never a request to regenerate a new session.
An uncertain commit poisons the handle; reopening the same expected session is
the only recovery path. Do not claim protection against coherent owner-controlled
rollback of the entire filesystem.

## Work, discovery and resource bounds

The v1 issued/imported cursor ceiling remains 4,096 per branch. Raw indices are
0 through 4,095. For each of eight branches, initial target is
`min(imported_next + 20, 4096)`. Imported, issued, derived and target are separate
facts. Lookahead is unissued; watches, scans and resumption cannot allocate it.
Do not derive inaccessible rows beyond 4,095 or widen v1's format ceiling to the
65,536-attempt profile-2 runtime budget.

One successful Step derives at most 128 raw child attempts OR processes at most
one bounded normal-PoW block. A successful derivation step greedily fills the
128-attempt quota or finishes the current target inventory, in fixed order:
scopes 44/49/84/86, branch 0 then branch 1 within each scope. It may cross branch
boundaries within one step. Invalid children consume raw attempts in that same
order. This preserves the existing DeriveRecoveryChunk packing behavior.
Invalid children count toward the 128 attempts and the total; each persisted skip must be independently provable from the exact
public branch key/index. The eight-branch raw inventory is at most 32,768. At a
4,096 cursor, lookahead is clipped to zero, not silently reserved beyond the
profile limit. Profile-aware ready allocation rules preserve the same v1 bound;
`resumableRecovery=true` must not grant profile-2 allocation policy.

Discovery of a used lookahead address advances issued-next monotonically to
index+1, extends the clipped target in subsequent chunks, and rescans earlier
blocks so an older payment to newly covered addresses is not missed. Reorg
repair retains address facts while rebuilding private transaction effects from
genesis. A gap larger than the finite lookahead may remain undiscovered; this
is not recovery of all history from an arbitrarily stale file. No cursor is
lowered to make a comparison pass. Backup verification compares the restored
state to the unchanged live wallet; a stale or insufficient file cannot claim
success by omitting live issued addresses, UTXOs or transactions.

Retain established scanner limits: 16,384 relevant transactions, 16,384 historical
owned outputs, and 32 MiB total serialized relevant transactions. Enforce block,
wire count/row-size limits before allocation and quota before commit. Watch
registration uses at most 128 addresses per call, at most 16,384 watched outputs
and an 8 MiB complete rescan request bound. Capacity is explicit; no quota
increase, unlimited fallback or partial verified result.

Begin/Open also perform fixed key setup and bounded audits; the 128-attempt
statement applies to Step's child derivation, not all loader or audit work.
Preflight stored master/cipher/sync sizes and KDF parameters before expensive
allocation/derivation. Apply the existing schema-11 KDF ceiling to schema 12:
scrypt N power-of-two greater than 1 and at most 2^18, r 1..8, p=1. This includes
creation and future password changes, without changing old schemas' behavior.
A running KDF or one Argon2id header hash is not forcibly preempted; cancellation
joins it and checks cancellation before publishing effects. No claim of a
128-address bound on all heap usage or constant-memory live startup is made.

## Source, completion and cancellation

Reuse the read-only `RecoveryRPCSource` identity/framing behavior, pinned to the
original child-owned literal-loopback node, exact network/genesis and Phase-A
activation 62. Never accept an endpoint or chain identity from the selected
backup. The source rechecks identity on every transport, bounds reads to the existing
30-second limit, and closes the exact socket on cancellation. The recovery
session verifies normal header PoW and Merkle/witness binding before committing
source observations. No mining, transaction broadcast, provider
request, private signing or new account enrollment is part of scanning.

The final step checks the canonical exact tip again, and commits scanner
completion, manager readiness and the correct verified genesis birthday/sync
state together. It never reports ready from height equality alone. Close the
recovery session before ordinary scratch-wallet Open. Disable a second inherited
recovery-window algorithm for this completed audited wallet; bounded ready
watching still runs, and Attach must reach actual ChainSynced even at genesis.
The original and restored views must remain at the same exact tip hash/height
through the final resampled comparison. Current walletVerificationState and
waitPoolBackupWallet expose height plus Synced only. The integration therefore
needs a private owned sample of Manager.SyncedTo hash and height under the
retained wallet lifetime lock; height equality alone cannot fulfill this rule.
Do not expand public wire DTOs merely to obtain that private comparison.

Session work is serialized, context/lifetime-bound, and joined. No account
lease spans loader KDF, database acquisition, address derivation, header hashing,
source I/O, watch setup, signing proof or cleanup. Original-view rechecks govern
entry, status publication and final verified disclosure. Reset/logout/Close
cancel and join every admitted operation before the wallet/source owner is
released. Keep existing D72 semantics: export requires original RecoveryExport;
verification is allowed under original View during the hold, with no delivery
or new recovery authority.

Library Close leaves durable pending progress for an explicit Open with the
same expected manifest; process termination may also be resumed after audit.
Do not adopt a new session if the expected one is unavailable. There is no
background task that resumes or completes a wallet after the owning context
has ended.

## Failed construction and cleanup ownership

Add a Phase-A-only typed error with an opaque retained owner:

```go
type PhaseARecoveryCleanupError struct { /* private fields only */ }
func (*PhaseARecoveryCleanupError) Error() string
func (*PhaseARecoveryCleanupError) Unwrap() error
func (*PhaseARecoveryCleanupError) Close() error
```

If Begin/Open acquired a database and then initialization, audit or cancellation
fails, the loader synchronously attempts manager/database cleanup exactly once.
If cleanup succeeds, return the original ordinary error and release the loader.
If cleanup fails, return this typed error, preserving both the initiating cause
and first cleanup failure for errors.Is/As. Keep the opaque failed owner and the
originating Loader's reservation (`db` plus recovery/failed-owner state). The
same Loader cannot create, open, unload into reuse, or publish another session.
The error and Loader retain the owner; no private keys, database handle or repair
capability are exposed through public fields.

The typed Close joins the already-attempted cleanup and returns its sticky first
cleanup error. It does not retry the backend and never returns nil after that
failure. There is no automatic retry loop, task or cleanup goroutine. This rule
is necessary because the current bbolt backend sets `opened=false` before
munmap/unlock/file close; after a first failure, a second Close can immediately
return nil without resolving that first uncertainty. It is not proof of closure.
A failure before any database is acquired remains an ordinary error.

Schema-12 RecoverySession.Close also cancels and joins admitted work, closes its
manager and database exactly once, and retains the first error. It releases the
Loader reservation only when cleanup succeeds. Do not change the existing
schema-11 API/Close behavior as part of this set. Tests inject the first close
failure and a hypothetical second-call nil to prove it cannot clear the error,
release ownership, enable another session or permit scratch removal.

The desktop helper owns one explicit lifecycle object across the session,
read-only source, completed ordinary runtime and any failed-construction cleanup
owner. It retains and joins each admitted component outside account leases.
Before ordinary ready-wallet Open, the session must have closed successfully.
Before RemoveAll, all owned closes must have completed successfully. Any typed
cleanup failure or session/runtime/source close error is sticky `backup_storage_failed`;
preserve the scratch directory and retained cleanup owner instead of removing
it, retrying into success, or reporting verified. An ordinary failed Begin whose
cleanup succeeded may remove only its own disposable scratch. This is a cleanup
safety rule, not automatic recovery of uncertain storage or a new install route.

## Existing Pool verifier integration and cleanup

Preserve the current private/native selection protocol, owner-only pinned file
read and one bounded backup work slot. Read at most the existing 64 KiB v1 file
limit, validate the original account identity and recipient, clear file/phrase
scratch as today. Backup work still drains mining/withdrawals and other child
work outside account leases before borrowing the wallet/source.

The existing 10-minute verification operation runs Begin + repeated bounded
Steps, using its original operation context and publishing only existing bounded
backup phase/status fields. A completed session closes before ordinary scratch
wallet attachment, key proof and the unchanged full public comparison. No new
navigation, profile picker, browser key/phrase payload or claim of app-level
recovery installation is added. Wire/schema expansion for numeric progress is
not necessary for this minimum set; it requires separate review if later wanted.

Current UI cancellation semantics stay intact: Cancel, reset, logout and Close
join the session/wallet, then remove the owned verification scratch directory.
Application restart does NOT automatically resume that discarded scratch. This
set qualifies explicit library crash/Close/Open resumption; it does not claim
app-restart resume without a separately pinned retained-scratch/file identity
protocol. Cleanup failure stays visible and preserves the directory if Close
fails; never remove a live database or report verified after cleanup failure.

The current unchanged-tip/full-state comparison, original re-sampling, actual
sync requirement and refusal while any observation has unconfirmed history remain
intact. Do not drop pending activity to make restored state match. Selected-file
verification concerns the snapshot that was exported; later wallet changes may
make a previously valid file stale and require a new export.

## Qualification before completion

1. Freeze reviewed contracts and exact input inventory before new independent
   expected vectors. Reuse existing v1 address/identity references where exact;
   independently derive additional mixed-49 branch-0/branch-1 and 4,095-edge
   cases. Do not reuse v2 address scripts or derive goldens from implementation.
2. Prove old v1 bytes/APIs and schema-11/profile-2 references remain unchanged;
   wrong profile, extra account, cursor overflow and foreign expected-manifest
   resume refuse before mutation. Pending schema 12 ordinary Open/unlock/sign
   refuses; completed schema 12 cannot enter Set68 CandidateWithdrawals.
3. Test 128-raw-attempt steps, clipped 20-address lookahead, invalid-child proof,
   current issued metadata, historical expansion/replay, reorgs, quota, audit
   corruption and exact final tip. Exercise bounded source refusal/cancellation,
   poison/uncertain commit, Close joins and subprocess kill/resume with expected
   imported manifest. Separately qualify loader KDF/row preflight and maximum
   32,768-address ready watches; no unsupported total-RAM claim.
4. On isolated copies of Set68's real post-withdrawal fixture state, export using
   the existing actual wallet. Freeze public metadata and source/chain inventory
   before new verifier execution. Both files must contain the consumed native84
   internal cursor and recover the exact canonical change, reciprocal payment,
   balances/history and same gym proof from file only. No original user data,
   new mining, new withdrawal, new authority, or golden creation from the new
   scanner is needed. Keep encrypted/private fixture file bytes out of public
   responses/logs; only public metadata, checksums and comparison evidence.
5. Integrate under the original view and exercise D72 hold, cancellation/reset,
   stale selected file, profile mismatch, cleanup failure, exact native descriptor
   handoff and ordinary complete package route. The completed scratch wallet is
   destroyed, never installed. Run appropriate normal/race/profile, affected
   full modules, exact package and required per-set smoke. Preserve failures.

## Proposed ownership / files

Wallet: new `wallet/phase_a_recovery_loader.go` and
`waddrmgr/phase_a_recovery.go`, plus the narrow private profile dispatch in
manager/version gates, recovery progress/invalid/state parsing, scanner scope
lookup, completion/birthday, ordinary ready Open/watch and allocation policy.
Add the explicit schema-9 guard to candidate withdrawals. Do not duplicate the
whole scanner or alter profile-2 public constructors.

Desktop: a narrow wallet runtime helper for the bounded session and edits to
`pilot/pool_backup.go` to use it, retaining private file/native contracts and
existing final comparison/cleanup. Supporting tests are distinct from current
legacy restore and Set68 payment tests. Root documentation/packaging remains
separate from wallet/scanner implementation ownership.

All engineering choices above have been reviewed. Root freeze and the separate
locked input/independent-vector inventory precede implementation. Actual runner
budgets and source bindings are recorded in the qualification plan before any
execution. There are no remaining user-facing policy choices for this set.
