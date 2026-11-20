# Hosted allocation recovery — Set72 engineering contract

Status: **adopted for implementation, November 19, 2026**. This fixture-only
contract extends chain Set71 `b61907a2` and wallet Set71 `27c8fc20` on
`slug-hosted-allocation-recovery`. The root review closed the concrete manager,
wallet, desktop and missing-wallet mappings. Independent public inputs and
producer sources are frozen before dependent implementation or new expected
outputs. Conservative pre-adoption sizing passed: external row 2127 bytes,
local link 1746 bytes, within their separate 4096-byte caps. This is an engineering
contract under the existing authorization, not product release or D74 approval.

## 1. Deliverable and preserved boundaries

Add one explicit normal-package fixture mode, `--candidate-hosted-recovery`,
with canonical namespace `LocalHostedRecoveryPilot` and public mode
`local-hosted-recovery-pool`. It continuously records every supported issued
receive/change path before usable output escapes. If only an established local
wallet database is later absent, the same signed fixture authority can export
the unchanged version-1 recovery file from surviving vault and issuance records,
then verify that file in disposable schema 12 storage. The existing wallet and
recovery panels consume this mode; final D74 design review remains later.

The new mode requires an explicit absolute data directory. Environment defaults,
the packaged default and a false/omitted mode flag do not satisfy explicit
selection. Any explicitly supplied legacy mode flag, including false, conflicts.
Name version1 is default; version2 requires explicit new-mode/data selection and
retains the exact existing descriptor. Default GUI startup remains ordinary
`--candidate-pool`. Existing Pool, Set71 hosted, manifest, practice, recovery
schema 9/11/12, profile 2, CurrentStore128-action and old API behavior remain exact.
There is no automatic conversion or historical-bootstrap claim for Set71 roots.

D70's 24 words/empty phrase passphrase, D72's signed same-wallet reset, immediate
revocation and 24-hour hold, and D73's separate production profile are unchanged.
Use only the two published fixtures, existing signed fixture driver/wrapper and
Phase-A profile 1/coin 0/mixed 49 identities. No real provider, credentials, keys,
custody promise, fee/finality/transfer rule or new attestation key is introduced.
Real login, provider and MFA implementation remain deferred. Existing signed
fixture checks are test infrastructure and do not claim production ownership.

Coverage means the complete reserved prefix of **supported hosted allocations**,
including unused, burned, no-change and uncertain ranges. It does not discover
arbitrary future addresses independently derived by someone holding the phrase,
xpub or raw database. The co-located fixture authority is not an off-device
backup. Successful restoration does not reconstruct an app payment journal,
signed-but-undelivered transaction, permanent input exclusion or new-device
spending authority. The application never silently installs the scratch wallet.

## 2. Concrete owners and schema 13 enforcement

Put `HostedAllocationInventory`, `HostedAllocationSource` and opaque
plan/reservation/receipt/recovery-head types in **wallet**. Inventory code may
use recovery and concrete gymaccount authority, but never import recoveryvault.
Recoveryvault already imports wallet and consumes its privately minted head.
No public JSON constructor or boolean/callback attestation creates a capability.
Private exact Wallet, Manager, Inventory and attachment pointer equality is
checked where applicable; immutable IDs alone cannot substitute another owner.

An installed wallet in this mode uses explicit manager schema 13 with unchanged
version-1 recovery identity/derivation. Old code rejects13 as a future schema;
an optional ignored bucket in schema 9 is insufficient. Generic open refuses13.
Only the new guarded loader opens it with `recoveryWindow=0` and exact expected
preselected IDs/binding. Fresh creation starts guard-locked with zero cursors;
one exact binding transition enables the attached allocator. Pending/bound
guard bytes and local-consumption-link grammar are specified in §6.

Mandatory low-level checks cover Next/Extend, NewAddress/NewChangeAddress,
CurrentAddress rollover, legacy/gRPC receive/change commands, generic
transaction authoring, FundPsbt/import/dry-run paths, future-path
DeriveFromKeyPath/cache/private derivation, and scope/account/import expansion.
These refuse in schema 13 before mutation or useful disclosure unless entered
through the narrow privileged consume operation. A failed/rolled-back DB
transaction is not sufficient if a derived address could still be returned.
Generic version-1 `ExportRecovery` explicitly refuses13. Old
CandidateWithdrawals.Prepare and CaptureCurrentRecovery remain strict; add typed
attached equivalents rather than globally relaxing their profile checks.

Existing transaction recording and MarkUsed may continue for known supported
addresses after session expiry; they cannot advance issued cursors. Generic
background discovery/Extend is disabled. Zero recovery window still performs
normal active-data collection and rescan. Add an explicit schema 13 bounded
active-address/output reader and watch-registration path rather than pretending
13 is a completed schema 11/12 scanner. Every managed address must be within the
audited local consumed/burned prefix and paired reserved ceiling. A recognized
managed hit beyond it fails typed `allocation_frontier` and leaves synchronization
unavailable; foreign outputs are ordinary foreign outputs. No arbitrary future
path search is implied. Live watch registration is re-established on reopen
before receive disclosure or reviewed signing.

## 3. Fresh setup, names and missing-wallet boundary

The controller preselects one random InventoryID per fixture in addition to the
existing authority/coordinator/vault/wallet-owner IDs. Each is a 32-byte value that is not all zero, encoded as 64 lowercase hex
characters; individual zero bytes are allowed. It first synchronizes a new immutable outer file
`SLUG-HOSTED-ALLOCATION-V1.json`, then the existing hosted INIT. The new guard's
ordered fields are:

```text
application, version, mode, hosted_init, inventories
```

Application is `slug-hosted-allocation-owner`, version1, mode is the new mode.
`hosted_init` is the entire unchanged ordered Set71 HostedInit object, including
its internal `local-hosted-fixture-pool` mode and fixed configs. It is reusable
owned setup metadata, not the new helper's public mode. `inventories` contains
exactly two `fixture, inventory_id` objects in zero256/incrementing256 order.
Cap32768 bytes. Embedding the expected HostedInit permits resuming a crash after
the new guard but before that INIT; do not attempt to reconstruct lost random
IDs from its digest or from orphan stores. Old Set71's strict root inventory
rejects the new guard before opening wallets.

New owned paths are `allocation-recovery/SLUG-HOSTED-ALLOCATION-INIT.json`,
`allocation-recovery/setup/{fixture}.json`, the two per-fixture journal directories
`allocation-recovery/{fixture}/`, and
`allocation-recovery/SLUG-HOSTED-ALLOCATION-READY.json`. INIT order is
`version, guard_sha256, inventories`; its inventories equal the outer guard.
Each immutable setup intent is
`version, fixture, guard_sha256, pool_allocation_id, binding`, where binding is
§4's exact AllocationBinding. PoolAllocationID is a preselected random nonzero
ID, retained in this intent before any recipient Reserve. It is never chosen
from an orphan reservation or regenerated after uncertain publication. READY order is
`version, guard_sha256, source_binding_id, fixtures`; each fixture row is
`fixture, inventory_id, binding_id, binding_sha256, pool_allocation_id`.
INIT/READY cap 16384 bytes; each setup intent cap 8192. Fixed fixture order applies.
Hashes cover canonical bytes without a marker's single LF. BindingID uses §4's
domain; BindingSHA256 is plain SHA256 of the same canonical binding bytes.

Preserve all Set71 setup receipt/INIT/READY preimages and old CurrentStore codecs.
Its current store may remain initialized and audited, but it is not allocation
authority and cannot substitute for a missing inventory. New live export uses
the inventory-aware path; there is no need to manufacture a live Set71 capture
for schema 13. New explicit readers/adapters preserve healthy own-activity,
recipient, gym/admission and reviewed-withdrawal behavior without enabling old
generic allocation APIs.

Actual Set71 order already creates/synchronizes the wallet, obtains the hosted
receipt, completes the required enrollment challenge and constructs the current
binding **before** ensurePoolRecipientBinding. Preserve that order: create a
guard-locked schema 13 wallet with preselected inventory/owner/source IDs; at the
known-binding seam write its exact setup intent, create/open the empty pinned
inventory, bind the guard once, then reserve/consume/acknowledge recipient 0.
Only after watch/readiness checks write the existing recipient/gym/withdrawal
readiness records and final allocation READY. The per-fixture stores allow this
sequence without waiting for the second receipt before the first recipient.

The new constructor owns a separate explicit root validator. It admits exactly
the old fixed hosted root entries plus `SLUG-HOSTED-ALLOCATION-V1.json` and
`allocation-recovery`, with the corresponding finite entry-count increase; it
does not call the unchanged old root reader and ignore its refusal. The new
allocation directory admits only INIT, READY, `setup`, `zero256` and
`incrementing256`; setup admits only the two fixed fixture JSON files. Every
control file is regular, bounded and canonical. Paths are pinned with the same
symlink/alias rules as the inherited owner. Old entry allowlists stay unchanged.

Resume boundaries are exact:

| Durable boundary | Allowed next work in this new mode |
| --- | --- |
| No outer guard | Only an empty root or its owned instance-lock is eligible for fresh IDs. |
| Outer guard, no old Hosted INIT | Publish only the exact embedded HostedInit; no component store may already exist. |
| Both INIT files, incomplete old setup prefix | Resume the inherited ordered fixed stages with the preselected expected IDs. The allocation INIT must exist before either fixture wallet is created. |
| Per-fixture setup intent, inventory initialization incomplete | Only while that fixture wallet remains guard-locked/zero and neither READY nor its completed fixture stage exists, finish that exact store's initialization as described below. |
| Inventory marker/state complete, wallet locked | Verify the exact zero head, then bind the expected guard once. |
| Wallet bound, recipient incomplete | Open-only inventory and wallet; resolve only the setup intent's PoolAllocationID against exact local links, then acknowledge/watch before recipient/gym readiness. No replacement ID or index is allowed. |
| Allocation READY, no Hosted READY | All dependencies are established/open-only. Audit all of them, then publish only the exact remaining Hosted READY. |
| Both READY files | Open/verify-only, including missing-wallet classification; no initialization or repair. |

The explicitly named inventory initialization/resume constructor requires the
retained setup intent and independent authority/current binding. Before its
marker exists it may create an absent store or resume an otherwise exact owned
empty directory/empty LevelDB, then write the unique canonical zero metadata
and marker. It may also finish the marker over exact zero metadata. No rows,
foreign entries, bound wallet or completed fixture/READY evidence may be
present at that boundary. Once a marker exists, missing/corrupt metadata is
refusal. Ordinary Open never initializes or repairs. A missing marker after
wallet binding or any allocation is refusal. The constructor never treats
inspection of an orphan store as its expected authority.

After both fixture recipient/gym/withdrawal receipts and the unchanged current
store stage are complete, publish allocation READY, then unchanged Hosted READY,
then start normal pool/admission/settlement services. In particular, absent
Hosted READY must not select an old `create=true` path when allocation READY
already exists. Hosted READY without allocation READY is impossible under this
order and refuses. Provisioning may already own the bounded primary/peer nodes
needed to synchronize fixture wallets; those are distinct from normal services.
All preexisting stage receipts and READY hashes remain exact. Missing expected
state after its established stage never becomes a creation opportunity.

Full-store hostile filesystem rollback is not claimed detectable solely from
local sequences or hashes.

The only permitted absent installed payload is the exact
`shared/gyms/<account-id>/wallet/slugwallet.db`, or its whole `wallet` directory
under an otherwise intact expected gym directory. The filename is
`wallet.WalletDBName`, **slugwallet.db**, not wallet.db. A symlink, wrong type,
unreadable file, busy owner, corrupt or foreign-schema wallet is not absence.
Do not create the absent file/directory while classifying or recovering it.

Require surviving exact account/coordinator/driver, vault/receipt, new guard/
INIT/READY/inventory, old hosted/current/source/runtime/league/pipeline identities,
gym/recipient/stable/outbox records, and established application withdrawal
guard/journal. Missing any of those refuses this slice. Losing the wallet's own
reservation namespace is expected local loss, not permission to recreate it.
Do not open or mutate the unaffected fixture wallet merely to classify recovery.
If either wallet is absent, stop all normal services for this candidate parent.
Only a selected genuinely missing fixture can receive the recovery-only arm.
Selecting the still-present fixture reports hosted_recovery_unavailable until
normal parent prerequisites are available; do not label its wallet missing or
fabricate healthy readiness.

## 4. Allocation inventory bytes and limits

All new JSON has exact declared field order, UTF-8 and encoding/json canonical
escaping, integral shortest-decimal numbers, exact lowercase hex and no unknown,
duplicate, missing or null fields unless explicitly listed below. On-disk control
files add exactly one LF; DB values do not. Timestamps are owner-sampled
milliseconds `1..253402300799999`, with0 only for an uncompleted field. uint32
revisions refuse overflow. Identity digests are SHA256, never PoW or signatures.

Ordered AllocationBinding:

```text
version, inventory_id, authority_id, account_id, principal_id, provision_id,
hosted_vault_id, retention_id, wallet_owner_id, source_binding_id, manager_schema,
max_allocations, max_bytes, max_plan_attempts, max_branch_index, initial_manifest
```

Version 1; all ID fields are64 lowercase hex and nonzero. ManagerSchema is 13;
MaxAllocations, MaxBytes, MaxPlanAttempts and MaxBranchIndex are exactly 1024,
4194304,128 and4096. These constants are in the digest preimage, not inferred
only from the request or a marker version. InitialManifest is the
exact original sealed receipt's version-1 identity and four branch schemas with
zero cursors, not a supplied changed identity. The parent independently verifies
full source config/pin and existing CurrentBinding against its retained objects;
this flattened binding is an exact projection of them. BindingID is
`SHA256("SLUG hosted allocation binding\0v1\0" || canonical_binding)`.
Both fixtures share authority/vault/source but have distinct inventory/account/
principal/wallet-owner IDs. In-memory pointer binding remains additional.

Journal marker `SLUG-HOSTED-ALLOCATION-INVENTORY.json` order is
`application, version, inventory_id, binding`; application
`slug-hosted-allocation-inventory`, version1, cap 8192. Only LevelDB keys `meta`
and `allocation/<allocation_id>` are allowed. Metadata order is
`version, marker_sha256, revision, allocations, clock_high_water_ms,
active_allocation_id, cursors`. `cursors` is exactly eight uint32 raw next-index
ceilings in 44/0,44/1,49/0,49/1,84/0,84/1,86/0,86/1 order, each0..4096.
Initially revision/allocations/time/cursors are0 and active ID is empty.
Revision increments on each acknowledged reserve or completion; allocation
count increments only on reserve. Every row has a unique contiguous reserve
sequence1..allocations. Initial revision0 is valid; no clock-only mutation is
needed. Clock high-water equals the greatest committed reserve/completion time.

Allocation row order is
`reservation, reservation_digest, phase, completed_at_ms,
wallet_record_digest, draft_digest`. Reservation order is:

```text
version, sequence, allocation_id, binding_id, request, purpose, branch,
start_index, end_index, selected_index, invalid_indices, address, script,
reserved_at_ms
```

The exact Request and local consumption-link codecs are in §6. ReservationDigest
is `SHA256("SLUG hosted allocation reservation\0v1\0" || canonical_reservation)`.
The row's immutable Reservation never changes after reserve. Initial consumer
kinds are pool_recipient, receive and withdrawal_change, all native84/account 0;
other six branch ceilings remain zero in fresh Set72. Include them explicitly
and reject unsupported scope allocation. Recipient0 is fixed native84 external 0
and never changed by new Receive or withdrawal operations.

Require `start_index < end_index <=4096`, selected index=end-1. InvalidIndices
is a nonnull strictly increasing array of at most 127 uint32 values exactly
covering `[start, selected)`. These are genuine modeled/observed invalid children,
not unused arbitrary gaps. One plan derives at most 128 raw children, clipped to
the branch bound. No valid child within that budget returns capacity without
mutation; no invented skip-only step is implicit. Address is at most 90 ASCII
bytes, script is canonical lowercase native84 P2WPKH script hex; exact old
network encoding/address/script and selected derivation must agree.

Phase is reserved, consumed or burned. Reserved has completion time0 and empty
record/draft digests. Consumed/burned have completion time≥reserve time and the
exact local-link digest. Consumed withdrawal_change additionally has the exact
existing draft digest; every other draft_digest is empty. A burned withdrawal
consumer cannot be reused for another allocation. A same-ID/request replay
returns the original row/time; changed request or changed kind/consumer mapping
conflicts. Every kind+consumer pair occurs once, independent of AllocationID.

Reserve advances the authoritative cursor to End immediately. Fold all rows in
reserve sequence: each Start equals that branch's preceding End; untouched
branches stay equal. Exactly one reserved row may be active; it must be the last
reserved sequence and match ActiveAllocationID. No later reserve proceeds until
it becomes consumed/burned. Completed rows are never removed or compacted to
regain capacity. Metadata revision equals allocations plus terminal rows.

Per fixture: at most 1024 rows, canonical row≤4096, metadata≤4096, logical DB
key+value total≤4 MiB. Count/byte limits are independent; all maximum-sized rows
need not fit. Reserve precharges the larger legal consumed/burned terminal row plus metadata
and key bytes, including maximum completion-time width and digest lengths. It
also precharges the exact local consumed/burned link, guard/meta and any paired
withdrawal namespace growth before admitting the range. No concurrent allocation
can consume this reserved logical capacity. A full journal cannot strand
acknowledgment/burn; disk/commit failures still follow uncertainty rules. One final mutation writes only
one row+meta, prepared key/value bytes≤12288, Sync true. Open/audit visits at
most1024 rows plus metadata and one refusal witness, checks every declared key,
canonical row, unique ID/consumer, range fold, phase/digest, count, time and byte
total. No source rehash or blockchain scan is part of inventory audit.

## 5. Allocation protocol, original action and crash outcomes

Only an attached concrete wallet can privately plan/consume. It retains exact
owner pointers and original session/action through the operation. Planning
reads the eight guarded cursors and paired journals, performs public derivation
and, for withdrawal, validates bounded funding/fees before reserve. No public
address/draft getter is exposed. Plans are stale if owner, guard, cursor or
selected inputs/tip change; they do not silently replan with a new nonce/range.

1. Acquire all fail-fast source/inventory/allocator permits outside account
   leases; perform original capability/epoch preflight. Receive and setup
   recipient use View; reviewed change uses Withdrawal. Plan/stage bytes outside
   the lease. The final reserve fence commits only the already-validated bounded
   host batch and original recheck. No wallet mutation follows uncertain reserve.
2. Consume outside account leases. Recheck exact committed Reservation and local
   cursor. One wallet transaction writes address/invalid-child state, cursor and
   immutable local link. Reviewed change writes its exact unsigned draft and
   prepared input reservations in that same transaction. Retain existing
   newAddrMtx/OnCommit cache discipline. No backend call is in that transaction.
3. Inventory completion accepts only its exact wallet-minted receipt, or a new
   opaque receipt reconstructed by bounded same-wallet durable lookup. It never
   accepts caller cursor/address/digest evidence. Stage and synchronously commit
   completion under the original action fence. Register/re-establish the exact
   address watch with the owned backend outside leases, then perform a final
   original-view disclosure/signing precheck. Ack is an allocation fact, not a
   claim that a network watch is currently active.

Plan/no-funds refusal before reserve has no cursor effect. If authoring fails
after known reserve but before a local commit, resolve that range by exact local
burn before another plan. An uncertain local commit must never be called absent
or burned: poison, join, reopen and audit its exact link/cursor first. After
reopen, atomic absence of the link with unchanged start cursor permits exact
consume/burn; changed cursor without its required link is corruption, not repair.
Every reserved range remains in the recovery head even if no wallet survives.

A reserved withdrawal whose process died before local commit has no durable
selected-input/tip Plan. The reservation does not authorize new coin selection
or a reconstructed replacement draft: explicit recovery can only Burn, followed
by the existing user Abandon before a new Prepare/OperationID. A consumed local
withdrawal recovers its exact saved draft and bytes. No new durable Plan codec
is added. Receive/setup reservations remain reproducible from their exact
public range and can resume Consume.

| Interrupted stage | Exact permitted recovery |
| --- | --- |
| Before reserve | No output/effect; same request may be explicitly retried. |
| Reserve committed, reply lost | Reopen/lookup that AllocationID; no different ID or wallet mutation until exact outcome is known. |
| Reserve known, local consume absent | Receive/setup can rederive and consume the exact reservation. Withdrawal can consume only while its original live private Plan survives; after process loss, only explicit Burn is allowed. Never release the high-water. |
| Local commit known, host completion absent | Reconstruct exact local receipt/draft and acknowledge, never derive again. |
| Completion/watch response lost | Re-read the exact acknowledged allocation, restore watches, disclose only after a new explicit action's original authorization. |
| Reset during local consume | Inert reserved preparation may finish; old action cannot disclose/review/sign. Later View reconciliation does not inherit payment approval. |

NewScript is invoked even when change is dust/zero. Such drafts and later
abandoned drafts consume the exact internal path. After a definitive post-reserve
authoring failure and burn, the linked app intent remains unresolved until the
user explicitly abandons it; a new payment requires a new OperationID. Existing
StageAbandon permits a draftless intent. No automatic second allocation for the
same consumer is allowed. The app walletwithdraw journal remains sole signed/
delivery authority; native approval, scratch-only signing, app signed commit,
retention/exclusions and one-use dispatch remain unchanged. Sign requires exact
acknowledged allocation and watch readiness as additional prerequisites.

Whole actions cap 30 seconds; each backend call cap 5 seconds inside that budget.
No wallet lock/DB transaction, derivation, KDF, signature, JSON encode/hash,
inventory audit, gate acquisition, network IO or join occurs under an account
lease. Pre-acquired local inventory publication permits only the prepared
bounded synchronous batch plus checks, as in Set71. Cancellation cannot abandon
an already-running local transaction/KDF; join it. Private unsigned preparation
may finish after revocation, but no result is exposed or signed without the
original fence. Capturing a replacement token to finish an old action is forbidden.

One uncertain journal write poisons that owner. Failed close retains owner/path
and returns a sticky error, never a later false success. Close cancels/joins
source operations, then detaches/joins the concrete wallet, then closes stores.
No component closes a borrowed parent authority or adopts a replacement wallet
while old work remains live. Per-store logical working allowance16 MiB covers
bounded audit, ID index, old/new row/meta, plans and recovery heads; maximum two
stores 32 MiB. Existing withdrawal32 MiB work,16 inputs,4096 visited credits and
previous-transaction limits remain additional separate budgets, not a total heap
claim. Normal watch collection caps 32768 scripts,16384 owned outpoints,8 MiB
request data and batches128 addresses; charge before copying/dispatching.

## 6. Wallet guard, exact request and local-link bytes

### Manager guard and local namespace

Manager schema is 13, RecoveryVersion remains1 and the retained derivation mode remains the existing standard Phase-A mode. The manager's existing `main` bucket gains key ASCII `hostedallocationguard`. Its value, maximum 2048 bytes, is:

```
version, state, inventory_id, authority_id, account_id, wallet_owner_id,
source_binding_id, initial_manifest_sha256, binding_id
```

`version=1`; state is `locked|bound`. The five identity IDs are nonzero and fixed from the original outer INIT/account/source (inventory, authority, account, wallet owner, source). InitialManifestSHA256 hashes the canonical unchanged initial v1 manifest without a domain. State locked requires `binding_id=""`, all eight manager cursors zero, and the exact empty local namespace below. State bound requires the full nonempty BindingID matching the surviving inventory and those identities. No other field changes at binding. GuardSHA256 is SHA256 of `"SLUG hosted allocation wallet guard\x00v1\x00" || canonical_guard`.

Creation atomically writes manager version13, locked guard and the empty local namespace. There is no schema 9 interval and no ordinary migration. One walletdb transaction changes locked→bound and its metadata GuardSHA256 only after the exact per-fixture store exists, its zero head is audited, and the original hosted receipt/current binding has been verified. It cannot bind a different existing wallet, nonzero cursors, populated namespace or alternate inventory. Failed initialization resumes only against the original retained INIT; missing established state is refusal.

Top-level wallet bucket ASCII `slug-hosted-allocation-v1` contains exactly value `meta` and nested bucket `records`; no unexpected values/buckets. Meta, maximum 2048 bytes, has ordered fields:

```
version, guard_sha256, completed_sequence, cursors
```

Version 1; CompletedSequence 0..1024; Cursors has exactly eight entries. Empty locked/bound state has sequence0, zero cursors and no records. Record keys are exactly 4-byte **big-endian** sequence1..CompletedSequence, with no gaps, duplicates, suffixes or extra keys. The entire namespace plus manager guard has a4MiB logical byte cap counting key and value bytes; count/bytes are independent pre-write limits. There is no on-disk secondary ID index: the bounded audit constructs a ≤1024-entry in-memory allocation/consumer index. The manager cursors must equal Meta.Cursors. The latest link's after-cursors must equal Meta.Cursors, and all links form a continuous before/after fold from zero.

### Exact request and reservation preimages

AllocationRequest fields, in order:

```
version, kind, consumer_id, purpose, branch, withdrawal_binding_id,
recipient, recipient_script, amount_atoms, fee_rate_atoms_per_kb,
fee_ceiling_atoms, min_confirmations, input_purpose, change_purpose,
account, tx_version, input_sequence, lock_time, sighash_type
```

Version 1; kind `pool_recipient|receive|withdrawal_change`; purpose 84. For pool/receive: branch 0; ConsumerID equals AllocationID; withdrawal_binding_id, recipient and recipient_script are empty; every numeric payment field after recipient_script is 0. Pool recipient additionally requires first external allocation start0 and selected0 and the exact existing independently frozen native84 index0 address/script. It never changes the pool settlement destination. Receive creates a separate destination.

For withdrawal: branch1; ConsumerID is the existing walletwithdraw OperationID, and WithdrawalBindingID is that exact existing app/wallet withdrawal binding. Recipient/address script and AmountAtoms match the durable app intent and inherited CandidateWithdrawalRequest. The address is canonical allowed P2PKH/P2SH/P2WPKH/P2TR,≤90 ASCII bytes; script is its exact lowercase hex,≤34 bytes; amount is positive,≤MaxMoney and satisfies the inherited dust check. Explicit constants are fee rate1000, fee ceiling100000, minimum confirmations1, input purpose 84, change purpose 84, account 0, tx version1, input sequence4294967295, locktime0 and sighash1. They are encoded, not inferred from a loosely named policy. RequestDigest is SHA256 of `"SLUG hosted allocation request\x00v1\x00" || canonical_request`. Request maximum 2048 bytes.

Reservation fields, in order:

```
version, sequence, allocation_id, binding_id, request, purpose, branch,
start_index, end_index, selected_index, invalid_indices, address, script,
reserved_at_ms
```

Version 1; sequence1..1024; IDs valid; Purpose/Branch exactly repeat Request. `0<=start<end<=4096`, selected=end−1, end−start≤128. InvalidIndices is exactly the ordered integer list `[start,...,selected−1]`, at most 127 entries; each must have been independently observed as a genuine invalid BIP32 child by the private bounded plan and rechecked during consumption. The selected child must be valid. Address/script are exactly native84's selected path; script is 22 bytes `0014…`. There is no ordinary public getter for an unacknowledged reservation. ReservationDigest is SHA256 of `"SLUG hosted allocation reservation\x00v1\x00" || canonical_reservation`. The full external journal row retains §4's `reservation,reservation_digest,phase,completed_at_ms,wallet_record_digest,draft_digest` order and4096-byte bound; independently measure the combined worst case before freezing.

AllocationID is a caller-preknown nonzero random identity retained by the native/controller action before dispatch; this is bounded process memory, not a new native disk journal. The setup recipient ID is separately persisted in its immutable setup intent. Durable allocation history begins at Reserve. There is no automatic replacement ID on uncertainty. The journal enforces uniqueness of both AllocationID and `(kind,consumer_id)`. Same-ID exact-request replay returns the original row; changed bytes conflict. A different AllocationID cannot create a second reservation for the same withdrawal OperationID. This gives exact resolution without changing existing walletwithdraw codecs or adding allocation attempts to its operation.

### Local consumption/burn record

Each `records` value is canonical JSON≤4096 bytes with ordered fields:

```
version, inventory_id, binding_id, sequence, allocation_id,
reservation_digest, request_digest, outcome, purpose, branch,
start_index, end_index, selected_index, invalid_indices, address, script,
cursors_before, cursors_after, withdrawal_binding_id,
withdrawal_operation_id, draft_digest
```

Version 1; Outcome=`consumed|burned`. Identity/range/address fields must equal the independently retained host reservation. Both cursor arrays have eight entries; before equals the preceding local record/meta, target branch before=start, after=end, all other branches unchanged. The exact valid selected address row is installed even for a burn, so future sync can watch the committed prefix without manufacturing missing rows. The local link's InvalidIndices is the sole durable invalid-child witness; no second skip table or schema11/12 progress bucket is added. Public derivation verifies every listed invalid child and selected valid child; no valid child may be labeled skipped. WalletRecordDigest is SHA256 of `"SLUG hosted allocation wallet record\x00v1\x00" || canonical_record`, with no self-hash field.

For pool/receive, all three withdrawal strings are empty. For withdrawal consumed, WithdrawalBindingID/OperationID equal Request and DraftDigest is the existing `CandidateWithdrawalDraftDigest`, with its inherited domain/LE32 framing unchanged. For withdrawal burned, binding/operation remain exact but DraftDigest is empty. A consumed withdrawal must have the exact corresponding existing withdrawal record and input reservations. A burned withdrawal must have **no** corresponding wallet withdrawal draft or prepared/retained input entries. The allocation link is never deleted when an unsigned draft is later abandoned; the retained withdrawal record continues to identify that immutable draft.

One successful walletdb transaction writes address/invalid-child evidence, manager raw cursor, this link, Meta's sequence/cursors and—only for withdrawal consumed—the exact unsigned draft and prepared input exclusions. This preserves the existing Set68 atomic boundary. Burn performs the same cursor/address/link writes but writes no payment draft or input exclusions. A record is immutable after commit; host acknowledgement changes only the separate inventory row. Transaction commit error, rollback error or postcommit cancellation returns outcome-unknown and poisons the owner; no subsequent burn/selection may infer absence from that error.

On open/reconciliation, audit both complete local links and host rows (≤1024 each). Each local sequence must match its reservation and exact link digest; terminal host rows must have exact local links while a reserved host row may be the single next sequence or already locally consumed but not acknowledged. Local-ahead without its reservation, wrong digest, mismatched manager cursor, unpaired withdrawal row or more than one unresolved range refuses. Acknowledgement uses only an opaque receipt minted by the same attached wallet from its successful commit or exact durable lookup—not supplied digests, a Boolean, callback proof or JSON constructor.


### Concrete APIs and integration lifetime

```
Loader.CreateHostedAllocationWallet(ctx,pub,priv,entropy,birthday,expectedLockedGuard)
Loader.OpenHostedAllocationWallet(ctx,pub,expectedGuard) // requires window0
Inventory.Attach(ctx,installed,originalToken,originalEpoch) -> *HostedAllocator
Allocator.PlanRecipient/PlanReceive(ctx,allocationID) -> *AllocationPlan
Allocator.Create/OpenWithdrawals(ctx,withdrawalBindingID) -> *AllocatedWithdrawals
AllocatedWithdrawals.Plan(ctx,allocationID,CandidateWithdrawalRequest) -> *AllocationPlan
Allocator.Reserve(ctx,*AllocationPlan) -> *AllocationReservation
Allocator.Consume/Burn(ctx,*AllocationReservation) -> *AllocationReceipt
Allocator.Acknowledge(ctx,*AllocationReceipt) -> *AllocationAcknowledgement
Allocator.Resolve(ctx,allocationID) -> *AllocationAcknowledgement
Allocator.Finalize(ctx,*AllocationAcknowledgement) -> *AcknowledgedAllocation
AcknowledgedAllocation.Receive()/Draft() // owned copies, only correct kind
AllocatedWithdrawals.Sign/Retain/Abandon/Lookup(...) // exact allocated linkage
Allocator.Close(); Inventory.Close()
```

These are the concrete API roles selected for this draft; exact Go result/error
signatures remain a finite implementation-mapping item before adoption. Neither
Plan, Reservation, Receipt nor Acknowledgement has an address/script/draft
getter. Finalize privately registers the exact consumed address through the
retained chain client, bounds and joins its five-second watch operation, then
checks the original capability/epoch before minting the getter-bearing owned
result. Burned acknowledgements cannot finalize into an address or draft. No
watch-success callback supplied by a caller is accepted.

The existing desktop withWallet/openPoolWithdrawal/recipient helpers hold
walletRuntime.mu across account-free seams. Do not substitute compound allocator
calls there: capture a retained installed pointer under a short mutex scope,
release that mutex, and use the child/source lifetime that joins before unload.
No account fence may acquire or wait for walletRuntime.mu, newAddrMtx, DB,
app-journal or inventory permits. The app Owner permit may span account-free
planning, but Reserve/Acknowledge enter outside its account callback. Existing
withdrawalRecover must resolve allocation acknowledgment before an old stored
draft becomes actionable. Stop, backup and Close join the new receive lane and
source before wallet unload. These are new integration requirements, not a
claim that the old account-free seam was defective.

## 7. Inventory-backed export and recovery-only owner

The inventory may open without a wallet only under its exact independent binding
and surviving authority. It mints an opaque HostedRecoveryHead carrying owner,
binding, revision, reserved ceilings and the resulting public v1 manifest. The
manifest retains every original identity/non-cursor field and replaces only the
eight cursors. No user manifest/latest JSON or Set71 dated head becomes evidence.
Reserved and burned ranges are included. Capture/export does not consume the
allocation count or Set71's128 actions.

HostedVault verifies exact surviving enrolled receipt, RetentionID, binding,
inventory pointer and original token. A prepared export retains the inventory
permit across validation/publication or rejects a changed revision, preventing
an old head from being relabelled current. Derive/decrypt/encode outside account
leases. Reuse the concrete pinned create-only destination and opaque
Publish/Close object; no seed getter, generic raw callback or plaintext staging
before authorization. At most64 KiB secret file write/sync/exclusive-link/dirsync
occurs under the final original RecoveryExport plus parent TryLock epoch fence.
Post-link uncertainty preserves the file and export_uncertain; no automatic retry.

Original RecoveryExport is mandatory for live or missing-wallet inventory
export, including D72 hold. NewReceive and existing-file Verify use View. Held
healthy wallets may view, receive and explicitly mine as before; recovery-only
mode has no miner because the installed prerequisites are absent, not because
the reset hold gained a new restriction. No silent wallet/journal installation,
source recreation, balance award, payout, mining or new payment follows export.

Startup acquires exact root/selection, audits immutable receipts and opens pinned
accounts/coordinator/driver first. Exact pending reset retains precedence; it
returns the usable existing resume-reset state. Otherwise audit surviving
vault/inventory/source/journals and classify each exact wallet path. Factor a
read-only shared-source audit owner; do not call the normal provisioning
constructor and swallow its missing-wallet error. No pool/admission/settlement
services start when either wallet is absent. Export is node-independent; Verify
may lazily own the exact pinned loopback source with no mining/services.

Recovery-only login uses a fresh signed fixture flow. The enrolled receipt is
verify-only if RecoveryRequired=false. If true, issue the exact recover
challenge, use the vault's gym-only signer, CompleteChallenge and existing
acknowledgment-only EnsureEnrollment. It never calls ProvisionFixture or unwraps
recovery material during held login. Missing enrollment/receipt is refusal.
Retain one original token, generation, fresh recovery ViewID, parent/helper epoch
and exact owner. This is not PoolChild/ManifestViewPin/mining/payment authority.

One recovery operation owns selected descriptors, scratch/session/loader/runtime
and any source through completion. Reuse schema 12 Begin/Step/Close/ordinary-ready
Open on the same Loader,128-derivation/one-block work steps, current bounded
scanner and exact final node/wallet hash+height checks. Scratch stays disposable;
it cannot turn into installed schema 13 or attach/recreate payment journals.
Failed construction/close retains its opaque cleanup owner and scratch directory.
Successful Close precedes removal. Before restoring, verify the selected file's
public identity, branch schemas and eight cursors equal a fresh exact inventory
head captured under View. This new recovery-only route is an exact-current-head
check: an older cursor file is backup_mismatch, even if independently well formed.
It introduces no dated-validity verdict or new protocol. At completion the head revision/ceilings must remain unchanged,
and before/after source samples must equal the restored wallet's synchronized
hash and height. Inspect the bounded restored ledger and key-control proof at
that tip. Only healthy mode retains the inherited full installed-wallet balance/UTXO/history
comparison. Recovery-only has no such baseline and must not claim that comparison.
Its result establishes the hosted reserved window at that exact chain state,
not arbitrary offline-derived future indices or reconstructed payment authority.

Reset makes the pending barrier/revocation durable before joining blocked work.
Logout/expiry/switch/Close invalidate the old View and cancel/join outside account
locks. A new helper or identical-looking IDs cannot rescue the original action.
Native captures helper+full View before save/open dialog, keeps pinned selection
until acknowledgment, and rechecks the exact original context before dispatch.

## 8. Normal helper wire, native actions and errors

### Framing, bounds and unchanged controls

New root/receive Go family prefix `HostedRecovery*`; private command prefix `hosted_recovery_`. This is the new mode's typed root adapter, not a replacement of healthy stable/entry/event/history/withdrawal/activity protocols. One UTF-8 JSON object and LF per frame; reject duplicate/unknown keys, null required fields, noncanonical numbers, excessive depth and trailing JSON. Marshal in the orders below. Inherited DTOs retain their exact field order and grammar.

- Request `{id,version,command}` followed by only its command's fields; ID1..9007199254740991 and version1. Action/allocation/inventory IDs and new recovery View IDs are nonzero64 lowercase hex. A healthy request's ViewID retains inherited ManifestViewPin grammar; do not strengthen old DTOs to reject an otherwise valid zero lexical hash.
- Times0..253402300799999, positive when an action happened; revisions/counts uint32; account generation1..9007199254740991. No monetary/cursor floats. Inherited AccountSnapshot keeps its own existing grammar.
- Whole request including LF≤4096 bytes, retaining the existing request admission limit; Pin's path/identity rules are unchanged, and the whole-frame limit still applies after JSON escaping. Snapshot response including LF≤262144; receive response≤16384; depth≤16. Check frame bounds before allocation. One receive action/terminal cache, one last-issued metadata tuple and existing backup owner; no queue. New metadata accounting≤128KiB per parent, separate from the bounded wallet/inventory/export/restore work. This is accounted reservation, not a total Go heap cap.
- Startup≤180s; existing fixture login/reset entered work≤120s. Receive≤30s with each watch call≤5s. Export stays synchronous≤30s; Verify stays asynchronous with the existing ten-minute operation deadline. Joined local file commit may delay cancellation; do not promise interruptible OS sync. Private export≤65536 bytes.

| Command suffix | Additional required fields, in order | Success arm |
|---|---|---|
| snapshot | none | snapshot |
| login_fixture | fixture | snapshot; existing dispatch semantics |
| logout | none | snapshot; dispatch ack is not joined-cleanup proof |
| reset_fixture | none | snapshot; existing current/pending fixture selection only |
| start, stop | view_id | snapshot; real healthy child only; Stop joins |
| receive_begin | view_id, action_id, operation_id | receive |
| receive_lookup | view_id, action_id, operation_id | receive; exact action lookup, no new work |
| receive_resume | view_id, action_id, operation_id | receive; explicit exact reserved-operation reconciliation |
| receive_redisplay | view_id, action_id, operation_id | receive; explicit fresh disclosure of an exact consumed receive |
| receive_cancel | view_id, action_id, operation_id | receive; exact action cancel/join |
| export_recovery | owner_kind, view_id, selection | snapshot; synchronous file publication |
| verify_backup | owner_kind, view_id, selection | snapshot; async verification dispatch |
| cancel_pool_backup | owner_kind, view_id | snapshot; cancel/join |

`fixture=zero256|incrementing256`; `owner_kind=healthy|recovery_only`. Receive commands imply healthy kind. Envelope order is `{id,version,ok,snapshot,receive,error}` with both payload keys explicit null unless selected. Success requires exactly one payload and empty error; failure requires both null and one closed error. No separate backup job family, backup operation ID, backup Lookup or async Export is introduced. Existing native LoginFixture/Logout/ResetFixtureAccount, ExportRecovery/VerifyBackup/CancelPoolBackup entry points remain; only their retained new-mode transport/owner dispatch changes. No new signin screens or provider route are part of this slice.

### Typed snapshot and exact third-mode validation

HostedRecoverySnapshot order is `{version,mode,kind,account,healthy,recovery,error}`. Mode is exactly `local-hosted-recovery-pool`; account is existing AccountSnapshot; kind is inactive|healthy|recovery_only. Healthy/recovery_only require signed_in, empty root error, and exactly their named arm. Expiry or failed final original fence blanks both arms. Inactive carries neither View nor scope/head. Ordinary signed-out/transitional states retain inherited blanking. Pending reset retains its existing exact fixture/hosted_reset_pending rule.

If the selected fixture's wallet is intact but another fixture's missing wallet prevents shared services, return **inactive** with account.state=failed, selected fixture, account.last_error=account_unavailable and root.error=hosted_recovery_unavailable. All account IDs/generation/hold/capability fields are blank/zero; both arms are null. No usable session/View is installed, and any temporary login credential is revoked/joined. The parent may retain the selected fixture label for status/retry. Do not label this wallet missing, report signed-in healthy, or invent a recovery-only owner. Only a selected genuinely missing wallet can receive recovery_only. This is runtime unavailability, not a new hold policy.

Healthy arm order: `{pool,allocation,pending_receive_id,issued_receive_id}`. Pool is the exact prepared schema13 child's PoolSnapshot v1, with Mode equal to the selected third mode and Account exactly matching the outer account. Its existing backup fields are the only healthy backup-state source. There is no second backup state to reconcile. Pending_receive_id is empty or the exact active reserved kind=receive ID; it never names a withdrawal-change row. Issued_receive_id is empty or the highest-sequence **consumed** kind=receive ID from the bounded audited inventory. Neither pointer includes an address, asserts the user saw anything, or establishes old native action completion. Burned/recipient/withdrawal rows are excluded from issued_receive_id.

Recovery-only arm order: `{view,allocation,local_wallet,inventory_revision,observed_at_ms,backup}`. Local_wallet is exactly missing, never corrupt/busy/foreign/intact. Recovery-only has no amounts, wallet tip, miner, payment or stable transport authority. Backup order is `{state,phase,error}` using the existing backup semantics: idle/cancelled blank phase/error; running existing noncomplete phase; failed inherited bounded backup error; succeeded/complete means **Verify only**. Export clears prior verification evidence at begin and ends idle on success, exactly as existing export. This owner is ready for recovery operations, so unavailable is an admission error rather than a fabricated successful verification.

Recovery View order: `{version,view_id,account_authority_id,account_id,generation,fixture,root_public_key,gym_public_key,gym_id}`. It is HostedRecoveryView, never ManifestViewPin. Exact fixture/root/gym identity comes from the retained receipt and original authorization.

The implementation delta is one explicit third mode in PoolSnapshot structural validation, parent mode comparison, bridge launch/expected mode and frontend mode normalization. Old routes continue to require their exact original mode. New-mode healthy snapshots are not relabeled as old HostedPoolMode. Pending-reset validation applies explicitly to both hosted selections without widening unrelated errors. Existing healthy full source/View and all downstream DTOs remain unchanged. Frontend branches on the typed root arm **before** StableSnapshot and payment/activity polling: healthy reuses the existing path; recovery-only/inactive do not call child families or synthesize a zero-balance/stopped PoolSnapshot. Keep current stopped layout, navigation and review/export controls.

### Immutable scope and original owner identity

Public allocation scope order remains `{version,inventory_id,inventory_binding_id,current_binding}`. CurrentBinding is the unchanged exact recoveryvault.CurrentBinding. Native recomputes the core AllocationBinding digest from this full binding, InventoryID, independently derived original zero-cursor fixture manifest and compiled constants manager_schema13, max_allocations1024, max_bytes4194304, max_plan_attempts128 and max_branch_index4096. The integrated core contract freezes the exact preimage/domain/order. No action reply establishes its own trust: initial namespace disclosure comes from the retained original parent after its exact startup audit; native checks selected mode/fixture/account/manifest/source relationships and digest before sealing the scope. Later action replies must match that sealed scope.

Before a dialog or Begin, native/bridge capture `(original helper object, owner_kind, original concrete child or recovery-session owner, full View, allocation scope)`. Public strings supplement, never replace, pointer/lifetime identity. Helper dispatch checks the supplied owner_kind and View against that exact current retained owner; a healthy/recovery-only swap fails even if public IDs match. It never substitutes a later token, current generic child or replacement helper. Backup requests carry owner_kind because they serve both arms; healthy receive/mining commands have an implicit healthy kind. Any arm switch requires previous owner cancellation/join and a new explicit session. No wallet/DB/parent mutex acquisition, network work or join is performed inside the final account fence.

### Receive allocation and fresh redisplay

HostedReceiveJob order is `{version,action_id,operation_id,view_id,allocation,state,error,address}`. ActionID is preknown native correlation for **this process's explicit invocation**; OperationID identifies the durable allocation. They are distinct concepts. A new receive preselects both; a Resume/Redisplay generates a fresh ActionID while retaining the exact prior OperationID. Action IDs and terminal replies are retained in bounded native/helper memory before dispatch, not persisted to a new native disk journal and not a durable “user saw it” ledger. Helper/native retain at most one admitted action plus its terminal until another explicit action replaces it.

States are running|ready|needs_resume|failed|cancelled|unknown. Only ready has an address and empty error. Running has no address/empty error; needs_resume uses allocation_resume_required; cancelled uses cancelled; unknown uses outcome_unknown. Address order is `{address,script,purpose,coin,account,branch,index,inventory_revision}`. Native84 external only: purpose84/coin0/account0/branch0/index1..4095, canonical SLUG address≤90 ASCII bytes and exact22-byte script hex. The immutable pool recipient remains index0.

Ready requires exact consumed local-link proof, durable inventory completion, successful owned watch registration and a final original View fence. Reserve/head advancement alone never permits disclosure. The expected native action command, ActionID, OperationID, helper/owner/View/scope must all match. Receive_lookup never re-enters work or creates an action. It returns only the same admitted action; if that action is absent but the exact durable allocation exists, return allocation_resume_required without a payload. If neither exists, allocation_not_found is definitive only for that ordered exact lookup. Do not overwrite an existing dispatched/uncertain action due to a later local busy/refused call. Lookup never adopts either snapshot pointer or a prior terminal ActionID as the new action result.

After reset/logout/helper loss, old action authority and caches are invalid. There is **no old-action-success recovery claim**. An actual reserved pending_receive_id supports a fresh explicit Resume with a new ActionID, exact old OperationID and new original View. A consumed issued_receive_id supports a fresh explicit Redisplay: capture that exact ID from the trusted healthy snapshot, re-read its exact consumed row, verify local link and watch readiness, then disclose under the new View. The request never means “whatever is latest now”; a later inventory head cannot substitute another ID. The public fixture derivation and exact scope are rechecked before displaying/copying.

The bounded recovery surface exposes just the last consumed receive candidate, selected from at most1024 audited rows; no general history page or search is added. If a still-active same-process action is uncertain, only its retained ActionID/OperationID may be resolved until joined. Once that action is gone after owner replacement, redisplay is labeled **“Show previously issued address”**, not “previous request succeeded.” Older exact IDs already retained by a current native invocation remain exact lookup targets; this UI does not promise arbitrary historical browsing. No persistent delivery/watch/disclosed bit is added.

Cancel joins the exact action. It does not recycle a range or automatically change a durable allocation phase. Unknown local commit requires joined reopen/audit; only a definitively unconsumed exact range may take the defined local-burn transition. A consumed record stays consumed, and cancelling an already-ready action cannot burn it. New allocation remains blocked while the core has an unresolved reservation.

The existing wallet area adds New receive address and, when an issued ID is available, a small explicit redisplay action in its address/status area, plus copy after successful disclosure. No automatic address display on sign-in, no extra recovery navigation, no payment review changes. View authorizes healthy same-wallet issuance/redisplay, including held accounts. Mining must already be stopped and conflicting work drained; busy refuses without pausing or restarting mining.

### Existing export, Verify and Cancel

Reuse the current native dialogs and recoveryfile.Pin `{version,mode,path,parent,file}`. Capture the original helper/kind/full View/scope **before** the dialog; after selection check the same owner before dispatch. Native retains Selection through the synchronous request. Helper independently opens matching handles before use; Verify acquires its own exact input handle before async dispatch returns. A lost/failed transport response follows existing uncertainty handling, never an automatic repeat or lookup of a different operation. Descriptor ownership and termination behavior stay the inherited qualified transport contract; do not claim asynchronous logout ack proves cleanup.

Export requires original RecoveryExport, exact inventory head proof, crypto/encoding outside leases and the existing bounded≤64KiB final private file commit. It responds only after publication/cleanup joins. Success keeps “Test wallet recovery file saved.” and backup idle, never verification succeeded. A failed outer fence or possible-publication cleanup failure keeps backup_export_uncertain; check the destination before another explicit save, never delete or silently overwrite it.

Verify requires original View and a concrete pinned owned source, so it remains available while held. It uses the existing async phase progression and “Backup verification started.” response. CancelPoolBackup cancels and joins that exact retained owner's verification. No endpoint/credential/private bytes come from the file, Pin or browser. Native root/helper replacement invalidates the old selection context; a successor cannot rescue an old save destination or claim its result. The recovery caption alone distinguishes missing local wallet from unavailable authority; ownership/hold policy and existing controls do not change.

### Errors and finite checks

Closed boundary codes: invalid_request, unauthorized, forbidden, stale_view, busy, cancelled, outcome_unknown, hosted_recovery_unavailable, hosted_reset_pending, allocation_capacity, allocation_conflict, allocation_not_found, allocation_resume_required, allocation_unavailable, wallet_missing, backup_invalid, backup_mismatch, backup_unavailable, backup_storage_failed, backup_export_uncertain. Unknown strings are rejected, never shown raw. Refused requests carry no partial payload. Failed new receive keeps a previously displayed address only within the same original View; owner/View change blanks it.

## 9. Independent reference and qualification gates

Freeze public inputs before producer design: adopted Set72 bytes/limits; Set71
commit/file provenance and independent provider/current/public models; old v1
recovery/BIP32/mixed 49 fixtures; Set69 invalid-child/raw-index/progress source;
Set68 independent no-change/dust/BIP69 draft/signed vectors; literal synthetic
IDs, requests, time/sequence and known binding recipes. Public Set71 actual
reports/manifests provide provenance only, never private DB/export inputs.
Freeze each independent producer's source/CLI/input lock before generating
expected outputs. No new Go result becomes a golden or expected digest.

Independent models cover exact JSON order/domains/local links; range fold and
all eight ceilings; genuine independently derived addresses/scripts; separately
labeled injected invalid-child traces; count/byte capacity; both fixtures;
reserve/consume/ack/burn/replay/conflict; reset/expiry transitions; unknown/null/
omitted/duplicate/uppercase/overflow controls; initialization and missing-owner
refusal; request/reply contextual binding; conservative encoded-size and working
set arithmetic. Model fault outcomes are not IO or lock proofs.

Focused tests cover every bypass entrance before mutation/disclosure, one
outstanding allocation, exact-ID lost-ack recovery at all three stores/stages,
definitive absent versus unknown burn, no-change/dust/abandon, revocation during
blocked consume/watch, account lock probes, original helper/dialog fencing,
closed/poisoned/wrong-owner proofs, sticky close failures, bounded normal watch
reopen, missing-state refusal and cheap-profile rejection before work/files.
Preserve original failed attempts. Normal/race/cheap/static/profile validation
bind exact paired source and compiler; normal PoW runs remain serialized.

Actual qualification uses both published fixtures and fresh owned chains. Issue
native84 receive and real reviewed change beyond old1/1 without manual export,
including abandoned/no-change operations and injected acknowledgment loss.
Verify every disclosed or signed-change index lies within the independent
reserved head. Stop old owners, make only their client wallet payload unavailable,
and prove the recovery path cannot read it. Reopen the normal new helper, signed
login, export from surviving authority/inventory, independently derive the
resulting manifest paths, restore at the exact owned chain hash and verify funded
receive/change. A controlled scratch spend proves key control only in the
isolated test; the app gains no replacement spending authority. Preserve source,
receipt, inventory and surviving app-journal identities and original artifacts.

Normal package acceptance covers both names/fixtures, NewReceive exact-ID retry,
current export without manual checkpoint, healthy versus missing-wallet typed
views, original view/dialog refusals, hold semantics, reset/reopen, missing
authoritative dependencies, no automatic services/mining and ordinary default
Pool/Set71 routes unchanged. Native/default selection and inherited icon assets
remain separately qualified; this is not final D74 design approval.

## 10. Finite pre-freeze items and checkpoint

This revision closes the former receive-disclosure and duplicate-backup-protocol
choices. A trusted last-issued metadata ID is only a selection for a new explicit
Redisplay action; it never resolves the old action. Synchronous Export and the
existing asynchronous Verify/Cancel are the sole backup family. Recovery-only
Verify requires exact current inventory coverage; healthy baseline comparison
is unchanged. Section 3 specifies both initializer/READY boundaries and the
preselected recipient ID, preserving old bytes and validators.

Only these bounded mapping/qualification items remain before adoption:

1. **Concrete Go mapping.** Pin the exact constructor/result/error signatures for
   the §6 roles, recovery-head/vault adapter and new-mode initializer. Identify
   the privileged manager consume entry, local invalid-child evidence encoding,
   and explicit schema 13 active-data/watch dispatch. The local link already
   binds every invalid position; any additional durable representation must be
   declared before reference generation. No generic proof callback, account
   lock nesting or relaxed old schema/API gate may substitute this mapping.
2. **Independent sizing and source/input freeze.** Review a source-only size
   model for maximum request/reservation/local rows, terminal-write precharges,
   setup/READY/guard files and escaped helper frames. Check the 4096-byte row,
   4 MiB store, 12288-byte prepared batch and bounded working allowances as
   separate limits. Freeze exact public inputs and producer sources before
   generating expected bytes; do not silently widen a cap on implementation.

The initializer source review is recorded separately in
`reviews/initializer-review.md`. These are engineering closure items for root
review, not user-policy questions or another approval gate. This checkpoint
produces no implementation, tests, nodes or expected outputs, and does not claim
production custody, transferable fighter ownership or an active replacement
wallet. Those ownership/transfer/restoration milestones remain subsequent work.
