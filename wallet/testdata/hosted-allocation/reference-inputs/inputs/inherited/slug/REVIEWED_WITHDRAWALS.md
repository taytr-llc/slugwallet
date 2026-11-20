# Set68 candidate withdrawal journal and delivery — proposal

External design only, November19,2026. No repository implementation, wallet
operation, transaction vector or new policy is authorized by this document.
Root review freezes this together with the wallet and desktop contracts.

## Scope and source-backed choice

Use chain-root package `walletwithdraw` for pure public types/validation and the
application operation journal. It must not import `slugwallet`; the wallet fork
must not import it. The concrete desktop adapter joins the two retained owners.
No generic wallet send RPC, caller PSBT/raw transaction, fee replacement, RBF,
send-max, automatic retry, source repinning, pool funds or production keys.

The additive wallet seam prepares an exact unsigned draft, allocated native84
change and temporary input reservations in one wallet DB transaction. Signing
returns owned scratch only. It writes no signed wallet record and never calls
`PublishTransaction`. The application journal's original-Withdrawal-fenced
publication is the sole signed authorization. Root selected this explicit split;
there is no durable `signed_pending_authorization` wallet state.

Use a narrow pinned-node adapter for context-bounded `sendrawtransaction` and
`getrawtransaction`, not the existing wallet publication API. Existing
`slugwallet/wallet/wallet.go:3992–4107` first writes an unmined wallet entry, then
performs contextless notification/network work; rejection can remove the entry.
That behavior cannot define application authorization or retry. Existing wallet
sync at `wallet/wallet.go:566–585` subscribes to spends of owned UTXOs. Normal
notifications should learn an authorized direct send; ordinary rescan/reopen
recovers missed observations. A missing wallet row is never a new-send authority.
Passive wallet/network rebroadcast after an authorized handoff cannot be recalled.

## Fixed candidate limits

-128 retained operations, no eviction/reuse; at most one unresolved operation.
-4096 candidate credit entries visited before selection, at most16 selected
 native84 account0 inputs. The wallet iterator must enforce its bound before
 materializing an unbounded credit collection.
-One canonical pinned-chain recipient address (purpose44/49/84/86, ASCII<=90),
 one recipient output and zero or one native84 internal-change output.
-Minimum1 confirmation and consensus100-block coinbase maturity; fixed
1000 atoms/kB fee calculation, exact fee including discarded dust<=100000atoms.
-Transaction version/sequence/locktime, selection ordering, output sorting and
 fee arithmetic are defined by the separately frozen transaction/wallet contract.
 They must not be inferred afresh when signing or retrying.
-Application caps: unsigned transaction1024bytes, signed transaction4096bytes,
 canonical draft16384bytes, one canonical operation32768bytes, and one complete
 canonical state<=8388608bytes. Keep128 retained records, one private staged
 successor, the immutable marker and a fixed process-lock file; no per-operation
 file or mutable side head. Enforce all nested limits as well as the outer limit.
-Whole entered action<=30seconds. Each node send/lookup request<=5seconds; the
 combined delivery/observation portion<=15seconds within that same30-second
 action. Explicit View-only observation<=15seconds, each call<=5seconds. All
 contexts are linked to child lifetime.
 Local operations check context before/after bounded work and are joined; no
 background goroutine is abandoned on timeout. No new PoW is needed.

## Neutral public record and digest contract

Closed canonical UTF-8 JSON, exact declared field order, decimal integers, lower
hex and no unknown/duplicate/omitted fields. Optional phase fields are explicit
`null`, never a second spelling through omission. Bounds are checked before array
allocation, signature work or wire decoding. All amounts are integer atoms in
0..2100000000000000; times0..253402300799999, with nonzero times when present.
Native-generated IDs are nonzero lower64hex. No password, token, phrase, private
key, raw RPC credential or serialized wallet private state enters this journal.

Marker exact order:
`application,version,journal_id,pin,binding_id`.
Application=`slug-candidate-withdrawal-journal`, version1, journal_id random32bytes
created outside account leases and retained unchanged. Pin exact order:
`version,network,genesis,account_authority_id,account_id,fixture,wallet_profile,
root_public_key,gym_public_key,gym_id,pool_source_binding_id`.
All identity/source fields come from retained trusted parent/account/wallet
objects, compared exactly on Create/Open; marker inspection cannot supply trust.
Pin does not include a login generation, since the same account may recover later.

`BindingID = SHA256("SLUG candidate withdrawal binding\x00v1\x00" ||
LE32(len(payload)) || payload)`, where payload is canonical
`{version:1,journal_id,pin}` in that order. The `\x00` notation denotes one zero
byte, not backslash characters. Use that exact ID to bind the wallet namespace; the random journal_id is part of
it, so recreating a same-identity journal cannot match an old wallet namespace.
An established wallet binding plus missing/mismatched app journal fails closed.

State exact order:
`application,version,journal_id,binding_id,clock_high_water_ms,records`.
Application is the same fixed marker value, version1, journal/binding IDs must
match the separately trusted marker exactly. Records is an array of0..128 exact
Operation objects in contiguous sequence order. Empty state has high-water0;
otherwise high-water is the maximum persisted mutation sample, positive and at
least every operation's updated time. The complete state is one atomic unit.
There is no caller-controlled state clock or independent mutable record index.

Operation exact order:
`version,sequence,operation_id,revision,updated_at_ms,prepared_at_ms,stage,
intent,intent_digest,draft,draft_digest,signed,sign_authorization,dispatch,observation`.
Updated time is the journal-owned staged publication sample, committed only with
the atomic successor. prepared_at_ms is0 until the first exact app draft
publication, then immutable; it is not the wallet allocation time. These are local
journal dates, not authenticated chain times (see the clock rule below). Sequence
is uint32 in1..128, unique contiguous creation order. Revision is uint32, starts1
and increases exactly once per actual mutation; overflow refuses mutation while
preserving lookup. Idempotent replay changes neither revision nor timestamps. Stage is one of:
`intent,prepared,signed,dispatching,submitted,abandoned`.

Intent exact order:
`version,operation_id,binding_id,created_at_ms,destination,recipient_script,
recipient_atoms,fee_rate_atoms_per_kb,max_fee_atoms,min_confirmations,
input_purpose,change_purpose,account`.
Its fixed candidate values are1000/100000/1/84/84/0. Destination decoding and
script equality are independently checked; neither may change later.
`IntentDigest = SHA256("SLUG candidate withdrawal intent\x00v1\x00" ||
LE32(len(canonicalIntent)) || canonicalIntent)`; lengths are unsigned32-bit bytes.

Draft is exactly the object in §3 of `wallet-contract-proposal.md`, with ordered
fields `version,binding_id,operation_id,recipient,recipient_script,amount_atoms,
recipient_output_index,fee_rate_atoms_per_kb,fee_ceiling_atoms,min_confirmations,
tip_hash,tip_height,tx_version,input_sequence,lock_time,sighash_type,inputs,
total_input_atoms,change,fee_atoms,unsigned_tx_hex`.
Input order: `txid,output_index,atoms,script,branch,index,block_hash,block_height,
coinbase`. Change order: `address,script,index,output_index,atoms`; retain consumed
native84 internal change metadata even when output_index=-1/atoms0. Exact wallet
identity/path and same-intent recipient/amount/fixed fee rules are required.
There is no PSBT field or durable PSBT requirement. Reconstructing a signing packet
from owned stored unsigned bytes/prevouts cannot change those bytes or roles.

`DraftDigest = SHA256("SLUG candidate withdrawal draft\x00v1\x00" ||
LE32(len(canonicalDraft)) || canonicalDraft)` exactly as the wallet proposal.
The app's intent digest is linked by checking all common fields; it is not an
extra field in the wallet Draft. Draft never changes after publication. A changed
input/tip may refuse signing, not rewrite the reviewed draft. Recipient/change
role tie-breaking follows the wallet contract, including identical outputs.

Signed exact order: `raw,txid,raw_sha256`.
Raw is canonical lowerhex. RawSHA256 is ordinary SHA256 over decoded exact signed
bytes; txid uses existing non-witness double-SHA256. Every input is native84,
empty scriptSig, exactly the required public-key/signature witness, SIGHASH_ALL.
Validate all signatures against the saved previous-output amounts/scripts and
require witness-stripped bytes to equal the exact saved unsigned transaction.
No second coin selection, output sort, change allocation or fee calculation.

Before `wire.MsgTx.Deserialize` or any count-driven allocation, prewalk the
bounded raw framing with checked offsets and minimally encoded CompactSize
integers. Unsigned has no witness marker,1..16 inputs, empty scriptSigs, and1..2
outputs. Signed requires the exact witness marker/flag0x00/0x01, the same counts,
empty scriptSigs, and exactly2 witness items per input: signature<=73bytes and
compressed public key exactly33bytes. Output scripts are at most34bytes, each
amount/sequence/version/locktime and all remaining lengths are bounded before
advance, and no trailing bytes are allowed. Zero/extra inputs or outputs, unknown
flags, nonminimal lengths, oversized declared scripts/witnesses and truncation
refuse before general wire decoding. The strict decoded validation then requires
recipient/change standard scripts and exact roles, native84 key/script binding,
valid strict-DER/low-S SIGHASH_ALL signatures and witness-stripped byte equality.
The raw4096/unsigned1024 limits alone never justify allocating from a declared
varint. The wallet authoring/signing seam applies equivalent preflight rules to
its persisted unsigned draft and scratch signed result.

Authorization exact order:
`action_id,review_id,view_id,generation,authorized_at_ms`.
It records the native-held review/action and original account generation of the
successful publication fence. It is local audit evidence, not a chain signature
or proof transferable to another application. Generation is an integer in
1..9007199254740991 and must equal the original native View generation. All three
IDs are nonzero lowercase64hex. Credentials are never persisted; the action and
view identities are supplied only by the concrete retained original-authority
adapter, never trusted from a saved audit record to authorize a new action.

Dispatch exact order:
`attempt,authorization,intent_at_ms,result,result_at_ms,error`.
Attempt increments a bounded uint32 counter (overflow refuses new dispatch while
preserving lookup). Result=`pending,acknowledged,unknown,rejected`; pending has
result_at_ms0/error empty. Only the latest attempt is retained; record revision and
attempt are monotonic, while signed authorization/raw bytes remain immutable.
This is bounded operation recovery, not a claim of complete delivery-attempt
history. An exact matching txid acknowledgment is merely acknowledged.

Observation exact order:
`version,txid,observed_at_ms,state,node_tip,node_height,confirmations,block_hash,error`.
Version1; txid is always the exact signed transaction. State is
`unknown,not_observed,mempool,confirmed`. Unknown is a dated failed attempt with
empty node_tip/block_hash, height/confirmations0 and error=`node_unavailable`;
it makes no absence claim. All other states have error empty and a nonzero64hex
verified node_tip at height0..2147483647. Not_observed requires an exact recognized
missing response bracketed by a stable verified owned-node tip, confirmations0
and block_hash empty. Mempool requires exact saved raw bytes, zero confirmations
and empty block hash. Confirmed requires those exact bytes, positive confirmations
and the reported block at its canonical height under the same stable tip, with
confirmations=tip_height-block_height+1. Body/case/txid/signature changes refuse
observation; never accept another serialization merely because txid is equal.
This is dated evidence, not irreversible finality or unspentness. It never edits
Signed, reservations, or the pool's payment records.

## State and two-journal reconciliation

Phase shape is closed. Intent has no draft/draft digest, signed authorization,
dispatch or observation and prepared_at_ms0. Prepared has exact draft/digest and
positive prepared_at_ms, but no signed/authorization/dispatch/observation. Signed
and later retain the identical draft plus signed object and sign_authorization.
Dispatching requires a dispatch attempt; submitted requires a retained successful
mempool/confirmed observation at the transition, but subsequent dated observations
may be unknown/not_observed without reverting its stage. The submitted stage is
its historical completion marker; this latest-only format does not claim full
observation history. Abandoned preserves the exact intent and any already-saved
draft but has no signed object/authorization/dispatch/observation. Null/empty
counterparts must agree. Sign authorization remains immutable forever; only the
latest dispatch and latest observation may advance under their original action.
Every nonnull date is between intent creation and updated_at_ms. First prepared
date remains unchanged, and state high-water never decreases.

`intent -> prepared -> signed -> dispatching -> submitted`.
Intent/prepared may become abandoned only while the signer/committer is joined,
there are no committed signed bytes, and no unresolved/poisoned app publication.
Submitted and abandoned are the only states that do not block a new operation.
Signed outpoints remain permanently excluded in every state and observation.
No release depth, expiration, calendar cutoff or automatic conflict rollback.

-Intent is durable before wallet allocation/reservation. A wallet draft without
 a matching app intent is corrupt/untrusted, not adopted or given a new ID.
-Prepare commits wallet draft+change cursor+temporary reservations atomically.
 Repeated same operation/intent returns exactly that stored draft. If app draft
 publication is interrupted, the wallet retains its active reservation and blocks
 a new preparation. Reopen retrieves the original draft and publishes only that
 exact prepared checkpoint under the account's current View; no allocation rerun.
-Sign checks the original Withdrawal action, revalidates exact inputs, signs
 outside leases, validates the result and stages the signed app record privately.
 Reset before its final original Withdrawal fence prevents signed publication;
 scratch is discarded, while the unsigned wallet reservation remains recoverable.
-After signed app publication, the concrete adapter immediately reconciles the
 exact operation/draft/txid to wallet `retained` state outside account leases.
 That wallet record retains the txid and permanent outpoint exclusions, not raw
 signed bytes or an unmined publication entry. No next selection is allowed
 until this step is durably complete.
-Crash between signed app publication and wallet retention is safe: the active
 unsigned wallet draft already blocks selection. Reopen audits both namespaces,
 sees exact signed app authority, then idempotently marks the same wallet draft
 retained. Wallet-retained with missing/different signed app bytes fails closed.
-Abandon publishes the unsigned app outcome first under a fresh unheld Withdrawal action, with all
 local sign/publication work joined and uncertain writes resolved. Only the
 concrete adapter may then release that exact unsigned wallet reservation.
 A crash in the gap leaves it reserved, never prematurely reusable. Change index
 remains consumed. Missing established app journal never authorizes release.
-Reconciliation is a concrete opaque app-journal handle for the adapter, not a
 caller boolean or JSON grant. It retains the journal operation permit through
 wallet Retain/Abandon and provides only a local lifetime/state recheck. Wallet
 API checks its stored pin/operation/draft itself; no walletwithdraw import is
 needed. Close cancels then joins the owning task before releasing either store.

## Storage and original-action commit boundary

Before creating either namespace, persist and sync the immutable shared-root
`SLUG-POOL-WITHDRAWAL-V1.json` upgrade guard. Existing Set67's closed root inventory
then refuses this data before opening wallets. New code recognizes only the
exact reviewed guard. Parent setup retains each random journal_id in durable
per-account initialization intent before journal creation; it must reuse that
exact ID after interruption. Pass that separately trusted ID into Create/Open.
Paired READY is published only after the exact app marker and wallet namespace
both exist. Missing established pieces fail closed. This does not repin any
source, recipient, stable or career history. Parent owns the exact guard grammar
in the desktop contract; no generic unknown-root-file acceptance is permitted.

Use an immutable `SLUG-WITHDRAWAL-JOURNAL.json` marker plus one canonical
`state.json` in a dedicated owner-only pinned directory. A fixed `LOCK` file
supports exclusive process ownership. A private `.state-<random64hex>.tmp` name
is staged outside account leases; at most one such successor may exist under the
single operation owner. These are the only allowed names. Canonical JSON files
contain no trailing LF. Marker/state/stage/lock are0600 files in a0700 directory;
symlinks, nonregular files, mixed identities and mutable-path substitutions refuse.
Canonicalize legitimate selected-parent aliases before pinning descriptors.

Create is explicit setup only. Parent's durable initialization intent pins the
journal_id before creation. Create writes and synchronizes the exact empty state
and marker before setup READY; partial creation is resumed only by that original
initialization intent and exact expected identity. Open never creates or fills
missing components. Once marker/setup says established, missing state fails
closed even if every operation would otherwise be absent. Complete bounded
startup audit validates the entire state, contiguous sequence order, unique
operation IDs, at most one unresolved record, exact state clocks, stage fields,
signed transaction validity and permanent signed outpoint exclusion. Different
operations may reuse abandoned unsigned inputs; signed outpoints may never recur
in any later draft. Duplicate signed outpoints across distinct operations refuse.
No silent migration, pruning, repairing, new journal ID or history adoption.
An interrupted stage never supplies state or authorization. After canonical-state
audit it is deleted and directory-synced, with cleanup failures preserved.

A single atomic state prevents deletion of an individual/latest operation file
from appearing as a valid shorter journal. It does not claim protection against
an adversary replacing the whole directory with a coherent older backup; no
external monotonic authority or new consensus/finality power is invented here.

An exclusive process owner plus fail-fast operation permit serializes updates,
capacity admission, complete successor validation and immutable reads. Acquire
journal/wallet/task ownership OUTSIDE account/controller leases. Validate and
serialize the entire successor outside the lease; create0600 private stage,
write and fsync it, and retain pinned directory, stage, current state and marker
identity before entering the final fence. All complete state-content reads,
hashing, signature validation and serialization finish outside that fence. The
original account capability callback
may only recheck the same session/view/action and trusted local clock, publish the
already-admitted exact stage by atomic descriptor-relative replacement of
`state.json`, sync the pinned directory, then recheck. No mutex acquisition,
wallet DB transaction, wallet address operation, signature, network, source wait
or join occurs inside this callback. Only bounded descriptor/path identity and
permission metadata checks occur there; no state-content hashing or reread occurs
under the lease. Unexpected target identity or ownership refuses publication; a
retained operation permit prevents legitimate
concurrent state changes. The callback does not serialize, rewrite timestamps or
create randomness. No partially acknowledged state is copied into live metadata.

The journal owns its clock function (real time in production, explicit private
test seam); no public mutation API accepts timestamps or clock callbacks. Stage
samples it after slow work and rejects a value outside the positive time range,
below the persisted clock_high_water_ms, or below an earlier date required by
that operation. The sampled value fills the successor's updated_at_ms and new
phase times (intent creation, first prepared publication, sign/dispatch local
authorization, dispatch result or dated observation) and clock_high_water_ms.
Existing phase dates remain unchanged. Publish checks the same journal clock
again without substituting any authority: it must be valid and at least both
persisted high-water and staged sample, with the original action context still
live. It commits the already-fsynced sampled date, not a new caller date. Thus
local dates denote the admitted publication attempt, not a cryptographic instant
inside rename; a failed/unauthorized stage grants no committed date. Backward
clock mutation refuses; bounded read/replay/reconciliation remains possible.
Exact idempotent replays return saved state without resampling or increasing the
clock. Timestamp overflow or revision/attempt overflow refuses before staging.

The prepared commit retains whether publication was attempted. An outer capability
failure after an inner Publish success is not success: the adapter must resolve
that exact prepared handle with the outer result before taking a dispatch handle
or disclosing success. Missing, repeated or swallowed callback execution refuses.
A negative outer result after possible publication poisons the same open owner.

Any possible publication with write/fsync/outer-fence failure is outcome_unknown
and poisons that open journal for mutation. No retry on the same handle. Close and
reopen inspect the exact known operation to decide old/new durable state. A
private uncommitted stage is never an authorized operation or broadcast source;
it may be removed only during explicit recovery after canonical-state audit.
Cleanup errors are preserved. Capacity admission reserves the complete32768-byte
maximum for each accepted operation before intent creation, so later signed/dispatch/observation updates
remain possible at128 operations. State envelope overhead (including array
separators) is reserved4096bytes;128*32768+4096=4198400bytes, below the8MiB state
ceiling. A record's independent16KiB draft plus exact signed hex<=8192bytes,
signed wrapper and all fixed identity/intent/authorization/dispatch/observation
metadata must fit the32768-byte record bound. The fixed metadata allowance is
8192bytes; strict per-field bounds and the32768-byte whole-record check apply
before publication. No unbounded error/path text enters the record.

The existing32MiB aggregate admitted withdrawal work budget accounts for at most
three state-sized encoded/serialized working regions,16MiB cumulative decoded
previous-transaction bytes and256KiB selected transaction/signature/metadata
scratch:3*4198400+16777216+262144=29634560bytes, leaving explicit margin. Reuse
immutable rows/phase buffers instead of retaining extra full-state copies. This
is a finite logical byte reservation, not a claimed hard Go allocator/heap cap.
Array limits and previous-transaction framing must hold before object allocation;
no unbounded wallet read can hide behind this accounting.

## Exact core API boundary

Package `walletwithdraw` exports `Pin`, `Identity`, `Request`, `Intent`, `Input`,
`Change`, `Draft`, `Signed`, `Authorization`, `AuthorizationInput`, `Dispatch`,
`Observation`, `ObservationInput`, `Operation`, `Snapshot`, typed `Stage`,
`DeliveryResult` and `ObservationState`. Their persisted field spellings and order
are the objects above; exported Go fields use normal PascalCase. `Identity` is a
nonserialized setup value `{JournalID string; Pin Pin}`. Pin.Network is uint32,
Pin.Version/Request.Version/Draft.Version/Operation.Version are uint32,
Pin.WalletProfile is the exact existing fixture profile string, heights/sequence/
revision/attempt are uint32, generation is uint64 within the stated safe bound,
atoms/times are int64, Change.OutputIndex is int32. Other input/output indices
are uint32. Pin must equal the chosen published fixture's network/genesis/profile/
root/gym identity; account/source IDs are separately retained nonzero lower64hex.
The package does not infer those trusted account/source IDs from journal data.

`Request` is the exact wallet Request with ordered
`version,operation_id,recipient,amount_atoms`. The journal derives its Intent's
canonical recipient_script and fixed candidate parameters. `AuthorizationInput`
is `{ActionID,ReviewID,ViewID string; Generation uint64}` with no caller timestamp.
`ObservationInput` has `State,NodeTip,NodeHeight,Confirmations,BlockHash,Error`,
matching Observation's types, with no caller timestamp/txid/version. It is trusted
concrete adapter output, not a public RPC or claimant evidence. `Snapshot` is an
owned nonpersisted summary `{JournalID,BindingID string; Count uint32;
ClockHighWaterMS int64; UnresolvedOperationID,LatestOperationID string}`.

```go
const Version uint32 = 1
const MaxOperations = 128
const MaxDraftBytes = 16384
const MaxOperationBytes = 32768
const MaxStateBytes = 8388608

func BindingID(identity Identity) (string, error)
func ValidatePin(pin Pin) error
func ParseDraft(raw []byte) (Draft, error) // bounded canonical syntax + static grammar
func DraftDigest(draft Draft) (string, error)
func ValidateSigned(draft Draft, raw []byte) (Signed, error)

func Create(ctx context.Context, path string, identity Identity) (*Journal, error)
func Open(ctx context.Context, path string, identity Identity) (*Journal, error)
func (j *Journal) Identity() Identity
func (j *Journal) BindingID() string
func (j *Journal) TryAcquire(ctx context.Context) (*Owner, error)
func (j *Journal) Close() error

func (o *Owner) Snapshot() (Snapshot, error)
func (o *Owner) Lookup(operationID string) (Operation, error)
func (o *Owner) List(after uint32, limit uint32) ([]Operation, error) // limit1..16
func (o *Owner) StageIntent(request Request) (*PreparedCommit, error)
func (o *Owner) StagePrepared(operationID string, draft Draft) (*PreparedCommit, error)
func (o *Owner) StageSigned(operationID string, raw []byte, action AuthorizationInput) (*PreparedCommit, error)
func (o *Owner) StageDispatch(operationID string, action AuthorizationInput) (*PreparedCommit, error)
func (o *Owner) StageDeliveryResult(operationID string, attempt uint32, result DeliveryResult, code string) (*PreparedCommit, error)
func (o *Owner) StageObservation(operationID string, observation ObservationInput) (*PreparedCommit, error)
func (o *Owner) StageAbandon(operationID string) (*PreparedCommit, error)
func (o *Owner) TakeDelivery(operationID string) (*Delivery, error)
func (o *Owner) Reconciliation(operationID string) (*Reconciliation, error)
func (o *Owner) Close() error

type Fence func(func(check func() error) error) error
func (p *PreparedCommit) Publish(fence Fence) (Operation, error)
func (p *PreparedCommit) Close() error

func (d *Delivery) Take() (raw []byte, txID string, attempt uint32, err error)
func (r *Reconciliation) Kind() string // retained or abandoned
func (r *Reconciliation) OperationID() string
func (r *Reconciliation) DraftDigest() string
func (r *Reconciliation) TxID() string // empty for abandoned
func (r *Reconciliation) Check() error
```

Create/Open require the normal candidate build profile first. An unsupported
platform must refuse rather than replace the descriptor-relative durability
contract. Create cannot convert a partial established namespace into a new one;
exact partial-initialization handling stays with the separately pinned setup
intent, before READY. No inspection-derived trust or public Repair API exists.

Owner is a fail-fast concrete store/lifetime-bound permit, acquired outside all
account leases. It is not safe for concurrent calls. It holds the journal's
operation ownership through staging, bounded local publication and subsequent
wallet reconciliation or node delivery. Close releases it only after its caller
has joined any entered wallet/node work. Journal.Close first cancels lifetime,
then joins active ownership and cleanup; a timeout never frees a live wallet or
file owner. Getters return owned copies, never maps/slices aliasing journal state.
Only one PreparedCommit may be outstanding per Owner. Its Close discards only
uncommitted scratch and preserves cleanup failures. A no-op exact replay returns
a prepared no-op that still requires a valid Fence for result disclosure, and
never increments clocks/counters or creates a new delivery permit.

Publish is called OUTSIDE account leases. It invokes the supplied original
capability Fence exactly once and keeps the temporary check only inside that
callback. It counts invocation and remembers inner/check failures independently
of the outer return, rejecting nil/missing/double/swallowed callback execution.
The callback does only the already-specified bounded identity/clock checks,
atomic replacement and sync. Only after a successful outer return does Publish
return an owned Operation or enable TakeDelivery. It never acknowledges a
possible publication after any outer authorization failure. Full-state validation
and signatures have already completed before Fence is entered.

The adapter supplies Withdrawal fences for new intent, prepared publication,
signed authorization, dispatch intent and abandonment. Recovering the exact
already-reserved wallet draft after a lost app-prepared commit may use View:
StagePrepared grants no spending or selection and must match that original
reserved draft. Delivery-result/observation publication and exact previously
authorized wallet reconciliation use original View, including during a hold.
Core Fence is an internal integration contract, not serialized authentication;
the concrete adapter owns the original token/capability and never accepts a
caller-selected Fence or substitutes a new token for an entered action.

TakeDelivery succeeds only once for the exact newly acknowledged StageDispatch
publication under this Owner and attempt. It never derives a dispatch ticket
from arbitrary saved state, Open, replay or a JSON object. Delivery.Take consumes
that ticket once and returns an owned copy of its exact bytes. A closed/cancelled/
poisoned owner invalidates every derived handle. A later explicit retry must
obtain a fresh review/action, StageDispatch and original Withdrawal publication.
A saved `pending` dispatch from a crash is read/reconciled, never automatically
handed to the network. Reconciliation exists only for an audited exact signed
record (Kind retained) or an unsigned abandoned record with a retained draft;
intent-only abandonment needs no wallet call. Its local Check remains valid only
while that same Owner is retained. The wallet fork imports none of these types;
the trusted adapter passes the exact checked values into the narrow wallet seam
while holding this concrete handle, outside account leases.

Stable sentinels are `ErrInvalid`, `ErrProfile`, `ErrBusy`, `ErrClosed`,
`ErrNotFound`, `ErrConflict`, `ErrCapacity`, `ErrClock`, `ErrCorrupt`, `ErrStorage`,
`ErrUnauthorized`, `ErrPoisoned`, `ErrOutcomeUnknown`. Context errors remain
recognizable. Poison carries outcome-unknown when publication was possible;
code mapping never includes raw credentials, filesystem/RPC errors or transaction
bytes. Dispatch error codes are closed: pending/acknowledged have empty code;
unknown has `node_unavailable`; rejected has `node_rejected`. A mismatch/malformed
ack is unknown, never an acknowledged or safely rejected payment. Observation's
unknown code is `node_unavailable` as specified above.

## Delivery, retry and cancellation

The native action knows OperationID/ActionID/ReviewID and exact draft digest
before mutation. Human review holds no account/wallet/store lock. Signing and
dispatch require separate short original Withdrawal fences from that same action.
Fresh five-minute authentication and D72 holds are inherited, not extended.

A committed signed record alone never broadcasts. Persist dispatch intent under
that action's original Withdrawal fence BEFORE network I/O. Only a private handle
from that exact commit supplies raw bytes to the pinned owned-node adapter. If
reset wins before the commit, nothing dispatches; if the commit wins, later reset
cannot promise recall. Parent invalidates/revokes promptly before Stop/Close joins.

The adapter checks pinned network/genesis and literal owned endpoint, submits
exact bytes once with context/no redirect/proxy/retry, and validates a matching
returned txid. Record ack/rejection/uncertainty without discarding bytes. Then
perform explicit exact-raw lookup within the original action bound. Only a stable
owned-node mempool/confirmed observation marks submitted and ends unresolved.
Ack plus missing/unavailable lookup remains dispatching. A later View-only lookup
can reconcile that same known transaction during a hold; it cannot dispatch.

Every explicit resend needs a new native review/action and fresh unheld Withdrawal
capability, using the SAME stored bytes/fee/outpoints. It does not sign or prepare.
Unknown requests resolve by known operation ID, never by latest generic success.
No automatic retransmission on restart, logout, reset, timer or missing wallet row.
The submitted stage is historical and monotonic: a later unknown/missing/conflict
observation cannot free its inputs or resurrect a second payment. Whether to expose
an explicit resend button for a previously submitted-but-now-missing transaction
can remain outside this first candidate; retained signed bytes and observations
must remain available. Do not silently change that transaction to recover funds.

## Required finite tests before closeout

Independent frozen transaction/codec vectors precede implementation. Test exact
fees/dust/order/roles, wrong chain/recipient/input path, cap edges before allocation,
signature and witness-stripped equivalence, canonical format and immutable fields.
Test every two-journal crash gap, original-action reset/expiry before/after signed
and dispatch publication, late/lost ack, context cancellation and joined Close,
capacity recovery, missing journal and uncertain fsync/rename poisoning. Prove no
selection/sign/change allocation on retry and no wallet publication before dispatch.

Actual copied fixture funds: review/sign/send once to the other published wallet,
observe the exact bytes in the owned node, confirm through explicitly owned test
mining, recover across reopen and prove repeated recovery/retry cannot pay twice.
Actual delivery is separate from Set67's read-only payout evidence. Use no operator
keys, original live wallet changes, public-chain mining or production rollout.
