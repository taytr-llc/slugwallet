# Set68 candidate wallet withdrawal seam — proposal for freeze

November 19, 2026. External proposal only. No implementation, wallet opening,
signing, expected-vector generation or repository mutation is authorized by this
file. Read with `set68-withdrawal-feasibility.md` and the separately reviewed app
journal/native contracts. The numbered-set stack remains root-owned.

## 1. Scope and fixed candidate parameters

This is an additive in-process library seam for the existing Pool Pilot's two
published recovery-v1 fixtures. It never broadcasts, registers an unmined wallet
transaction, calls a node, estimates live fees, or creates/replaces a wallet.
Preparation does not unlock or sign. Signing requires a previously committed
owned draft and returns private scratch to the trusted adapter only.

Proposed profile gate: normal PoW build; exact SLUG network/genesis/encodings;
recovery version1, `slug-phase-a-fixture-bip39-v1`, standard BIP32, manager schema9;
exact published zero256 or incrementing256 root/gym tuple. Scope84/coin0/account0
must have native P2WPKH on both branches. Retain all existing recovery/profile
checks and cursor bound4096. No legacy schema8, arbitrary root, watch-only wallet,
imported material, candidate profile2/schema10/11, production profile or caller
selected path is admitted. Schema11 belongs to the separate resumable profile2;
it is not a spelling of the current Pool Pilot wallet.

Fixed candidate parameters, not production policy:

- At most16 selected confirmed native84 inputs. At least one confirmation;
  coinbase maturity remains the chain's100-block consensus rule.
- At most4096 mined-unspent credit rows visited, counted before skips. At most
  16MiB total previous-transaction bytes decoded per operation, each previous
  transaction at most4MiB. A capacity refusal does not choose a partial result.
- One recipient, canonical address of at most90 ASCII bytes, only P2PKH/P2SH/
  P2WPKH/P2TR for the exact network. No raw script, URI, whitespace or mixed-case
  alias accepted in place of the canonical address.
- Fee rate1000 atoms/kB; exact total fee at most100000 atoms, including any dust
  remainder. No estimator, fee selector, subtraction from recipient amount or
  subsidy from pool earnings. Amount and every checked sum are in integer atoms
  and within `btcutil.MaxSatoshi` (2100000000000000).
- Native84 internal change only. Inherited transaction version1, sequence
  4294967295 on every input, locktime0, and SIGHASH_ALL. No RBF or alternate sighash.
- At most128 retained operation records, including abandoned records. At most one
  `prepared` record at once. At most2048 permanently retained input outpoints.
  No automatic history eviction, operation-ID reuse or finality-based unlocking.

The wallet tip is its owned synchronized observation, not a network attestation.
The adapter separately checks its concrete owned node and original authority.
Any wallet-not-synced, changing tip during preparation, missing source binding,
invalid profile or capacity condition fails closed before a draft is returned.

## 2. Proposed privileged API

The wallet fork does **not** import the new chain-root `walletwithdraw` journal
package. These structs/codecs are wallet-owned; the trusted adapter explicitly
maps/checks the same fields against the app contract.

```go
func (w *Wallet) CreateCandidateWithdrawals(ctx context.Context, bindingID string) (*CandidateWithdrawals, error)
func (w *Wallet) OpenCandidateWithdrawals(ctx context.Context, bindingID string) (*CandidateWithdrawals, error)

func (s *CandidateWithdrawals) Prepare(ctx context.Context, request CandidateWithdrawalRequest) (CandidateWithdrawalDraft, error)
func (s *CandidateWithdrawals) Lookup(ctx context.Context, operationID string) (CandidateWithdrawalRecord, error)
func (s *CandidateWithdrawals) Sign(ctx context.Context, operationID, draftDigest string) (CandidateWithdrawalSigned, error)
func (s *CandidateWithdrawals) Retain(ctx context.Context, operationID, draftDigest, txID string) error
func (s *CandidateWithdrawals) Abandon(ctx context.Context, operationID, draftDigest string) error
func (s *CandidateWithdrawals) Close() error
```

`bindingID` is the exact nonzero64-lowerhex app journal pin ID, supplied by the
concrete adapter, not browser data. The handle captures that binding and wallet
identity once and rechecks storage before returning a result. Mutable return
values are owned copies. Nil context is invalid; cancelled context and a closed
wallet/handle are rejected. Only one live handle owns a wallet's candidate seam.
Calls admit one operation fail-fast, and Close cancels/joins accepted work without
closing or reopening the borrowed wallet.

Create is explicit first initialization only, errors if the namespace exists, and
requires the caller's concrete first-use app intent. Open requires the existing
exact namespace and never creates it. The caller must have independently persisted
paired initialization/READY state; an established app marker with a missing wallet
namespace or journal is corruption, never a reason to call Create. Do not accept
an existing unpinned namespace by rewriting its binding.

Retain/Abandon are privileged internal-library methods, never wallet RPC, native
raw command or webview APIs. The wallet verifies exact handle/binding/op/digest
and its own state. It cannot independently infer app authorization. The concrete
adapter must hold an opaque reconciliation lease minted by the audited app journal
through the call; no caller boolean, exclusion list or claimant JSON can replace
that authority. This trust boundary is explicit rather than pretending the wallet
has read an account store it does not own.

## 3. Exact proposed value grammar and canonical bytes

All new JSON is compact UTF-8, object fields in the order listed below, no trailing
newline, duplicate/unknown fields, nulls, omitted fields, floating/exponent numbers
or alternate numeric spellings. New strings are ASCII. Use canonical lowercase
hex, no prefix. Numbers are JSON integers; only `change.output_index` may be
negative. Parsing must bound containers/strings before allocating their DTOs.
Canonical re-marshalling must equal the supplied bytes. Existing wallet files and
recovery JSON are unchanged.

`CandidateWithdrawalRequest` has these ordered fields:

1. `version`:1.
2. `operation_id`: nonzero64-lowerhex, generated by native before dispatch.
3. `recipient`: canonical address,1..90 ASCII bytes.
4. `amount_atoms`:1..2100000000000000, non-dust under inherited relay rules.

Prepare with an existing ID and byte-identical request returns the existing draft
without address allocation. A different request for that ID conflicts. An abandoned
ID is never revived. A retained ID is discoverable via Lookup; it is not a new
preparation. An ID is scoped to one binding and wallet, never silently rebound.

`CandidateWithdrawalDraft` is the following ordered object:

| Field | Exact rule |
| --- | --- |
| `version` | 1 |
| `binding_id` | handle's nonzero64-lowerhex binding |
| `operation_id` | request's nonzero64-lowerhex ID |
| `recipient` | request canonical address |
| `recipient_script` | canonical lowercase hex of the exact decoded standard script, at most34 bytes |
| `amount_atoms` | exact requested recipient amount |
| `recipient_output_index` | 0 or1, exact recipient role in the final sorted outputs |
| `fee_rate_atoms_per_kb` | 1000 |
| `fee_ceiling_atoms` | 100000 |
| `min_confirmations` | 1 |
| `tip_hash` | nonzero64-lowerhex wallet sync block hash |
| `tip_height` | integer0..2147483647 |
| `tx_version` | 1 |
| `input_sequence` | 4294967295 |
| `lock_time` | 0 |
| `sighash_type` | 1, SIGHASH_ALL |
| `inputs` |1..16 ordered Input objects, in final BIP69 transaction order |
| `total_input_atoms` | checked sum of inputs, positive and <=MaxSatoshi |
| `change` | allocated native84 internal Change object, even if no change output |
| `fee_atoms` | checked input sum minus all outputs,1..100000 |
| `unsigned_tx_hex` | canonical no-witness unsigned transaction serialization, all scriptSigs empty |

An Input object has ordered fields `txid`, `output_index`, `atoms`, `script`,
`branch`, `index`, `block_hash`, `block_height`, `coinbase`. Txid/hash are lowercase
64hex; vout is uint32; atoms positive and <=MaxSatoshi; script is exactly22 bytes
in lowercase hex and structurally `0014` plus20-byte pubkey hash. Branch is0 or1,
index0..4095. Purpose84/coin0/account0 are fixed by the contract, not selectable.
Block height is0..tip_height; block hash nonzero; coinbase is bool. The wallet must
prove the exact script belongs to that derivation path using its own address
manager and transaction store; the path is not claimant authority. Duplicate
outpoints are rejected.

A Change object has ordered fields `address`, `script`, `index`, `output_index`,
`atoms`. Address is canonical native84 P2WPKH; script exactly22 bytes; index0..4095
is the actually consumed internal index. With retained change, output_index is0
or1 and atoms positive/non-dust. Without a change output, output_index=-1 and
atoms=0, but the allocated address/script/index remain present. Upstream
`txauthor.NewUnsignedTransaction` calls NewScript once on a successful funding
pass even when zero/dust change is discarded. Retrying a saved draft must not
allocate again, and abandon never rolls back that committed address cursor.
Recipient and change may have the same script, including equal amounts. After
BIP69 sorting, assign the recipient role to the lowest output index matching the
exact recipient amount/script; any retained change takes the remaining output
index and must match its exact allocated script/amount. This makes identical
outputs unambiguous without changing their transaction bytes. Do not use the first
TxOutsEqual match independently for both roles. With one output, the recipient is
index0 and allocated-but-absent change is index-1.

`DraftDigest(draft)` is lowercase SHA256 of
`"SLUG candidate withdrawal draft\x00v1\x00" || LE32(len(canonicalDraft)) || canonicalDraft`.
The digest is outside the Draft object, avoiding self-reference. Length is bytes.
This is a proposed byte contract to freeze before independent derivation; no
expected hash has been generated here.

`CandidateWithdrawalRecord` ordered fields are `version`, `state`, `draft_digest`,
`draft`, `retained_txid`. Version1. State is exactly `prepared`, `abandoned` or
`retained`. retained_txid is empty for prepared/abandoned and exact64-lowerhex for
retained. It must equal the no-witness transaction ID derived from the saved
unsigned bytes; native84 witness signing does not change this ID. No signed raw
bytes or app dispatch status are stored in this wallet record.

`CandidateWithdrawalSigned` is transient and has ordered fields `version`,
`operation_id`, `draft_digest`, `txid`, `raw_hex`; version1, exact IDs as above,
canonical bounded witness transaction bytes. It is returned only to the trusted
adapter after successful local verification, never to the webview or a generic
RPC. It is not a durable authorization, mempool receipt or confirmation.

Caps: request512 bytes; canonical draft16384 bytes; record32768 bytes; unsigned
raw1024 bytes; signed raw4096 bytes. Hex caps are twice the raw cap. The analytical
transaction maximum is740 unsigned bytes (10+16*41+43+31), and at most2486 witness
bytes with16 worst-case109-byte P2WPKH witness stacks plus the2-byte marker/flag.
The larger caps leave framing margin without permitting extra inputs, outputs,
script types or witness items. Input scripts are22 bytes; recipient scripts<=34;
strings/arrays retain their individual bounds. These are byte-contract limits,
not a promise about allocator overhead or the entire Bolt file size.

## 4. Selection and atomic unsigned preparation

Read current wallet sync readiness/tip, then acquire the candidate operation gate
and new-address exclusion outside any account lease. Use one explicit wallet DB
transaction for validation, candidate record/reservations and change allocation.
No node/RPC call occurs inside it.

Enumerate at most4096 mined-unspent credit rows, incrementing visited count before
lock, scope, maturity, pending-spend or reservation skips. Do not enumerate unmined
credits because minConf1 excludes them. A4097th row is capacity, not truncation.
Validate raw row framing before decode; before decoding a previous transaction,
require its raw length<=4MiB and cumulative decoded bytes<=16MiB. Count each actual
decode, including repeated work; caching a validated same-parent record can avoid
another decode. Check context during enumeration. Copy only the native84 22-byte
scripts and needed scalar/path data; never retain slices backed by full decoded
transactions for thousands of credits. Retain only a bounded best16 candidate
set while scanning.

The currently inherited fetchCredits limit counts appended results after skips,
not rows visited, and it decodes whole previous transactions. It cannot be used
unchanged as proof of this work/memory bound. Add a narrow bounded enumerator or
an explicit bounded mode; preserve its existing callers and unlimited behavior.

Eligible credits must be owned native84/account0, recognized as unspent by the
concrete wallet ledger, not spent by an unmined transaction, not under a foreign
wallet lease, not in another prepared reservation or any permanent retained input
index, and sufficiently confirmed/mature at the exact wallet tip. Existing
in-memory LockOutpoint restrictions also apply. Reject inconsistent stored credit
amount/script/path or sums; do not skip corruption as though it were no money.

Sort eligible credits by atoms descending, then displayed txid bytes ascending,
then output index numerically ascending. Select the shortest prefix sufficient
under inherited `txauthor.NewUnsignedTransaction` fee rules, at most16. If all16
are insufficient, report insufficient funds for this bounded candidate route;
do not silently select a seventeenth input. Reuse the inherited conservative
native-witness estimator (witness weight3+109*n; base10+41*n+recipient output size
+31 native change bytes), relay dust check and integer fee calculation.

Use the same DB transaction's native84 change source. Do not call public
CreateSimpleTx or the empty-input FundPsbt path, and do not call a public helper
that starts another wallet DB transaction from inside this one. Reuse their
internal txauthor/source logic. Final BIP69 sort happens once before persistence;
reorder the saved prevout metadata to match final input order. The transaction
uses version1/final sequences/locktime0. Check exact input/output sums, recipient
and change roles, fixed fees/caps, and tip readiness before committing. Both
unsigned bytes and change/reservation records commit together. An error rolls
back all these changes, including any provisional change allocation.

An uncertain DB commit poisons this live handle. Reopen must recover one complete
original draft or absence, never regenerate while the same handle is uncertain.
The adapter's durable intent distinguishes a first attempt from an established
missing component. A successful existing-draft lookup is independent of later
chain progression and returns its original dated tip, not rewritten metadata.
Fresh eligibility is rechecked separately before signing.

## 5. Same-DB namespace and audit

Proposed top-level bucket `slug-candidate-withdrawal-v1`; it is additive and does
not migrate the address-manager schema or rewrite recovery metadata. Required
entries: `meta` is a canonical JSON value; `operations`, `prepared_inputs` and
`retained_inputs` are nested buckets. No other entry is allowed.

- `meta` has ordered fields `version`, `binding_id`, `identity`, `record_count`,
  `active_operation_id`. Version1; count0..128; active ID empty or a nonzero64hex
  prepared ID. Identity is an ordered object `profile`, `network`, `genesis`,
  `root_public_key`, `gym_public_key`, `gym_id`, copied from the retained validated
  profile, not the caller. Root key is canonical public extended key<=128 ASCII;
  gym key is compressed66-lowerhex; gym ID64-lowerhex. All fields must equal one
  of the two exact published profiles; there is no arbitrary-identity constructor.
- `operations`: key=32 decoded operation-ID bytes; value=the canonical Record.
  All operation IDs remain present; abandoned records count against128.
- `prepared_inputs`: key=32 wire-order transaction-hash bytes plus LE32(vout),
  value=32-byte active operation ID. Exactly the active prepared draft's inputs,
  at most16. No expiry or inferred release on a reorg/time change.
- `retained_inputs`: same36-byte outpoint key; value=32-byte operation ID plus
  32-byte draft digest plus32-byte retained transaction ID (decoded display hex
  bytes for these value IDs). Exactly all retained records' inputs, at most2048.
  Values are immutable. No deletion/release API or guessed confirmation threshold.

On Create/Open, validate bounded records and complete record/index correspondence:
exact metadata count; one-or-zero prepared; every prepared input belongs exactly
to its record; every retained input belongs exactly to a retained record; no
cross-operation overlap or orphan index. Prepared and retained indexes are
disjoint. Unknown/nested/malformed entries and missing required buckets are
corruption. Sum encoded operation values before copying and cap at4MiB; indexes
have exact lengths/counts. The physical DB size/compaction is not this logical cap.

Selection in the new seam always honors both indexes. Ordinary candidate wallet
coin selection must also exclude these reservations if it can share this wallet;
no candidate writer may bypass them using a generic funding/sign API. This is a
local safety rule, not a consensus lock and not control over an exported wallet
copy. Pre-Set68 binaries do not understand the additive namespace; the paired app
version/READY marker must fail closed on downgrade rather than promise permanent
exclusion under arbitrary old software.

## 6. Scratch signing and concrete-journal reconciliation

Sign accepts only the saved operation ID and matching digest, never caller raw
transaction or input metadata. It rechecks profile, original saved draft,
current owned inputs/reservations, synchronized wallet tip and candidate limits.
It uses the existing context-aware short unlock lease, validates selected previous
records under the same16MiB/4MiB bounds, and signs a copy of the exact unsigned
transaction with existing native P2WPKH SIGHASH_ALL machinery. Signing and script
verification are bounded to16 inputs. Use the existing signature engine and
standard verification flags. Strip witness afterward and compare byte-for-byte
with the saved unsigned transaction. Check exact output/fee/txID and canonical
witness framing. Context cancellation/wallet stop after work suppresses the result.
No signing path writes raw signed bytes, inserts an unmined transaction or sends.

Only the trusted native/app workflow may call Sign after approval of this exact
draft and the action's original Withdrawal check. The wallet has no independent
account authority and does not claim that a raw library caller proves a human
review. It offers no arbitrary message/PSBT signer through RPC.

After scratch signing, the app performs its final original Withdrawal fence
around the **app journal's** signed-byte commit. This is the sole durable signed
authorization. A guard inside a walletdb.Update callback would not fence that
method's later commit, and is not part of this design. No account lease is held
while Sign or any wallet DB method runs.

The paired adapter then acquires the concrete journal's opaque Reconciliation:
original open-store/pin/lifetime bound, exact operation/draft/input tuple, and
kind retain-signed or abandon-unsigned. Its Check must be synchronous and cheap,
without new disk/network/lock acquisition, and the adapter holds its exclusive
operation permit through the wallet mutation. The wallet does not import that
journal; the concrete adapter validates/matches it and calls only the ID/digest
bound privileged method. It must not substitute an interface supplied by a client.

Retain requires a matching prepared record, exact digest and exact transaction ID.
The adapter proves a durable exact signed app record before invoking it. Wallet
retention atomically converts all prepared reservations to permanent retained
entries, updates state/retained_txid, and clears active ID. Repeat Retain on the
same tuple is idempotent; any different txID/digest conflicts. It neither stores
signatures nor queues broadcast.

Crash after the app signed commit but before Retain leaves the original prepared
wallet reservation active, blocking a new draft. On reopen the concrete app journal
is audited first, then that exact Retain reconciliation completes before selection.
Missing/corrupt/uncertain established app state never clears the reservation.

Abandon is allowed only after the concrete app journal has durably committed its
original-authorized unsigned-abandon transition, proves no signed or uncertain
signed commit exists, and the signing task is joined. It atomically changes
prepared to abandoned, removes only its prepared index and clears active ID.
It leaves the consumed change cursor and tombstone. Repeated exact abandon is
idempotent; retained can never become abandoned. A cancelled task, empty caller
list, missing transaction lookup or elapsed lease time is not abandonment authority.

For any app commit uncertainty, the wallet reservation remains prepared/retained
until exact journal reconciliation. A live poisoned wallet/journal owner must be
closed and reopened before retry, without new operation ID/address allocation.

## 7. Context, locks and error outcomes

All APIs check nil context, normal profile and immutable argument bounds before
waiting or mutation. Candidate owner admission is fail-fast (`ErrWithdrawalBusy`)
and there is no background lock waiter abandoned on cancellation. Preparation
acquires candidate/newAddrMtx/DB resources outside account leases; use context
checks during a bounded TryLock wait or fail-fast contention. Signing uses
holdUnlockContext and checks the captured wallet run after cryptography. The
borrowed wallet cannot unload until this handle's accepted operations have joined.

walletdb.BeginReadWriteTx has no context-aware acquisition; do not claim that
cancelling context interrupts an already blocked OS/database operation. Acquire it
outside account authority, check cancellation as soon as acquired, roll back, and
join it. No detached goroutine may retain the DB or wallet. To keep shutdown bounded
under ordinary conditions, no network, user dialog or hashing is permitted in any
wallet DB transaction. Local storage failure can still require visible cleanup
failure rather than a fabricated successful cancellation.

Close cancels/joins the seam; it does not abandon a durable prepared payment,
release permanent exclusions, mine, send, or close the borrowed wallet. Root's
walletRuntime/child lifecycle closes the handle before unloading wallet storage.
The app's reset flow must revoke/invalidate before joining these operations, with
no account callback waiting on them.

Proposed stable sentinels: ErrWithdrawalInvalid, Profile, Busy, Closed, NotFound,
Conflict, Capacity, Unavailable, Corrupt, Storage, OutcomeUnknown. Prefix each with
`ErrWithdrawal` in Go. Cancel/deadline errors remain recognizable. Invalid covers
closed grammar/unsupported address/dust; Unavailable covers unsynced, stale/spent
inputs, locked wallet for Sign or insufficient eligible funds. No error includes
raw PSBT, signature, credential, private key or arbitrary backend text. A failed
or uncertain persistence returns no actionable replacement draft/signature. An
uncertain mutation poisons the handle, including final observation errors after a
possible commit. Lookup after a clean reopen determines exact state.

## 8. Reuse and acceptance inventory for later freeze

Reuse source-backed mechanisms: wallet/createtx.go's constant/make input source,
addrMgrWithChangeSource and validateMsgTx; txauthor.NewUnsignedTransaction and
AddAllInputScripts; txrules.FeeForSerializeSize/CheckOutput/IsDustOutput;
btcutil/txsort.InPlaceSort; waddrmgr native84 derivation/transaction OnCommit cursor
updates; wallet/private_operation.go's holdUnlockContext; bounded ledger lookup
adapted from wtxmgr's existing credit loop. Public FundPsbt itself nests DB access
and its no-input branch signs, so it is not the same-DB preparation implementation.
A persisted PSBT is unnecessary: fixed unsigned bytes plus exact owned prevouts
are sufficient for the existing signing machinery and reduce the format surface.

Independent future cases should cover all4 recipient types,1/16 input bounds,
amount/tie ordering, BIP69 reorder and equal recipient/change script+amount roles,
fee-ceiling refusal, dust/no-change with cursor
consumption, exact unsigned/signed bytes and signatures, native84 path ownership,
4096/4097 visited rows including skipped/locked entries,16MiB aggregate decode
refusal, request/digest mutation, duplicate/reopen behavior, rollback before/after
change, scratch signing cancellation, app commit uncertainty, retain-gap restart,
prohibited retained abandon and reorg/time passage without exclusion release.
A normal owned-node fixture withdrawal must later prove exact external receipt and
no second debit after lost response/retry. No expected byte or outcome has been
produced by this proposal; source/input locks and independent producer review come
after the contracts are frozen.
