# Set70 — own-wallet activity in the existing wallet section

Frozen candidate engineering contract, November 19, 2026. Root reviewed the
source layouts, independent review findings and sizing producer before outputs
or implementation. The external freeze record preserves proposal provenance.
Set69 source and its actual harness remain unchanged. This is read-only wallet functionality, not a
new accounting, custody, transfer, fee or finality policy.

## Result and limits of the claim

Show a signed-in Pool Pilot user a bounded recent capture of transactions that
the already-owned wallet records as crediting or debiting it. Include ordinary
incoming payments, outgoing payments and self-payments, rather than treating
pool settlements or the latest withdrawal journal entry as the whole wallet.
Pages and transaction details read the same immutable capture. Explicit Refresh
creates a new dated capture, including updated wallet-recorded confirmations.
Keep the current wallet section and existing navigation. There is no separate
selected-transaction observation task or RPC route in this set.

This does not change wallet balances, select coins, allocate addresses, sign,
submit, abandon, replace or rebroadcast a transaction. It does not change pool
earnings/payment records, withdrawal authorization, imported recovery state or
any chain rule. All amounts and ownership facts are local wallet observations,
not a portable ownership proof. A wallet-recorded confirmation is not result
finality, absence of conflicts, current spendability or a guarantee of payment.

Only the current two published fixture account/wallet identities and existing
Pool mode are enabled. No schema migration, new installed wallet, provider,
real custody, public endpoint or generic RPC capability is introduced.

## Source findings that constrain the implementation

The current `listtransactions` API is not a suitable capture authority:

- Its amounts/fees are float64. One transaction can emit many rows. A spent
  credit may produce a synthetic send row; change outputs are omitted.
- `Wallet.ListTransactions` increments its internal count before a transaction
  and again when result rows are nonempty. Its count is not a dependable number
  of unique returned transactions.
- `TxStore.RangeTransactions` constructs the entire unmined set or a whole
  block's transaction details before invoking the early-stop callback. A small
  requested count or HTTP response cap does not bound that backend work.
- `gettransaction` also returns float totals. Its send detail is an aggregate
  with an acknowledged unset address/output index. Unknown fee can appear as
  zero, and `walletconflicts` is always empty because conflicts are not saved.

Do not fix or change these inherited RPC methods in this set. Do not use their
floating numbers, row categories, count behavior, zero fee, empty conflicts,
trusted/abandoned defaults or aggregate send output as new authority. The
existing integer `TxDetails` credit/debit records and raw transaction bytes are
the appropriate underlying inputs, but their inherited batch iteration needs
a genuinely bounded reader.

## Narrow private read-only wallet seam

Add one wallet Go I/O method; its exact private types are specified below:

```go
func (w *Wallet) CaptureOwnActivity(ctx context.Context) (OwnActivitySnapshot, error)
```

The fixed-limit snapshot is owned data, not a live database handle, callback or
public RPC result. Internal `wtxmgr` support enumerates bounded raw record
metadata and resolves the selected records under one read transaction. A narrow
read-only manager helper exposes the persisted sync stamp and bounded public
root/gym identity from the same supplied manager bucket. It accepts the known
schema 9 only, checks ciphertext lengths before public-only decryption, and
never reads/decrypts the private recovery payload or performs KDF/unlock work.
It does not change the manager schema or return private keys.
There is no caller-supplied namespace, policy, query expression or larger limit.

The desktop retains the concrete installed wallet identity from the current
Pool child. It uses `walletRuntime.mu.TryLock` only around the bounded local
read, rejects a closed/unsynced/disconnected wallet, and releases the lock before
any network work. The child task owns lifecycle admission so Close cannot unload
that wallet while admitted work remains. No account lease spans lock acquisition,
database reads, sorting, raw transaction processing, node/wallet RPC or joins.

All transaction bytes, metadata, credits/debits and the persisted manager sync
stamp must be copied from **one walletdb read transaction**. Sampling only the
in-memory manager tip before/after separate reads is insufficient: mempool
transactions can change without changing the tip. This atomic local snapshot
avoids adding a durable mutation counter or relying on the global notifications
channel. It makes no claim to represent later state at publication time.

The owned node's exact hash/height is sampled before and after the local read,
outside wallet/account locks, using its existing pinned private connection.
The retained wallet must report synchronized before/after, and the persisted
snapshot stamp, live wallet stamp and both node samples must all match. A
disconnect, changed hash at the same height, changed height, cancellation or
view revocation discards the prospective capture. Same-tip wallet mutations
after the atomic snapshot do not mutate the capture; Refresh creates a new one.

No header PoW is needed to read local wallet activity. No raw-block scan, full
UTXO inventory, broad `VerificationState`, or inherited `RangeTransactions`
batch allocation is permitted in this interactive path.

The database interface is not context-aware. Its finite read/rollback must be
joined on cancellation; a deadline does not permit unloading the wallet while
an admitted read still owns the database. Context is checked before entering
the read, at each bounded enumeration/parse step and before returning. Do not
claim that cancellation can preempt an underlying database lock or filesystem
operation.

### Concrete storage seam

Use a direct read cursor over `wtxmgr` bucket `m`, then the existing height-ordered
block metadata bucket `b` in reverse, not the inherited details-range helpers or
a scan of every `t` record. Scan at most 4096 unmined metadata rows to sort their
recorded timestamps. Mined block keys are exactly 4-byte big-endian heights;
within each visited height, sort its bounded metadata txids by canonical
displayed-hex order (compare reversed hash bytes without allocating hex strings
for every comparison). Skip txids already represented by unmined/newer records.
Stop at 256 selected distinct IDs plus one distinct older metadata witness for
`has_older`, or exhaustion. If unmined metadata alone has more than 256 records,
there is no need to visit `b`.

Charge every visited unmined row, block row and block hash slot against an
aggregate 8192-slot work limit, plus one refusal probe. Before copying/sorting a
block's hashes, ensure its full count fits both the 4096 per-block bound and
remaining visit budget. Pathological duplicate history can hit capacity; ordinary
long mined history does not require scanning all older records. A block's txids
must be unique. Only selected records are fetched from `m`/`t`; exact mined keys
are 68 bytes (txid, height, block hash) and unmined keys 32 bytes. Both values
begin with an 8-byte recorded Unix timestamp, then raw transaction bytes. No
labels are read. Older blocks, unselected transactions and unindexed `t` rows
are not claimed audited; no repair or broad consistency pass runs here.

The selected mined record's block metadata must agree with its exact height/hash,
have a bounded well-formed stored transaction-hash list, and contain the selected
txid. Check lengths and counts before iterating; do not invoke the inherited
block parser that allocates from a stored count. Validate selected credit and
debit prefixes with at most the selected transaction's output/input count plus
one refusal probe. A generic unbounded credit/debit iterator is insufficient.

Mined debit values contain an exact previous-credit key. Check that its outpoint
matches the selected raw input and its amount agrees with the referenced owned
credit. Unmined debits are not stored: derive them with at most two bounded
Gets per raw input through the existing unspent index or unmined-credit
bucket, validating that exact outpoint and amount. This is the same ownership
source used by existing TxDetails, with bounded access and stronger consistency
checks. Do not scan other wallets or parse every previous transaction.

The unspent index deliberately means not spent by a **mined** transaction.
It includes outputs spent by this or another unmined transaction. Do not filter
debit ownership through the unmined-spender (`mi`) map, output locks, reservation
indexes or spendability. Do not enumerate `mi`: it may contain multiple spender
hashes and is not a complete conflict proof. Two competing unmined records can
both show their recorded own-input values. Never sum history rows into a wallet
balance, available amount or conflict-free total. Refresh may remove a record
after the existing wallet's normal conflict handling; this read performs no
conflict repair.

The persisted manager sync helper accepts only the manager bucket from that
same read transaction and returns owned hash/height data. Current on-disk sync
grammar is the existing 36- or 40-byte record. Schema/profile selection remains
the current retained wallet's identity, not a caller-controlled interpretation.

## Fixed candidate bounds and ordering

- At most 4096 unmined metadata rows, 4096 hashes per visited block, and 8192
  aggregate metadata row/hash slots in one local read, plus one refusal probe.
  Cursor keys, metadata sizes, timestamps and declared counts are checked before
  allocation. Capacity refusal occurs before a copy that exceeds the limit.
- At most 256 distinct latest transaction IDs retained. Unmined records come
  first, sorted by wallet recorded time descending then txid ascending. Mined
  records follow by height descending then txid ascending. This is display order,
  not consensus transaction ordering. Existing TxDetails precedence selects an
  unmined occurrence first, otherwise the latest indexed mined occurrence of a
  txid. This uses the wallet's existing block index, not unindexed historic `t`
  rows; malformed/duplicate entries at a visited height fail as corrupt.
- The reader may scan bounded metadata to find those latest IDs, but parses
  raw transactions only for the selected records. Retain `has_older` when older
  distinct metadata records exist; label this a recent bounded view, not complete history.
  Exceeding the metadata work bound is a visible capacity refusal, not a partial
  trusted capture. Do not silently skip an unsupported selected transaction.
- Each selected raw transaction is at most 256 KiB, at most 256 inputs and 256
  outputs; aggregate selected raw bytes at most 8 MiB. Prewalk canonical wire
  framing, count limits, script/witness lengths and allocation budget before
  MsgTx decoding. Additional parsing limits are 128 witness items per
  input, 4096 witness items per transaction, 10 KiB per input signature script or
  output script, and 256 KiB per witness item (also constrained by the whole raw
  byte limit). Canonical varints, exact marker/flag grammar, no trailing bytes
  and no superfluous witness encoding are required. These are candidate display
  capacity limits, not new consensus rules. An over-limit selected transaction
  produces capacity, not an invented summary. Public summary rows are capped
  at 512 KiB for the whole capture.
- One active activity operation (capture or a synchronous bounded detail read)
  and one completed immutable capture per
  child. Reserve capacity before admission; a successful replacement invalidates
  the prior capture. Failure/cancellation does not silently turn its partial
  result into the current capture. At most 8 rows per local page.
- Whole capture action 30 seconds; local scan checks cancellation at each record
  and before publication, each existing node-tip RPC at most 5 seconds. No wallet
  history RPC is used. No waiting retry loop under a lease, automatic network
  retry or owner substitution.
- Request 1024 bytes, summary/page response 16384 bytes, selected detail
  response 98304 bytes, complete summary capture 512 KiB plus private raw 8 MiB.
  Retain raw bytes and bounded credit/debit indices, not decoded transactions or
  all output descriptions. Parse one selected transaction at a time; details
  derive one immutable projection from its retained bytes and indices. Fixed
  count limits separately bound metadata and slice overhead. Replacement permits
  one old and one prospective capture, never a third; page/detail copies are
  bounded by their response caps. Reserve 32 MiB of logical work budget before
  admitting a new capture/detail owner; the byte/count checks remain mandatory.
  The source-only budget checker below accounts
  for that overlap, the decode arena and reserialization scratch. These are explicit
  work/data bounds, not a total-process-RAM claim.

The reader validates selected TxID against canonical serialized transaction
bytes, unique debit input indices and credit output indices, matching credit
amounts versus raw output values, bounded nonnegative amounts and checked sums.
Each selected transaction must contain at least one wallet-recorded credit or
debit. Return owned copies; never return database-backed slices or retain a read
transaction while paging or awaiting UI input. Reject malformed selected records
without repair. Historical offscreen data are not claimed independently audited.

## Exact atom semantics

All public monetary fields are integer atoms, represented as safe JSON integers.
Use checked integer arithmetic only. Each amount and sum is within the existing
MaxMoney bound, so the signed net is within ±MaxMoney and therefore within the
existing JavaScript safe-integer range. Never parse a float and multiply/round
by 1e8. Frontend decimal SLUG formatting is integer/string arithmetic.

For one transaction, let D be the sum of all wallet-recorded debit amounts, C
the sum of all wallet-recorded credit amounts, and K the sum of credits marked
Change. Define:

- `received_atoms = C`: outputs recorded as owned, **including change**.
- `spent_atoms = D`: owned input value consumed, not an external-recipient total.
- `change_atoms = K`: the recorded change subset of C.
- `net_atoms = C - D`: the net effect on this wallet's recorded funds.

Show net change prominently. Gross fields must explicitly say “Received,
including change” and “Spent from wallet inputs”; do not present a change return
as external income or infer a counterparty from the sign. A self-payment can
therefore have both gross sides and a net of minus its fee. Mixed-wallet input
transactions can have exact own net while the total transaction fee is unknown.
Spent flags on old credits do not create a new send row in the old transaction.

`fee_atoms` is null unless this is a noncoinbase transaction and every input is
represented by one unique wallet debit. Only then compute D minus the sum of
ALL raw transaction outputs, check the nonnegative bound, and publish the exact
integer (including a genuinely known zero fee). Otherwise label “Fee unknown.”
Do not copy gettransaction.Fee or turn its omitted/zero value into known zero.

Coinbase remains explicit. Confirmation count or the existence of a wallet
credit is not spendability; the view grants no permission to spend immature,
reserved, locked, conflicted or otherwise unavailable outputs.

## Public capture and details

Reuse the original `ManifestViewPin` plus exact source binding and retained
wallet root/gym identity as `WalletActivityBinding`. Do not substitute pool
recipient identity for the full wallet. Session tokens, DB paths and credentials
never enter it. Existing original helper/view generation validation remains.

Capture metadata contains version 1, captured-at timestamp, exact wallet and node
hash/height, retained count and `has_older`. A fresh native-preknown JobID is the
lookup identity; it is scoped to the original view and child lifetime, not a
durable account authority or file certificate. Repeating Begin for that same
request recovers its status; it must not start another capture after a lost reply.

Each transaction row contains TxID, raw-byte SHA256 for exact local correlation,
wallet recorded time, coinbase flag, wallet-recorded block hash/height/time or
null for unmined, wallet-recorded confirmations, the four atom totals, nullable
fee, input/output counts and owned input/output counts. The atomic snapshot's
sync height defines these captured confirmations. UI states are “Unconfirmed
wallet record” or “Wallet records N confirmations,” dated to the capture.
Unmined does not assert actual mempool presence; no word “final” or settled title
is inferred from a numeric depth. Conflict absence is always unknown.

Details require exact membership `(original ViewID, JobID, TxID)` in that same
retained capture. They contain the same immutable row plus bounded output
descriptions: output index, integer atoms, wallet-recorded ownership/change flag
and an address only when one unambiguous supported script address can be encoded.
Unknown/nonstandard scripts get an explicit no-address presentation, not a
fabricated destination. An output without a recorded credit is “not recorded as
owned,” not a proof that somebody else owns it. The change flag implies recorded
ownership. No raw transaction bytes, raw script, signing object or
input funding selector is exposed to the webview. Browser-supplied amounts,
addresses, ownership flags and arbitrary txids cannot select data.

New closed-family commands can mirror the current pool history route:
`wallet_activity_snapshot`, `wallet_activity_begin`, `wallet_activity_job`,
`wallet_activity_page`, `wallet_activity_detail`, and `wallet_activity_cancel`.
Initial load and explicit Refresh use the same Begin operation with a fresh
native-preknown JobID. Final request/response DTO field order, nullable
shapes, safe integers and byte limits are frozen before independent wire vectors.
No generic map, caller RPC method or arbitrary passthrough is added.

## Explicit Refresh and dated wallet facts

Every displayed activity record comes from the private atomic wallet DB
snapshot. No gettransaction or listtransactions call supplies records, amounts,
details, fees or confirmation updates. Existing wallet RPC methods and their
restricted allowlist remain unchanged.

Refresh admits one new capture under the current original view. It repeats the
bounded atomic read and existing node/wallet tip guards. Only a successful final
publication replaces the completed capture. The old view remains visibly dated
while refresh is running or fails; it must not be relabeled as current. A new
capture invalidates old page/detail handles and clears any old selection.

The refreshed capture may differ because wallet records changed at the same tip,
new blocks arrived or a reorganization occurred. Its confirmation count is still
the wallet's report at the new captured tip, not an independent chain-membership,
mempool, conflict-absence or finality proof. A transaction absent from the bounded
recent capture is not asserted absent from the wallet or chain. Refresh cannot
erase immutable pool payments, cancel or resend a withdrawal, or change a prior
capture's facts. A separate selected observation API is deferred.

## Original-view and lifecycle rules

All entry, paging, selection, status publication and final disclosure use the
original View capability, account token and parent epoch. D72 permits viewing
during the reset hold; this adds no Withdrawal or RecoveryExport bypass. No
replacement token supplier or refreshed view may rescue an old action.

Reserve bounded child work before starting goroutines. If the outer admission
fence fails, cancel/release the task and do not start its backend. Status retries
use the preknown JobID. Late replies and completed payloads are discarded if the
original view/session expires, resets, logs out or closes. Publish only owned
bounded data under a short final fence; no I/O or joins occur there.

Capture and backup/withdrawal lifecycle operations must not
race wallet closure. Reuse the existing stop/backup/withdrawal drain discipline:
Cancel stops the admitted task; reset/logout/Close cancel and join it before
releasing wallet/source owners; backup must drain it before scratch/original
wallet coordination. Read-only activity does not stop mining by itself, but
cannot overlap an exclusive backup lifecycle. A busy owner reports typed busy,
not blank success. Clearing a view clears all activity handles and cached data.

Retained pages are immutable original-capture data, not a continuously changing
cursor into live RPC results. `after` is a local bounded offset, limit 1..8;
Next/HasMore refer only to that capture's rows. `has_older` separately announces
history outside the capture. Never use page calls to silently query fresh wallet
rows or reuse another gym's capture.

## Qualification required before completion

Freeze the contract, exact source metadata and independent arithmetic/codec
input inventory before deriving expected vectors. Model received/spent/change/
net, self-payment, partial-input unknown fee, known zero/nonzero fee, coinbase,
duplicate/index errors, integer limits and history ordering independently. Include
raw count/size bombs, whole-block/unmined iteration bounds and byte ceilings.

Prove sparse long-history captures stop after the latest selected block index
entries and do not scan the old `t` table. Include repeated old txids, large
visited blocks, unmined precedence, exact 256/257 boundaries, exhausted older
metadata and bounded refusal probes. The older witness proves only an indexed
record exists, not a fully parsed/audited transaction.

Prove atomicity under a same-tip mempool mutation, exact tip changes and reset/
expiry during blocked local work or RPC; cross-view/gym/selection refusal; lost
Begin reply with no duplicate capture; owned data and cancellation/Close joins;
no account lease or wallet mutex held during network work. Old RPC outputs and
unrelated profile/schema behavior remain unchanged.

Use copies of the already-qualified Set68 funded wallets/chain to capture both
incoming reciprocal payments, outgoing payments, original pool payout and change
from original integer records. Capture independent existing raw transactions and
integer credit/debit baselines before new projection code is executed; no fresh
payment/mining is necessary. Distinguish actual old-source inputs from modeled
edge cases. The original source files remain byte-identical.

The exact package exposes the new capability in the existing wallet section,
with signed-out blanking, original-view handles, empty/capacity/unknown states,
dated captures and explicit Refresh. Required normal/race/profile, source
bindings, affected regressions and per-set smoke remain independent gates.

## Exact source anchors read

- `slugwallet/rpc/legacyrpc/methods.go:818`: gettransaction, integer sums converted
  to floats, aggregate send detail and walletconflicts “Not saved.”
- `slugwallet/rpc/legacyrpc/methods.go:1280`: listtransactions account wildcard.
- `slugwallet/wallet/wallet.go:2271`: per-output rows, omitted change, synthetic
  sends for spent credits; `:2430`: count/from behavior; `:2703`: GetTransaction.
- `slug/btcjson/walletsvrresults.go:135` and `:235`: actual float/nullable DTOs.
- `slugwallet/wtxmgr/query.go:19`: integer credit/debit records; `:258` and `:289`:
  inherited unbounded pre-callback materialization; `:373`: RangeTransactions.
- `slugwallet/waddrmgr/db.go:2214`: persisted sync stamp getter currently private;
  `waddrmgr/sync.go:76`: separate in-memory manager stamp.
- `slugwallet/walletdb/interface.go:16`: read transaction ownership/lifetime.
- `slug/desktop/pilot/wallet.go:277`: restricted RPC allowlist; `:363`: broad
  backup-only inventory comparison, not this bounded interactive capture.
- `slug/desktop/pilot/wallet_payout.go:77`: existing separate payout observation
  path, deliberately not duplicated for activity;
  `pool_payout_controller.go:138`: original-view capture/task pattern.

## Exact private API and data

These are ordinary owned Go values, not a JSON/file format or account authority.
Names and types are part of this proposed contract; there is no private RPC.

```go
func (w *Wallet) CaptureOwnActivity(ctx context.Context) (OwnActivitySnapshot, error)

type OwnActivitySnapshot struct {
    Version       uint32 // 1
    RootPublicKey string
    GymPublicKey  string
    GymID         string
    SyncedHeight  uint32
    SyncedHash    chainhash.Hash
    HasOlder      bool
    Records       []OwnActivityRecord
}
type OwnActivityRecord struct {
    TxID         chainhash.Hash
    Raw          []byte
    RecordedAtMS int64
    Block        *OwnActivityBlock
    Credits      []OwnActivityCredit
    Debits       []OwnActivityDebit
}
type OwnActivityBlock struct {
    Height uint32
    Hash   chainhash.Hash
    TimeMS int64
}
type OwnActivityCredit struct {
    Index  uint32
    Atoms  int64
    Change bool
}
type OwnActivityDebit struct {
    Index uint32
    Atoms int64
}
```

Empty Records/Credits/Debits are nonnil empty slices. A nil Block means unmined.
Credit/debit entries are sorted by their unique index. Raw is exact owned
canonical full serialization, including witnesses, not a hash-only substitute.
TxID is SHA256d of the nonwitness transaction serialization. The desktop's
`raw_sha256` is ordinary SHA256 of Raw, with no added domain or authentication
claim. All returned backing arrays are detached from the DB and one another.

The one wallet method performs all metadata, framing, index, ownership, amount
and block-consistency checks before returning. It needs no unlock and does not
require a backend/RPC call; the desktop applies live connection/sync/node-tip
guards separately. No method argument can replace the wallet, source or limits.
The desktop's bounded pure projector may defensively revalidate Raw and indexed
values but performs no further wallet/DB access. It retains one private capture,
not an exported reusable capability. There is no new detail lookup in the wallet.

Public identity reading is limited to the current profile's schema 9, standard
BIP32 mode, recovery version 1, exact Phase-A network/genesis, the bounded public
manifest and master-public-key ciphertext, and the persisted sync stamp. Public
manifest ciphertext is at most 65576 bytes, plaintext at most 65536; public root
ciphertext at most 168 bytes, root text at most 128. Validate canonical public
root and compressed gym key, their existing manifest agreement and GymID. Do not
read private payload bytes, enumerate derivation accounts/addresses, restore,
export, derive new addresses or migrate another schema. In-process loaded
manager state must agree with this public profile. The fixed four-scope profile
is already pinned by the retained wallet; this read does not audit its entire
address inventory. The current runtime independently matches the returned
root/gym tuple to its retained published fixture identity before disclosure.

Wallet errors are `ErrOwnActivityInvalid` for nil context, `ErrOwnActivityProfile`
for an unsupported normal/profile/schema, `ErrOwnActivityUnavailable` for a
closed owner, `ErrOwnActivityCapacity` for fixed limits, and
`ErrOwnActivityCorrupt` for malformed/inconsistent selected stored data.
`context.Canceled`/`DeadlineExceeded` remain distinguishable through errors.Is.
No caller receives partial records on error. Normal-profile refusal precedes
DB work. Existing APIs and error behavior remain unchanged.

### Exact read and allocation bounds

The existing `wtxmgr` binary integer order is **big-endian**, as fixed by
`wtxmgr/db.go`'s `byteOrder = binary.BigEndian`: all stored 8-byte recorded/block
Unix-second timestamps and amounts, and all 4-byte block heights, counts and
input/output indices use that order. Exact layouts are:

- `m`: key hash32; value received_seconds_BE64 || raw_wire_transaction.
- `t`: key hash32 || height_BE32 || blockhash32; same value as `m`.
- `b`: key height_BE32; value blockhash32 || time_seconds_BE64 || count_BE32 ||
  count consecutive hash32 entries.
- `c`: key hash32 || height_BE32 || blockhash32 || output_index_BE32; value
  atoms_BE64 || flags_byte, followed by an exact 72-byte spender-debit key only
  when spent. Bit 0 is Spent, bit 1 Change; all other bits must be zero.
- `d`: key hash32 || height_BE32 || blockhash32 || input_index_BE32; value
  atoms_BE64 || exact_previous_credit_key72.
- `u`: key hash32 || output_index_BE32; value height_BE32 || blockhash32.
- `mc`: key hash32 || output_index_BE32; value atoms_BE64 || flags_byte, where
  only bit 1 (Change) may be set. There is no optional spender key.

Each hash32 is the existing internal `chainhash.Hash` byte order, not ASCII hex;
canonical displayed txid/blockhash text reverses those bytes before lowercase
hex encoding. The raw transaction itself remains the existing Bitcoin wire
grammar: little-endian fixed integers and minimally encoded CompactSize counts
and lengths. Its unsigned output amount bits must fit nonnegative int64 and
MaxMoney. Do not apply database big-endian order to wire transaction parsing.
The manager's persisted sync record instead uses **little-endian** height32 ||
hash32, with an optional little-endian timestamp32 in the existing 40-byte form
(otherwise exactly 36 bytes). Manager version/mode/recovery-version words are
also the existing little-endian uint32 values. The public identity encryption
and manifest formats are unchanged; this set introduces no new storage codec.

Metadata visits count unmined rows, reverse block rows and all hash slots in
each visited block against 8192 plus one refusal probe. Check exact key sizes,
nonnil values, timestamp and mined-height bounds before retention. Copy at most
4096 fixed unmined metadata rows and one block's 4096 hashes, not all historical
values. A selected record fetch is one Get. Times are integer Unix
milliseconds in 0..253402300799999; stored seconds must fit before multiplying
by 1000. Historical times need not be earlier than the current capture clock.
Compare txid ties using lowercase displayed hex lexicographic order, not raw
little-endian storage order. Unmined precedence and latest mined occurrence
selection use the reverse block index as specified above. No whole mined-table
enumeration or per-txid `latestTxRecord` search is performed.

For a selected transaction with I inputs and O outputs (each 1..256):

- Mined: one raw-record Get, at most O+1 credit cursor
  positions, I+1 debit cursor positions, and at most I previous-credit Gets.
  At most O+2I+3 positions/Gets. Block metadata is already retained from the
  bounded selection phase, not fetched and rewalked for every transaction.
- Unmined: one raw-record Get, at most O+1 credit cursor positions, and at most
  two Gets per input: `u` then its `c` record, or `u` then `mc` when no `u`
  entry exists. A malformed present `u` value is corrupt, not absence/fallback.
  At most O+2I+2 = 770 positions/Gets. No unmined-spender-map reads.
- The maximum transaction read work is therefore at most 8193 +
  256×max(O+2I+3,O+2I+2) cursor positions/Gets, plus fixed public identity/sync
  reads and bucket opens. This conservatively also charges hash slots as cursor
  work. Each visited block has count 1..4096 and exact length 44+32×count, with
  matching metadata hash and unique txids. Copy one bounded hash array for its
  within-height ordering; reuse/release it before the next block. Context checks
  occur during enumeration and bounded sort comparisons. The inherited
  unbounded block parser is not called.

Credit keys/values: mined 72-byte key and 9-byte unspent or 81-byte spent value;
unmined 36-byte key/9-byte value. Only defined flag bits are allowed. Mined
debits are 72-byte keys/80-byte values; their previous-credit key must identify
the exact raw input outpoint and matching amount. That previous mined credit
must be spent, exactly 81 bytes, and its spent link must point back to this exact
debit key. An unmined input's present unspent (`u`) value is exactly 36 bytes and
must resolve to an exactly 9-byte unspent mined credit; a spent credit there is
corrupt. Missing/malformed referenced credit never falls back to `mc`. Unmined
credits are exactly 9 bytes with only the Change flag permitted. Unmined credit keys
resolve exactly the raw input's outpoint. Check every index/length before use.
Do not append a 257th indexed row or traverse a foreign prefix as matching.
The selected mined height must be at most the atomic persisted sync height.
Block metadata is a wallet DB record, not an 80-byte chain header or independent
chain proof. Coinbase has no debit records; duplicate raw input outpoints and mixed null
coinbase prevouts are corrupt. Raw output values and their sum must be within
0..MaxMoney, as must C and D. Credit amounts must equal their raw output values.

The raw parser walks canonical varints before generic wire decoding: 1..256
inputs and outputs; witness marker/flag exactly 00/01 when used; per-input
witness count <=128, total <=4096; scripts <=10240 bytes; each witness element
<=262144 bytes; raw <=262144 bytes and fully consumed. The witness flag requires
at least one input with a nonzero witness-item count; an item may contain zero
bytes. Other inputs may have zero witness items.
Unknown flags, zero input/output counts, nonminimal varints, negative output
values and trailing bytes refuse. Selected raw bytes
total <=8388608; the whole prewalk is bounded by those bytes and count limits.
No fixed 73/33-byte signature assumption is applied to ordinary history.

Retained data per capture has at most 256 records, 65536 credits and 65536
debits, plus 8 MiB raw and 512 KiB summary bytes. Process one decoded transaction
at a time; discard its parse arena/serialization scratch before the next.
During Refresh, one previous capture may coexist with one prospective capture;
no synchronous detail operation may overlap capture replacement. At most one
detail scratch with one selected raw copy is retained. Page calls retain at
most eight summary rows. No deep copy of all raw history for status/page/Begin
is allowed. The budgeting script reports these independent byte/count bounds
and conservative 64-bit logical allocation accounting, not DB mmap/GC/OS RAM.
It budgets up to 4096 unmined map entries plus 256 selected-ID map entries even
if an implementation combines them. The one older witness need not be retained
after setting has_older. It also uses a maximally JSON-escaped 256-character
synthetic authority origin when bounding wire bytes, without relying on the
narrower valid loopback alphabet.

## Exact public wire contract

Every object below lists fields in canonical marshal order. Go initialisms use
`ID`, `MS`, `SHA256` and `TxID`. All listed fields
are required; no omitempty. Parse accepts field order/JSON whitespace, but
rejects duplicate/unknown/missing fields, invalid UTF-8, trailing values,
unlisted nulls, exponent/fraction/negative-zero numbers and unsafe integers.
Marshal emits one compact object followed by exactly one transport LF. Existing
stable View/AuthorityPin validators and exact native expected bindings apply.
No decoded shape alone authenticates its account/source/wallet identity.

Common domains: Version=1; `ID` is 1..9007199254740991; JobID is a nonzero
lowercase 64-hex native-preknown value; txid/raw_sha256/block/tip hashes are
lowercase 64-hex (tip/block nonzero); all heights <=2147483647. CapturedAtMS is
1..253402300799999. Other times allow zero. Amounts are signed int64 JSON-safe
integers but only `net_atoms` permits negative values, bounded by ±MaxMoney;
all other atom values are 0..MaxMoney. Null fee is explicit unknown.

Ordered objects (Go exported names are their CamelCase equivalents):

| Object | Exact ordered fields |
|---|---|
| WalletActivityBinding | `view:ManifestViewPin`, `source_binding_id:string`, `root_public_key:string`, `gym_public_key:string`, `gym_id:string` |
| WalletActivityCapture | `version:uint32`, `captured_at_ms:int64`, `wallet_height:uint32`, `wallet_tip:string`, `node_height:uint32`, `node_tip:string`, `count:uint32`, `has_older:bool` |
| WalletActivityBlock | `height:uint32`, `hash:string`, `time_ms:int64` |
| WalletActivityItem | `txid:string`, `raw_sha256:string`, `recorded_at_ms:int64`, `coinbase:bool`, `block:*WalletActivityBlock`, `confirmations:uint32`, `received_atoms:int64`, `spent_atoms:int64`, `change_atoms:int64`, `net_atoms:int64`, `fee_atoms:*int64`, `input_count:uint32`, `output_count:uint32`, `owned_input_count:uint32`, `owned_output_count:uint32` |
| WalletActivityOutput | `index:uint32`, `atoms:int64`, `owned:bool`, `change:bool`, `address:string` |
| WalletActivitySnapshot | `version:uint32`, `state:string`, `error:string`, `binding:*WalletActivityBinding`, `activity:string`, `active_job_id:string`, `last_job_id:string`, `capture_job_id:string` |
| WalletActivityJob | `version:uint32`, `job_id:string`, `state:string`, `binding:WalletActivityBinding`, `error:string`, `capture:*WalletActivityCapture` |
| WalletActivityPage | `version:uint32`, `binding:WalletActivityBinding`, `job_id:string`, `capture:WalletActivityCapture`, `after:uint32`, `limit:uint32`, `next:uint32`, `has_more:bool`, `items:[]WalletActivityItem` |
| WalletActivityDetail | `version:uint32`, `binding:WalletActivityBinding`, `job_id:string`, `capture:WalletActivityCapture`, `item:WalletActivityItem`, `outputs:[]WalletActivityOutput` |
| WalletActivityRequest | `id:uint64`, `version:uint32`, `command:string`, `view_id:string`, `job_id:string`, `after:uint32`, `limit:uint32`, `txid:string` |
| WalletActivityResponse | `id:uint64`, `version:uint32`, `ok:bool`, `snapshot:*WalletActivitySnapshot`, `job:*WalletActivityJob`, `page:*WalletActivityPage`, `detail:*WalletActivityDetail`, `error:string` |

The binding's root is a validated canonical Phase-A master public key <=128 ASCII
bytes; gym key is canonical compressed 33-byte hex and GymID must match it. The
whole binding must equal the native independently derived binding from the
current Pool snapshot's full View/source and published fixture account tuple.
It never binds through the pool payout recipient alone. Read-only history's
narrow in-process seam is an explicit exception to the old ordinary-history
RPC convention; the private RPC allowlist remains unchanged.

Capture wallet and node tips/heights must be equal. Count <=256; has_older implies
count=256, while count=0 implies false. One item has 1..256 input/output counts,
owned counts no larger than corresponding counts and at least one owned count
nonzero. C/D/K must satisfy the formulas above, K<=C; no cross-item total exists.
Unmined block=null implies confirmations=0; a mined block must be <=captured
height and confirmations=height-block.height+1. Coinbase implies input_count=1,
owned_input_count and spent_atoms zero, and fee=null. Fee is null exactly when
coinbase or owned_input_count<input_count; otherwise it is nonnull and <=D.
No owned inputs implies D=0; no owned outputs implies C=K=0.

Page Items is a nonnil array of exactly min(limit,count-after) records. Limit is
1..8, after<=count, next=after+len(items), has_more=(next<count). IDs are unique
and rows follow the frozen order; bridge pages are compared to their same
capture/job and neighboring retained selections, never a live source cursor.
Selected detail must match exactly a member of that retained capture, and its
item must equal the selected page item. Browser txids cannot introduce a new
selection. Outputs has exactly output_count entries in ascending contiguous
index order. Atoms sum within MaxMoney; owned count/sum matches C, change count
is a subset of owned and its sum matches K. For a known fee, output sum + fee=D.
Each address is either empty (unknown/unrepresentable) or a canonical native
chain address <=90 ASCII bytes extracted from exactly one supported output
script. Never resolve or infer an address through wallet derivation. An empty
address is not an error or evidence that an output has no owner.

Commands and zeroing rules:

- `wallet_activity_snapshot`: ViewID/JobID/TxID empty and After/Limit zero.
- `wallet_activity_begin`, `wallet_activity_job`, `wallet_activity_cancel`:
  exact ViewID and nonzero JobID; TxID empty, After/Limit zero.
- `wallet_activity_page`: exact ViewID/JobID, After<=256, Limit 1..8, TxID empty.
- `wallet_activity_detail`: exact ViewID/JobID/member TxID; After/Limit zero.

Snapshot unavailable is exactly state=`unavailable`, error=`activity_unavailable`,
binding=null, activity=`none` and all job IDs empty. Signed-in idle has binding,
empty error, activity=`none`, active_job_id empty. Busy activity is `capture` or
`detail` with nonzero active_job_id; a detail's active ID equals capture_job_id.
Last/capture IDs are blank or nonzero canonical IDs. One current capture and one
last/active attempt metadata are retained, not an unbounded job journal.

Job states: `running`/`cancelled` have empty error/capture=null; `failed` has
capture=null and error `busy`, `capacity` or `activity_unavailable`; `done` has
empty error and nonnull valid capture. The capture job remains queryable while
a new attempt is running/failed/cancelled. A successful Refresh supersedes it.
Successful response has exactly one arm corresponding to the requested command
and error=""; failure has all four arms null and one closed error code. No partial
payload on authorization, transport, decoding or correlation failure.

Exact error vocabulary: `invalid_request`, `unauthorized`, `stale_view`, `busy`,
`capacity`, `activity_unavailable`, `activity_not_found`, `operation_conflict`,
`outcome_unknown`. Expired/revoked/forbidden original View maps unauthorized;
wrong epoch/binding/selected helper maps stale_view. Missing retained job/member
maps activity_not_found, and inconsistent reuse of a known job maps
operation_conflict. Busy is local admission contention, not successful empty
history. Bounds map capacity. Closed/profile/corrupt/backend/tip mismatch errors
map activity_unavailable without raw storage or credential strings. Lost or
malformed Begin acknowledgment maps outcome_unknown; other read failures map
activity_unavailable. Explicit Cancel completes as cancelled; deadline is a
failed activity_unavailable task unless the original view has already vanished.

Request frame cap is 1024 bytes including LF. Snapshot/job/page/error response
frames <=16384 including LF; detail response <=98304 including LF. Response
reader may use the overall 98304 cap, then enforce the arm-specific cap before
publication. Max token depth 3 for requests and 8 for responses; arrays only
page.items<=8 and detail.outputs<=256. Strings have per-field caps before typed
decode: IDs/hashes64, gym key66, root128, address90, authority origin256, closed
  labels/commands64. Aggregate bytes are checked first. Null only at response
arms, snapshot.binding, job.capture, item.block and item.fee_atoms. Items/Outputs
must be arrays, never null. Canonical encoders use the field orders above.

The corresponding `WalletActivitySurfaceAPI` has exactly:

```go
WalletActivitySnapshot(context.Context) (WalletActivitySnapshot, error)
BeginWalletActivity(context.Context, string, string) (WalletActivityJob, error)
WalletActivityJob(context.Context, string, string) (WalletActivityJob, error)
WalletActivityPage(context.Context, string, string, uint32, uint32) (WalletActivityPage, error)
WalletActivityDetail(context.Context, string, string, string) (WalletActivityDetail, error)
CancelWalletActivity(context.Context, string, string) (WalletActivityJob, error)
```

The string parameters are ViewID, JobID, then TxID for Detail; Page numbers are
After, Limit. A successful Begin admission and its bounded read run outside the
request's transport lifetime, but only while the original child/View remains
valid. Native reserves fresh JobID against original helper+full View before any
write. Recover an uncertain Begin only through that exact ID; never a generic
last job or new Begin. A definitive exact job-not-found retires that unresolved
attempt, permitting an explicit new Refresh. Predispatch busy may retire only
an exact never-dispatched intent. A dispatched/unknown action remains unresolved.
There is no automatic capture refresh, retry after failure or cross-session job
recovery. A retained same-ID Begin returns its same job instead of duplicating
the work; old evicted IDs cannot be selected/reissued by native/webview state.

Page and Detail share one fail-fast local projection slot; no concurrent local
materialization is admitted. Acquire it outside any account lease, and join it
before child disposal. A Page copies only its eight-or-fewer summaries and
metadata, not private raw bytes or an entire capture. It may coexist with a new
capture's work, because the copied public page has its separate fixed cap.
Native/helper framing already serializes request/response exchange; retain only
one bounded outgoing frame, not an unbounded queue of owned results.

Detail also acquires the one operation slot outside any account lease, retains the
immutable captured record, parses/projects outside locks, and rechecks the same
original view/capture before disclosure. Its caller and child lifetime jointly
bound it to 30 seconds, with checks during raw/output processing. Close/reset/
backup cancel and join it like the capture task; it touches no live wallet or
network. Capture admission while Detail is active is busy, avoiding old/new/third
capture overlap. Cancel addresses capture attempts only; requesting it for a
completed capture returns that completed job, without altering saved rows.

## Source-only independent budget review

`set70-prep/reference-producer/size_budget.py` and `size-budget-inputs.json` are
review material only. Do not execute either before root reviews/freezes the
contract and those inputs. The script imports no project implementation, opens
no wallet, calls no network and generates no key. It computes canonical JSON
size upper bounds from the ordered grammar and independent integer formulas,
and reports explicit count/buffer overlap budgets. Synthetic field maxima are
conservative size witnesses, not valid expected cryptographic/account vectors.
The later actual/reference corpus remains a separate frozen-input workflow.
