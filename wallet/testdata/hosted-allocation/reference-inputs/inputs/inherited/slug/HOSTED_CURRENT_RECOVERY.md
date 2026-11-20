# Set71 — hosted current recovery for the explicit fixture Pool

Status: reviewed engineering contract adopted for Set71, November 19, 2026.
The external freeze record binds these bytes before implementation. Independent
producer inputs and source must also be reviewed and locked before generating
expected outputs or implementing their dependent behavior.

## 1. Deliverable and preserved policy

Add an explicitly selected, runnable fixture-hosted Pool mode to the normal
packaged desktop/helper. It uses the existing fixture selection, login/reset,
mining and backup controls and existing shared Pool source. Its account
authority is schema 2; all login/reset evidence is signed and goes through
`gymidentity` and `gymprovider`. The locally installed wallet remains the same
schema-9 Phase-A fixture wallet across reset. A purpose-separated fixture vault
provides enrollment/recovery and prospect signing, and an authorized current
export combines its retained entropy with a fresh concrete wallet cursor
checkpoint. Independently restore an actual exported file after change
allocation and prove funds and the same gym.

This is a candidate fixture controller and local simulated hosted custody, not
real signup, a live provider/KMS integration, a production wallet or cross-device
release. Publicly documented fixture RSA/KEK material is permitted only in the
explicit fixture driver/wrapper; no real key, credential, wallet entropy or
provider resource is read or created. Do not substitute unsigned claims for
signed evidence. A test-only constructor without the packaged user path does
not satisfy this deliverable.

D70 remains 24 English BIP39 words, empty phrase passphrase, and separate
login/encryption passwords. D72 remains same-wallet reset, immediate revocation,
durable pending barrier, fresh authorization and the 24-hour hold. Viewing and
mining remain allowed; withdrawal, recovery export, fighter transfer,
recovery-authority change and marketplace purchase/listing remain blocked.
Completed-event replay never restarts the hold. Export does not revoke hosted
authority or migrate to exclusive self-custody.

D73 remains separate: preserve profile-1 coin-0/mixed-49 derivation and the
version-1 recovery file. No profile-2 activation, final coin allocation, permanent
genesis or production issuance is part of this set. D74 remains the final joint
design review. Do not reorganize navigation or change logos.

Legacy schema-1 Pool selection/data, schema-2 account/coordinator APIs, the old
vault constructors and immutable export API, and all existing file/profile
formats retain their behavior. No silent migration, import of existing Pool
histories, source repinning or fallback between modes.

## 2. Explicit activation and public route

Native and helper accept `--candidate-hosted-pool` as a separate boolean mode.
It requires an explicitly supplied canonical absolute `--data-dir`, and the
helper's explicit normal `--node-binary`. It conflicts with `--candidate-pool`
and every legacy mode flag. A packaged default for ordinary Pool does not count
as explicit hosted selection. Go boolean spellings such as `=true` are accepted.
`--candidate-name-version=1|2` retains the same descriptor options, but version 2
requires an explicitly selected Pool or hosted-Pool mode and explicit root.
Unknown/mismatched selections refuse before directory/lock/store mutation.

The new runtime/native mode string is `local-hosted-fixture-pool`. The existing
PoolSnapshot field shape is unchanged; its Mode discriminator explicitly adds
this value. The native bridge pins the expected mode from launch arguments,
alongside the existing exact descriptor/source/full View, and rejects a response
from the other mode. The frontend recognizes both as Pool layouts, with a
visible “Hosted public-fixture pilot” caption for this route. No JSON/provider
configuration, arbitrary issuer, assertion, key, token or verified flag is
accepted from the webview. Current backup selection/Verify controls and existing
version-1 file parser remain unchanged.

`accountpilot.NewHostedFixturePool(ctx, pilot.Config, pilot.PoolOptions)` is the
normal candidate constructor. It constructs only the compiled fixture
coordinator/driver/wrapper. `ServePool` may dispatch to its existing controller
surface; native launch has a separate constructor that supplies the hosted flag
and expected mode. A private test factory may replace typed dependencies for
fault injection, never expand the production fixture allowlist.

## 3. Ownership and namespace

The hosted parent owns, in order of dependency: original schema-2 account
authority, coordinator, local fixture credential driver, HostedVault/current
checkpoint store, shared PoolRuntime, and the active child. The runtime borrows
the authority/vault and retains immutable bindings. The child owns one opened
installed wallet and one exact original login/View, and borrows the vault/source.
No second loader opens its installed wallet. Quit/failed construction invalidates
the View, cancels and joins the child and runtime borrows, closes runtime, then
hosted vault/current store, driver/coordinator and account authority. Shutdown
failure retains the responsible owner and prevents replacement/reopen; there is
no best-effort release of a wallet still in use.

Use a fresh separate managed root. Top-level entries are exactly:

```
instance-lock/
SLUG-HOSTED-POOL-INIT.json
SLUG-HOSTED-POOL-READY.json       # only after complete initialization
setup/
authority/
coordinator/
fixture-provider/
hosted-vault/
current-recovery/
shared/
```

INIT is written/synced before dependent stores. Before writing it, generate the
AuthorityID, CoordinatorID, HostedVaultID and two WalletOwnerIDs. INIT pins these
nonzero random 32-byte IDs along with the selected descriptor and exact compiled
configuration hashes. Creation receives those exact IDs; reopen compares with
INIT before adopting any store identity. Add narrow `CreateIdentityPinned` /
`OpenIdentityPinned` account and `CreatePinned` / `OpenPinned` coordinator
constructors accepting the expected ID; preserve all existing constructor
semantics. HostedVault create/open also takes the expected HostedVaultID.
Neither an Info getter nor an existing marker supplies a missing expected pin.

After each store is created, a bounded immutable stage receipt pins that exact
preselected ID/config hash. A crash after creation but before receipt can audit
and reopen only the next store under its original INIT pin. If the constructor
left only an uncommitted initializer footprint, only its explicit exact-ID
initialization recovery can resume it; arbitrary nonempty contents are refused.
It may not delete/replace a store, generate a substitute ID or skip ahead.
READY pins those same IDs, source BindingID and both fixture retention/current
source bindings, in fixed fixture order. Once READY
exists all listed stores/receipts are open/verify-only; missing or mismatched
established data fails closed. The same holds for existing inner Pool READY,
recipient, league, pipeline and withdrawal markers.

All control/marker JSON has exact required fields, fixed version, no unknown,
duplicate decoded, null, case-alias or invalid-UTF8 values. Marker cap is 32 KiB;
single fixture stage receipt cap 8 KiB. Paths use existing canonical-directory,
regular-file/no-symlink and managed-root overlap checks. Hosted and legacy roots
must also refuse ancestor/descendant overlap with each other. No directory scan
selects a mode. Old Pool cannot open this namespace; no old marker is fabricated
as a compatibility shim.

The inner shared source, Pin2 stable histories and original registry sequences
retain their existing contracts. The new outer root may initialize that source
only once, and never adopts a source from an old authority. This is ordinary
fixture source selection, not a new chain or production genesis.

## 4. Signed local fixture provider

The fixed provider is `published-fixture-v1`, issuer
`https://identity.slug.invalid`, tenant `fixture-tenant`, client
`fixture-client`, connection `fixture-database`. Use
`gymprovider.FixtureVerifierConfig()` exactly, including its two audiences,
RS256/kid and credential-epoch claim. The driver is explicitly
`local-published-fixture-evidence-v1`. Its signing key is only the already
published RFC7515 A.2 fixture copied from the frozen old source input; no
environment key, key-file selector, live endpoint or arbitrary assertion input.
Pin its exact public JWK/config digest before stores open.

The driver selects only `zero256` or `incrementing256`. It persists its own
fixture credential epochs, original authentication facts and reset operations
separately from the coordinator, using bounded synced atomic state. It is not
the account authority. Transport assertions are transient strings <=16 KiB;
never save them, log them, put them in errors or return them to native/webview.
All claim grammar, number encoding, exact field order used by the independent
producer, audience/type separation and verification follow GYM_PROVIDER.md.
Fresh transport has `iat=now`, `exp=iat+120s`, but does not change original
`auth_time`, epoch, verification time, auth ID or operation ID.

The narrow code-only driver API is:

```go
type HostedFixtureEvidence interface {
    ID() string
    FreshLogin(context.Context, gymprovider.LoginFlow, string) (string, error)
    BeginResetEvidence(context.Context, gymprovider.ResetRequest, string) (string, error)
    CommitReset(context.Context, gymprovider.ResetRequest, gymprovider.ResetResult) error
    CompleteResetEvidence(context.Context, gymprovider.ResetRequest) (string, error)
    PendingReset(context.Context, string) (*FixturePendingReset, error)
    ObserveResetComplete(context.Context, gymprovider.ResetRequest, gymprovider.ResetResult) error
    RetireUnbegunReset(context.Context, gymprovider.ResetRequest) error
    Close() error
}
```

The driver validates every supplied flow/ack against its retained immutable
record, including coordinator/authority, raw EventID versus derived Barrier ID,
nonce, fixture/account, provider operation, original epochs/time and phase.
CommitReset is one exact compare-and-swap from FromEpoch to ToEpoch after an
acknowledged pending barrier with CanCommit=true; repeating its same saved
operation returns its stored result without another credential mutation.
Historical completed receipts cannot authorize new mutations. Completion
evidence requires that stored successful credential mutation. No generic
“verified” method or caller-populated VerifiedLogin/VerifiedReset entry point.

FreshLogin called again with the exact retained flow/fixture reuses its durable
original auth ID/time/epoch and emits fresh transport only; it does not invent a
new authentication under the same flow. A different flow is a new explicit
authentication. All driver record times are integer Unix milliseconds, with
authentication/verification times sampled as `floor(now_ms/1000)*1000` for
inherited JWT seconds. JWT `iat` is `floor(now_ms/1000)` and `exp=iat+120`;
the original stored authentication/verification time is never refreshed by
transport replay. The durable clock highwater cannot decrease. RNG/signing is outside
account leases; uncertain driver writes poison the owner until reopen/audit.

Fixed capacities: account MaxLoginAttempts=1024, MaxSessions=4096,
MaxChallenges=4096, MaxEvents=16384; coordinator MaxLoginFlows=1024,
MaxResetFlows=256. Driver retains at most 1024 original auth rows and 256 reset
rows plus exactly two epoch rows, without eviction/recycling. Each original-auth
row <=2048 bytes, reset row <=4096 bytes, canonical driver state <=4 MiB.
Counter overflow and capacity fail before mutation; reserved reset completion
space cannot be consumed by new flows. One fail-fast driver operation, a
16-MiB accounted transient budget, and no unbounded request queue. These are
logical byte/count bounds, not a total Go heap cap.

Login: IssueLogin -> driver durable fresh authentication -> signed evidence ->
FinishLogin -> original private Session. Lost completion never returns an old
session token; discard/revoke an unpublishable token and require a new explicit
login flow. On startup, the same signed flow provisions the two fixtures in
fixed order, then revokes setup sessions. It does not start mining.

Startup opens/pins the authorities and driver before attempting fixture login.
If either fixture has an exact retained pending reset, return a usable signed-out
controller with `hosted_reset_pending` and that fixture's Resume reset control;
do not require both logins or Pool StartServices to finish first. Runtime/child
services remain gated until exact reset completion and resumed setup succeed.
Opening the controller itself does not mutate credentials. A runtime already
open when reset begins retains its parent source; its old child is invalidated
and joined, and new child creation is gated by the pending barrier.

Reset: invalidate old native/controller View immediately, persist the exact
selected reset request/driver operation, verify BeginReset evidence and obtain
the durable authority/coordinator pending barrier BEFORE credential mutation
or child joins. Then join the old child, perform the exact driver credential CAS,
verify CompleteReset evidence, and obtain the original completed receipt before
fresh-login/recovering the same wallet. Begin failure still joins/revokes the old
view and never reopens it. An uncertain stage preserves the exact EventID and
provider operation; it is never replaced with a “latest pending” lookup.

After restart, no automatic credential mutation occurs. Existing fixture login
selection discovers only its own pinned pending record and reports reset
pending. The same Reset control becomes “Resume fixture reset”; it can operate
while signed out only for that exact retained fixture/event. It replays fresh
signed transport for the same operation under the existing coordinator rules.
No timeout unlock, forged completion or restart of verified_at. An expired
never-created begin may be retired only after the existing authority/coordinator
show no barrier; it cannot be turned into a different reset under the same IDs.
This does not add a manual override for a committed pending reset.

PendingReset returns the owned exact retained request and operation association
from the driver's fixed fixture slot, not a reconstructed request or a latest
operation search. The parent verifies its coordinator/authority binding and
queries/replays the exact EventID. ObserveResetComplete accepts only the matching
verified coordinator completed result, atomically marks that record completed
and clears its pending slot. A crash before this acknowledgment leaves the exact
slot recoverable; repeating completion cannot extend the account hold. Neither
method produces an account capability or discloses these private records to UI.
RetireUnbegunReset is permitted only for the exact expired `issued` coordinator
request with no semantic begin/barrier, using the driver's privately retained
concrete coordinator/authority, under its already-owned operation permit. It
does not accept a caller-supplied absence flag. A prepared/pending/complete or
uncertain coordinator/authority state refuses retirement. The old row remains
retained as retired; a later reset must use new IDs and cannot reuse capacity.

## 5. Explicit hosted vault and typed signing

Add `recoveryvault.CreateHosted/OpenHosted`, returning a distinct `*HostedVault`
with no accessor for the underlying legacy `*Vault`. Its store marker explicitly
selects hosted mode; old `Open` refuses it, and hosted open refuses a legacy
store. Envelope Binding/Purpose/ContentRevision/ManifestHash, original
DefaultAccounts, ciphertext plaintext formats, Receipt/RetentionID and wrapping
AAD remain exactly version 1. A new store-mode discriminator is not a new
cryptographic content format. Do not rewrite either envelope to track cursors.

This separation is mandatory for lock order. Legacy methods may take the account
gate and then wait for `v.lock`; new hosted methods acquire a fail-fast lifecycle/
vault permit outside account leases, then use short original-session fences.
Those two orders must not coexist on one exposed live object. Refactor private
pure helpers as needed, but preserve old constructors and method behavior.

Hosted methods expose only typed ProvisionFixture, SignAccountChallenge,
EnsureEnrollment, SignAdmission, Status and current-recovery operations.
They return owned public receipt/signature values and sanitized errors only.
The caller captures the exact original token before work. Vault/provider/DB
reads, proof verification, signature derivation, encryption/decryption and
permit acquisition occur outside account leases. Final fences reauthorize the
same token/generation, validate retained revision/binding in memory under the
already-owned permit, and perform only bounded local commit/disclosure. A lost,
omitted, double, retained or swallowed-error fence callback cannot publish.

Define a concrete pilot `HostedVaultSigner` binding, created only from the
parent's HostedVault, exact immutable Receipt/RetentionID, source Policy,
AuthorityID, AccountID and fixture identity. PoolChild admits that concrete
typed mode only through hosted resources, not a generic callback. It still
rejects AccountConfig.AdmissionSigner in legacy mode. Each signing invocation
uses one original mining token, copies exact Context/Proof, checks source/gym,
performs the vault call outside authority leases and verifies the returned
signature over the original bytes before final same-token disclosure. Vault
failure is failure; no local wallet-key fallback. D69 block-first worker order,
D80 expiry suppression and source issuer ownership are unchanged.

During held login, only the gym envelope may be unwrapped for typed enrollment/
recovery or admission signatures. No recovery plaintext/DEK, mnemonic, root
private key, arbitrary path/digest signer or withdrawal signer is added. The
retained fixture wallet continues to serve its existing guarded wallet functions;
the hold is not claimed to revoke independent copies of public fixture keys.

Fresh setup ordering is concrete: obtain original schema-2 session; prepare the
exact local wallet in its new owned root; provision/verify vault envelopes; use
the vault to sign the runtime's existing enroll/recover challenge; CompleteChallenge;
then EnsureEnrollment acknowledges the vault record without issuing another
challenge. Only afterward commit recipient/current-source/withdrawal READY.
Calling EnsureEnrollment before creating the local wallet is prohibited: current
ProvisionFixture correctly refuses a missing wallet for an already enrolled
account. Established missing wallet/vault remains a hard refusal.

Established enrolled reopen has a distinct hosted verify path: original View
preflight and verify exact saved receipt/RetentionID and installed wallet. When
the enrolled account has RecoveryRequired=false, this is verify-only: issue no
challenge and do not call CompleteChallenge. Only when RecoveryRequired=true,
issue the exact recovery challenge, sign it through the gym purpose under
Enrollment, and CompleteChallenge under its original session. Do not invoke legacy
WithProvisioning/reserve/ProvisionFixture for an already retained record: that
path refuses an active hold. Held reopen never unwraps recovery material and
never creates a missing wallet, envelope or enrollment. A partially initialized
record requiring provisioning cannot be completed under a hold; it remains a
typed held setup refusal with the controller usable for permitted reset/status.

## 6. Concrete public current-wallet capture

Add an opaque `wallet.CurrentRecoveryCapture`. Its constructor is a method on
the concrete retained Wallet, with context and no caller-supplied manifest:

```go
func (w *Wallet) CaptureCurrentRecovery(ctx context.Context) (*CurrentRecoveryCapture, error)
func (c *CurrentRecoveryCapture) Manifest() recovery.Manifest // owned copy
func (c *CurrentRecoveryCapture) CaptureID() string
func (c *CurrentRecoveryCapture) CapturedAtMS() int64
```

No JSON parser can construct the handle. Private fields bind it to the exact
wallet/manager owner, capture identity and original public retained profile.
The vault's current-source attachment receives that concrete wallet privately
from its verified runtime owner; an arbitrary same-root restored wallet or
webview manifest is not interchangeable authority.

The public reader must be new/factored bounded schema-9 logic. Do NOT merely
export recoveryPublicManifest/RecoveryAccounts: their existing call chain reads
private-retention ciphertext metadata through fetchRecoveryState. Reuse/factor
Set70's public identity checks, then read the exact four account-zero scopes and
eight issued cursors in the SAME walletdb View. No private retention Get, private
decryption, unlock/KDF, seed/root-private extraction or address derivation.
An account database value contains an encrypted-private-key span before its
public cursors. Bound the entire row at the inherited 65536-byte limit before
parsing, validate exact length framing, and skip that span without copying,
decrypting or retaining it. The database necessarily returns that mixed row;
the contract forbids separate private-retention Gets and private-span use, not
the physical presence of private ciphertext in the bounded row value.
Reject watch-only, legacy, profile2/schema10/11, pending/completed schema12,
foreign chain/profile, extra scope/account or nonempty imported account.
The required imported-account metadata row itself is legitimate. Its imported
address-index subbucket may be absent or empty when no imports exist; either is
accepted, while an actual imported address is rejected.

Require fixed scope order 44,49,84,86; coin/account 0; existing mixed scope49
external/internal types; each cursor 0..4096. Validate persisted manager version,
derivation/recovery version, public root/manifest identity and current account
records, with limits before copies/decryption. At most five scope cursor entries
and three account entries per scope (the extra item is a refusal witness), plus
one imported-address presence probe per scope. No whole address/UTXO/tx scan.
Check context before View, between bounded reads and before return. The database
operation cannot be abandoned on cancellation; it is joined before owner close.

The runtime holds its fail-fast wallet mutex only for this local capture, never
under an account lease. The capture does not need node sync/PoW or transaction
history: it is a dated committed cursor inventory, not chain finality. It must
retain all non-cursor manifest fields exactly, and match the published fixture
root/gym and immutable vault receipt.

## 7. Separate current checkpoint

Attach a current-recovery owner to the concrete HostedVault and installed wallet
using a trusted immutable source binding established by the parent. Proposed
public types use this exact field order and snake_case JSON:

```go
type CurrentBinding struct {
    Version uint32               // 1
    HostedVaultID string         // random persisted hosted store identity
    VaultBinding Binding         // exact immutable version-1 vault Binding
    RetentionID string           // original immutable receipt identity
    WalletOwnerID string         // random persisted local owner namespace ID
    SourceBindingID string       // exact shared Pool source
}
type CurrentCheckpoint struct {
    Version uint32               // 1
    Binding CurrentBinding
    Revision uint32
    CaptureID string
    ExpectedRevision uint32
    CapturedAtMS int64
    CommittedAtMS int64
    Manifest recovery.Manifest
    ManifestSHA256 string
}
```

The candidate private API is concrete rather than a supplied-manifest callback:

```go
CreateCurrentStore(ctx context.Context, path string, vault *HostedVault,
    bindings []CurrentBinding) (*CurrentStore, error)
OpenCurrentStore(ctx context.Context, path string, vault *HostedVault,
    bindings []CurrentBinding) (*CurrentStore, error)
(*CurrentStore).AttachSource(ctx context.Context, originalLoginToken string,
    binding CurrentBinding, installed *wallet.Wallet, epoch EpochFence) (*CurrentSource, error)
(*CurrentSource).Capture(ctx context.Context) (*wallet.CurrentRecoveryCapture, error)
(*CurrentSource).Checkpoint(ctx context.Context, expected uint32,
    capture *wallet.CurrentRecoveryCapture) (CurrentCheckpoint, bool, error)
(*CurrentSource).LookupCheckpoint(ctx context.Context, captureID string) (CurrentCheckpoint, error)
(*CurrentSource).PrepareExport(ctx context.Context, captureID string,
    destination *CurrentDestination) (*PreparedCurrentExport, error)
(*PreparedCurrentExport).Publish(ctx context.Context) error
(*PreparedCurrentExport).Close() error
(*CurrentSource).Close() error
(*CurrentStore).Close() error
```

AttachSource pins one original login token/account/generation and current
parent View for its entire ephemeral lifetime, verifies the actual installed
wallet public identity outside account leases, and checks the exact compiled
store binding against the parent's READY ownership. It never closes the borrowed
wallet. Closing its parent child cancels/joins it before wallet Close; reopening
creates a new source from the same established owner namespace, not a new stored
WalletOwnerID. Capture handles from a former or different concrete wallet cannot
be used on it. PrepareExport requires the capture produced/checkpointed by this
live source, not an arbitrary historical ID from another source lifetime.

EpochFence is a code-only parent-epoch fence, **not** an account authorizer:
`func(context.Context, func(check func() error) error) error`. It TryLocks only
the parent view mutex (busy rather than waiting), matches the captured
helper/child/token/View/generation,
and retains that match through the bounded callback. It never calls WithSession.
The hosted vault itself takes the real original-token account capability fence,
then enters EpochFence, avoiding a nested account lease. It checks both
reauthorizers before and after commit/disclosure. Missing/double/late/outer-error
epoch callbacks fail closed. Passing a permissive epoch callback cannot bypass
the concrete vault-owned account authority. The parent does not acquire or wait
for vault/current/wallet permits from inside EpochFence.

The two source bindings are created only after both original fixture wallet and
vault reservations are verified; initialization may retain exact partial
receipts while the second fixture is prepared. Creation/open rejects duplicate,
foreign or reordered bindings. HostedVaultID is returned only by a bounded
owned `HostedVault.Info(ctx)` value compared with the preselected INIT ID. A similar public
`Coordinator.Info(ctx)` exposes its existing immutable coordinator ID/config
binding without issuing an expendable login flow or reading marker files as
authority. These getters convey identity, never account capability.

IDs/digests are 64 lowercase hex; generated owner/capture IDs are nonzero random
32-byte IDs. Root/gym/profile fields use the unchanged recovery validators.
Revision is 1..128 in this bounded store; overflow refuses. ExpectedRevision is
0 for the first checkpoint and exactly Revision-1 thereafter. Time is
positive Unix milliseconds <=253402300799999. CapturedAtMS is sampled inside the
trusted capture operation; CommittedAtMS is sampled before staging the local
commit, must be >=CapturedAtMS and the prior store highwater, and is retained on
replay. Any rollback refuses rather than relabeling the old observation. Manifest
hash is SHA256 of existing canonical recovery.MarshalManifest bytes, no newline.
The current binding digest, if used by a marker, is SHA256 of ASCII
`SLUG hosted current recovery binding\x00v1\x00` followed by canonical ordered
CurrentBinding JSON bytes. No session generation is recovery identity.

`current-recovery` is an additive exclusively owned store, not legacy vault
record mutation. Exactly two account bindings, at most 128 retained checkpoint
actions across both accounts, and a current-checkpoint pointer per account.
Retain every committed action ID/result so exact replay and same-ID/different-
intent conflict are enforceable after later captures. No eviction or reuse.
Fixed maximum canonical state is 2 MiB; checkpoint <=8 KiB and manifest <=4 KiB
for this exact fixture inventory (the unchanged external recovery file remains
64 KiB). Creation pins complete bindings/config. READY loss refuses, never
silently creates an empty checkpoint store after established use.
Store canonical bounded action rows, current pointers and metadata in one
exclusively owned LevelDB namespace. A commit batch contains one <=8-KiB action,
one current pointer and counters/highwater, with total prepared key/value bytes
<=12 KiB. Full audit is bounded by 128 actions/two bindings and occurs outside
account leases. Do not rewrite a 2-MiB aggregate file under the final fence.

Checkpoint admission is original View, not RecoveryExport: it moves only public
metadata, cannot change recovery authority, and performs zero envelope unwraps.
Capture concrete wallet outside the account lease, then reserve the one current
store permit fail-fast before entering final original-token publication.
Publish by expected current revision and exact binding. Every branch cursor
must be >= its prior checkpoint and >= immutable initial inventory; reject any
regression rather than silently taking a max. Non-cursor fields must equal the
original receipt's manifest. Same CaptureID+identical capture/expected-revision
returns the original committed result, including its timestamp; same ID with
different capture or expected revision conflicts. A fresh capture with unchanged
cursors is a new dated action and consumes one slot. In one synced atomic commit
write the new immutable action, current pointer, revision and clock highwater.
Do not rewrite a previous action's time to make it look current. The 128-action
limit is explicit candidate capacity, independent of vault MaxOperations; it
does not promise an unbounded production backup history.

The trusted source owner keeps its CaptureID and exact staged intent in memory
until the live operation is resolved or its owner is joined. No durable pending
capture intent is added. A write/sync error after possible commit poisons that
owner/store; preserve its exact in-memory bytes until close, then require full
reopen/audit. While that owner survives, exact lookup may resolve its ID, but
there is no promise to recover an uncommitted capture or report an old operation's
outcome after process death. A caller that retained an exact committed ID may
read that result; a new session cannot recover an old opaque capture/View.
After process restart and successful full audit, the user may begin a new
explicit capture/export. Never call the latest saved checkpoint the old result,
automatically replay an old export/destination, or blind-retry an uncertain live
operation with a new ID. A new session can read committed public metadata only
under its own View; it cannot rescue an old View's disclosure/publication.

The default user export always captures/checkpoints the currently installed
wallet first. The saved checkpoint is explicitly dated; it is not automatically
current after every future allocation. A missing/unavailable current wallet
cannot produce a “current” export merely from a saved checkpoint. Continuous
allocation-to-vault disaster-recovery coupling remains later work. Restoring this
file does not recreate payment journals, signed-input reservations or account
authority, and never authorizes deletion/replacement of them.

## 8. Current export and native publication

Add a distinct HostedVault current export path; never change legacy
ExportRecoveryFile from its original immutable snapshot. The new path privately
receives the attached concrete source/capture, current checkpoint owner and the
original login token/View. Revalidate retention, account, source, capture and
checkpoint; unwrap only the recovery-purpose envelope, validate entropy against
the original immutable manifest, then assemble recovery.NewExport with the
captured current Accounts. Root/gym/non-cursor identity must remain equal.
No generic seed/entropy/DEK/bytes getter or secret callback is exposed.

Use an opaque `recoveryvault.PreparedCurrentExport` and a concrete create-only
`CurrentDestination` owned by recoveryvault. The desktop converts only the
already-captured public CreateMode native selection to:

```go
type CurrentDestinationPin struct {
    Version uint32               // 1
    Path string                  // canonical absolute, <=2048 UTF8 bytes
    ParentDevice string          // exact16 lowercase hex
    ParentInode string           // exact16 lowercase hex
}
```

OpenCurrentDestination independently verifies canonical parent components,
pinned directory identity, basename, existing destination absence and protected
roots; it retains its own descriptor. Native holds the existing Selection until
the synchronous helper operation is known joined, including transport failure
or helper shutdown. The original full View/helper is captured BEFORE the native
dialog; an account switch does not retarget the selected destination.

Prepared export keeps <=65536 private encoded bytes in memory. It has no Bytes,
WriteTo or caller-controlled secret callback. Crypto, derivation, serialization,
vault/checkpoint traversal and permit acquisition happen outside account leases.
**No plaintext recovery staging file is created in the user directory before
the final RecoveryExport fence.** Root selected the established bounded private
local commit: under that exact original capability, create an unpredictable0600
temporary, write/sync <=64 KiB, verify its inode/size, exclusive descriptor-relative
link to destination, verify, unlink owned temporary and sync directory. Check
context/authority before commit and before reporting success. This finite local
file transaction is the explicit exception to outside-lease bulk work. Ordinary
filesystem sync can delay a reset through an admitted atomic commit; do not
claim OS disk I/O is interruptible.

Missing/double/late/swallowed fence callbacks and outer errors never report
success. Existing destination is definite conflict and never overwritten.
Possible link/publication followed by error is `export_uncertain`; retain that
classification through cleanup. Close joins operations, clears private buffers
and removes only an owned temporary inode. Sticky cleanup failure prevents new
export/backup ownership until safely resolved; never remove an uncertain final
destination automatically. Old recoveryfile pins, limits, writer/read behavior
and old vault API remain unchanged.

Existing native ExportRecovery routes to this current path only in the hosted
mode. Existing VerifyBackup uses the actual chosen file and Set69's bounded
scratch restore, not a cached in-memory bundle. Export success is “file saved,”
never “backup verified.” Existing backup phase/state/error protocol suffices;
private checkpoint details need not be exposed as a new webview family.

## 9. Lifetimes, locks and fixed bounds

One parent account setup/login/reset operation; one active child; one backup
operation per child, mutually exclusive with mining and joined activity,
payout, withdrawal, stable/history/event work using existing stopMu discipline.
Start remains explicit. A checkpoint/export is admitted only with mining stopped,
the existing backup lane acquired, and the current source owner retained. Pure
public checkpoint setup outside a child also holds the original runtime borrow.

One hosted vault operation permit is fail-fast (busy, no queue). One current
source/capture/export owner per account; the parent permit spans child generations
until actual cleanup joins. Reserve 16 MiB of accounted transient recovery work
before capture/envelope/encoding; keep exact independent component bounds: public
manifest 4 KiB, private recovery export64 KiB, legacy envelope196608 bytes each,
wrapped key8192 bytes, current state2 MiB/128 actions and two current bindings.
At most an old retained state, one staged replacement and their bounded encoded
copies overlap; never a third transition. No address
inventory or raw blockchain allocation belongs to this operation. File output
copies and in-memory encoded material count toward the reservation.

Whole entered backup/export action30s, each wrapper call5s inside it, existing
Set69 VerifyBackup10min with bounded steps, account login/reset2min and initial
hosted startup180s (45s node start plus two60s wallet setup paths and bounded
local remainder, with child deadlines clipped by parent). Driver evidence/RSA
work5s per call. No automatic retry loop extends these deadlines. Expiry stops
new work and final publication; actual non-context-aware DB/file work is joined.

No account lease spans wallet/DB/network/provider operations, lock waits,
hashing/crypto, derivation or joins. Exception only the explicit pre-admitted
bounded synced local checkpoint/file commit, with prepared bytes and no new
permit acquisition. Account reset establishes revocation/pending barrier before
joins; newly held sessions can view and use gym-only signing. Stale token/view
cannot be replaced by a token supplier. Every returned public result is owned,
and final disclosure rechecks the exact full View, helper, account/generation,
retention and source.

## 10. Failures and recovery vocabulary

Private APIs use typed invalid/config, profile, unauthorized, held, stale_view,
busy, capacity, conflict, not_found, unavailable, outcome_unknown, poisoned,
closed and cleanup errors. Preserve context cancellation internally. Public
messages never contain JWTs, subjects, filesystem data, mnemonic, key/DEK,
provider response bodies or private crypto errors. Reuse existing account/backup
bounded errors except one account code `hosted_reset_pending`, shown with its
exact retained fixture and Resume reset action. No payload accompanies failed
private wire responses.

Logical states and permitted recovery are:

| State | Next permitted action |
| --- | --- |
| INIT, no completed dependency | Resume only exact next initializer/config |
| Established dependency missing/corrupt | Refuse; no recreate/adoption |
| Provision reserved/sealed/verified | Same original reservation; fresh authorized continuation as existing vault rules allow |
| Pending reset | Exact retained event begin/complete evidence replay; never timeout unlock |
| Lost login completion | No token replay; next explicit signed login |
| Checkpoint commit uncertain | Join/close poisoned owner; full reopen audit; exact ID lookup only if retained, otherwise new explicit capture without an old-result claim |
| Export definite prepublish refusal | Cleanup/join; caller may explicitly select a new destination |
| Export outcome unknown | Inspect selected destination; no automatic duplicate export or overwrite |
| Cleanup/owner shutdown failed | Preserve sticky failure/ownership; do not reopen replacements |

The local fixture driver persists one unresolved reset association per fixture.
The UI never substitutes a reset by subject/time or takes an older account's
pending record. Closing the app preserves pending semantics and clears all View
handles; opening the app alone does not start mining, issue an export, mutate
credentials or reveal recovery words.

## 11. Finite qualification and independent expectations

Freeze this contract and exact old public inputs before producer design/output.
Independent Python source derives checkpoint/manifest canonical bytes and
digests, monotonic/cross-binding cases and signed provider evidence from existing
frozen fixture sources. No Go/desktop implementation output is an oracle. Reuse
unchanged old envelope vectors and Phase-A address/recovery vectors; generate
new vectors only for the additive binding/checkpoint/driver encodings.

Meaningful finite checks include exact mode refusal before mutation; INIT/READY
crash boundaries; held public capture with zero recovery unwraps; schema9-only
public reads with a bucket spy that forbids private keys; scope/account/import
and cursor boundaries; foreign/stale/regressing checkpoint refusal; known
commit/lost-ack/reopen; context/reset while capture or wrapper blocks; original
token/View and failed outer fence; vault busy cannot block reset under a lease;
driver original auth/replay/epoch/CAS; vault failure without local signer
fallback; native dialog switch/selection identity; final publication uncertainty;
Close/backup join and sticky cleanup. Preserve all legacy routes/profile tests.

Actual isolated acceptance uses both published fixtures and the real shared
Pool path. Before/after source bindings record normal PoW profile and exact
compiled inputs. Exercise one real change allocation/send, export through the
new vault path, independently fresh-restore the FILE, synchronize to the exact
owned node hash/height, recover expected outputs and make a controlled spend.
Do not restore into or modify the installed withdrawal journal. Confirm original
root/gym and current cursor inventory with independent old-source derivation.

Then verify schema2 reset through the local signed driver: durable barrier
before one credential mutation, old token/View revocation during blocked work,
same wallet/recipient/retention/checkpoint after fresh login, export/withdrawal
hold refusal, allowed public view and explicit gym-only mining, zero recovery
unwrap during the hold, same-event replay without hold extension, interrupted
begin/completion restart. Use tagged clock advancement only in acceptance for
the fixed hold where needed; normal runtime has no clock override. Run the
normal packaged hosted flag with both fixture controls, actual export/Verify,
restart and genesis/no-implicit-mining checks; also prove ordinary Pool startup
and existing schema1 roots are unchanged. Keep HANDOVER smoke and required
candidate-profile checks, without mining the public seed.

No genuine owner policy choice is required for this slice. Real provider/KMS,
operator-owned production secrets/resources, permanent chain/coin values,
continuous disaster-recovery promises, exclusive self-custody migration and the
joint D74 review remain separate. They are not prerequisites for completing and
qualifying this explicit public-fixture mode.

## Appendix A. Exact additive byte contracts

This appendix freezes the new records only. Inherited nested types retain their
existing JSON field order, scalar grammar, validation and bytes. New records use
UTF8 compact JSON, listed field order, all fields present, no unknown/duplicate
decoded keys, no null except the two explicitly nullable acknowledgment fields,
no floats/exponent/-0 integers and no invalid Unicode. Empty collections are `[]`,
not null. Canonical encoding uses the existing Go JSON string escaping convention
(including `<`, `>` and `&`); hashes exclude any terminal LF. Files have exactly
one terminal LF; LevelDB values have none. Every file/value cap below includes
its LF when present. Untrusted readers reject oversize before decoding/copying.

All newly generated IDs are 32 random bytes encoded as 64 lowercase hexadecimal
characters and must not be zero. Hashes are 64 lowercase hexadecimal characters;
all-zero digests are lexical values, not generated identities. Account/principal
IDs and inherited request nonces obey their original validators. Version is
uint32 value 1 unless a nested type says otherwise. Revisions/counters are uint32
and overflow refuses; credential epochs retain the inherited positive uint64
grammar and overflow refusal. Times use integer Unix milliseconds
0..253402300799999; sampled/action times are positive, while only initial clock
highwater uses zero. This new-record rule does not override inherited time
sentinels: in particular ResetBarrier.CompletedAtMS and HoldUntilMS remain zero
before completion, exactly as their existing contract requires. No session
token, JWT, mnemonic, DEK or private key is ever
part of these public/control records.

### A.1 Fixed fixture configuration

Fixture order is always `zero256`, then `incrementing256`. Each maps to the same
literal subject as its fixture name, issuer `https://identity.slug.invalid`.
The new candidate chooses tenant `fixture-tenant`, client `fixture-client`,
connection `fixture-database`, matching the prior accountpilot provider fixture
(the lower-level gymprovider unit fixture's `fixture-password` is not this
configuration). Authority principals are exactly these two triples; the stored
Accounts.Principals order is the existing normalizedConfig order, sorted
lexicographically by `gymaccount.PrincipalID(issuer, subject)`. It is distinct
from fixed fixture processing, WalletOwnerPin, driver and current-binding order.
Identity config is version 2 with Accounts version 1 and the limits in §4.
Coordinator config is the exact existing `gymprovider.Config` order, provider
`published-fixture-v1`, preselected AuthorityID, the selected verifier digest,
MaxLoginFlows 1024 and MaxResetFlows 256.

Verifier is exactly `gymprovider.FixtureVerifierConfig()`: kid `rfc7515-a2`,
RS256, epoch claim `slug_auth_epoch`, login audience
`slug-provider-fixture-login`, reset audience `slug-provider-fixture-reset`.
Private fixture RSA source is the already published
`slug/gymidentity/testdata/rfc7515_rsa.json`; its public modulus/exponent must
match that config. A new normal-package fixture driver uses these public fixture
inputs only in this explicit mode; it does not call a `_test.go` helper or expose
an arbitrary signing interface. Freeze the exact source bytes in the independent
input inventory. Existing JWT header/claim grammar and verifier digest are
unchanged, and the independent producer states its canonical claim order.

Wrapper ID is `public-fixture-wrapper-v1`. Active and allowed recovery reference
is only `fixture-recovery-v1`; active and allowed gym reference is only
`fixture-gym-v1`. MaxOperations is 128. Recovery KEK is public byte range 00..1f;
gym KEK is public byte range 40..5f from the old
`slugwallet/recoveryvault/testdata/vault_v1.json`. No reference selector or
rotation UI is added. A new explicitly typed candidate wrapper implements the
old KeyWrapper contract with AES-256-GCM and exact caller AAD. Its 60-byte blob is
12-byte fresh random nonce || encrypted 32-byte DEK || 16-byte tag. Envelope DEKs
and content nonces also use fresh randomness; deterministic old vector nonces
are not used by the runnable route. Unwrap requires the exact role reference,
length and AAD and clears owned temporary DEK buffers. The unchanged generic
wrapped-key cap remains 8192 bytes, though this fixed wrapper produces 60.

Vault Policy is the exact selected shared runtime's prospectnode.Policy under
the fixed fixture network/genesis. Its configuration is fixed before the vault
opens and compared again against the constructed runtime; mismatches refuse.
ProviderConfigSHA256, IdentityConfigSHA256 and VaultConfigSHA256 below mean
SHA256 of canonical bytes of those exact inherited normalized persisted config
structs. In particular IdentityConfigSHA256 hashes normalized IdentityConfig
with Accounts.Principals sorted by the existing exported PrincipalID function,
not by fixture name or input order. Verifier
digest keeps its inherited domain/encoding, not this generic config hash rule.

### A.2 Initialization and durable stage receipts

`HostedInit` field order:

```
version, mode, descriptor_id, authority_id, coordinator_id, hosted_vault_id,
provider_driver_id, wrapper_id, verifier_config_hash, identity_config_sha256,
provider_config_sha256, vault_config_sha256, wallets
```

`wallets` is exactly two `WalletOwnerPin` objects with field order
`fixture, wallet_owner_id`, in fixed fixture order. Mode is
`local-hosted-fixture-pool`; driver/wrapper IDs are A.1 constants. IDs and config
digests are computed before INIT is synced. The additive constructors have
these exact parameter positions (the existing APIs are untouched):

```
gymaccount.CreateIdentityPinned(path, config, authorityID)
gymaccount.OpenIdentityPinned(path, config, authorityID)
gymprovider.CreatePinned(ctx, path, config, accounts, verifier, coordinatorID)
gymprovider.OpenPinned(ctx, path, config, accounts, verifier, coordinatorID)
recoveryvault.CreateHosted(ctx, path, config, accounts, wrapper, hostedVaultID)
recoveryvault.OpenHosted(ctx, path, config, accounts, wrapper, hostedVaultID)
```

Each validates expected ID/config before store mutation, including existing-ID
comparison before accepting an open. The constructors may share private code
with the old APIs; the old random-ID creation defaults remain unchanged.

`setup/` allows only these immutable files in order: `authority.json`,
`coordinator.json`, `driver.json`, `vault.json`, `runtime.json`,
`fixture-zero256.json`, `fixture-incrementing256.json`, `current.json`.
A complete prefix plus at most the next unfinished initializer is allowed.
Each `SetupReceipt` field order is
`version, stage, init_sha256, identity_sha256`, where stage is exactly the file
stem. INIT SHA hashes its canonical bytes; identity SHA hashes the corresponding
canonical exact expected ID/config or fixture binding, never arbitrary marker
contents adopted after the fact. The stage identity preimages are:

| Stage | Canonical preimage, exact field order |
| --- | --- |
| authority | `authority_id, identity_config_sha256` |
| coordinator | `coordinator_id, provider_config_sha256` |
| driver | `provider_driver_id, coordinator_id, provider_config_sha256` |
| vault | `hosted_vault_id, authority_id, vault_config_sha256` |
| runtime | `source_binding_id, descriptor_id, authority_id` from the owned inner runtime |
| fixture-* | that exact `CurrentBinding` |
| current | `version, bindings` of the current store marker |

Inner runtime setup/restart continues its already-qualified exact marker
protocol, with the outer pinned authority and descriptor supplied as expected
inputs. A stage receipt may be recovered only by auditing its concrete owned
store under those pins; it cannot authorize replacement of an established store.
Fixture receipts additionally require the account's verified vault Receipt and
installed wallet/recipient/withdrawal readiness. The typed CurrentBinding pins
the INIT WalletOwnerID; no generated ID is learned from an untrusted receipt.

`HostedReady` field order is
`version, init_sha256, authority_id, coordinator_id, hosted_vault_id,
source_binding_id, fixtures`. `fixtures` is exactly two objects ordered
`fixture, current_binding`, fixed fixture order. Current binding values are
those in §7, with `vault_binding` as the nested Binding key. Every stage must
exist and match before READY. INIT/READY each cap 32768 bytes; each stage cap
8192 bytes. These fixed schemas are public ownership metadata, not secrets.

The hosted vault's additive mode marker field order is
`application, version, hosted_vault_id, authority, config`, where application is
`slug-hosted-fixture-recovery-vault`, authority is existing AuthorityInfo and
config is existing vault Config. Old Vault.Open refuses this application before
opening its database. Current store marker order is
`application, version, bindings`, application
`slug-hosted-current-recovery`, exactly two §7 bindings in fixed fixture order.
Each of these markers caps at 32768 bytes and uses the same synced initialization
closure as its owned store. Existing mode markers are not rewritten.

### A.3 Driver records and exact pending lookup

Driver state field order is
`version, driver_id, coordinator_id, config, revision, clock_high_water_ms,
epochs, auth, resets`.
`config` is the inherited complete coordinator Config, including AuthorityID.
Revision starts at 1 and increases once per acknowledged state transition;
uncertain writes poison instead of advancing the in-memory acknowledged state.
`epochs` has exactly two rows ordered
`fixture, subject, credential_epoch, pending_event_id`, fixed fixture order.
Epoch starts at 1; pending EventID is `""` or the exact own unresolved reset.

`auth` holds up to 1024 `FixtureAuth` rows in ascending sequence:
`version, sequence, fixture, subject, auth_id, flow, credential_epoch,
authenticated_at_ms`.
Sequence is its immutable insertion index beginning at 1. Flow is the exact
inherited LoginFlow. Auth ID is random before durable insertion. A duplicate
exact FlowID requires all bindings to match and reuses this row. No row/ID/time
can be changed to make an old authentication fresh.

`resets` holds up to 256 `FixtureReset` rows in ascending sequence:
`version, sequence, fixture, subject, account_id, operation_id, request,
from_epoch, to_epoch, verified_at_ms, phase, begin_ack, complete_ack`.
Request/acks use exact inherited ResetRequest/ResetResult field order. Phase is
`verified`, `committed`, `completed` or `retired`; acknowledgment fields are
explicit null before their stage. `verified` has both null and reserves the
fixture's pending slot. `committed` has the exact CanCommit pending begin_ack,
null complete_ack and exactly one atomic From→To epoch mutation. `completed`
retains that begin_ack and matching completed result, and clears only its own
pending slot. `retired` is an expired never-begun row with both acks null and no
epoch change. No transition can regress or reuse an old pending slot. ToEpoch
must equal FromEpoch+1 without overflow. Epoch/slot/row changes are one synced
atomic driver-state replacement; no assertion is issued before its prerequisite
state is acknowledged or exactly recovered by reopen.

`FixturePendingReset` is a private owned result with exact field order
`version, fixture, account_id, operation_id, request, from_epoch, to_epoch,
verified_at_ms, phase`. It returns only the row referenced by the fixed selected
fixture pending slot, after checking all references and owner bindings. No row
means typed not_found. It never searches by subject for the latest record.
PendingReset does not mutate state; each resumed evidence/commit call verifies
the original exact tuple again. Parent setup may call it before any session
exists, because it discloses only local fixture-control metadata to its retained
trusted controller, not account-authorized UI data.

Each auth row cap is 2048 bytes and reset row cap 4096; whole canonical driver
state cap is 4194304 bytes. Counts/encoded-size preflight occurs before replacing
the file. One old state and one staged exact replacement plus their encodings
fit the separate 16-MiB accounted driver allowance. Driver initialization and
state writes are outside account leases, with exclusive owner/regular-file/
canonical-root checks, file sync + atomic replace + directory sync and poisoned
uncertainty. No automatic compaction drops replay records. Reopen audits every
bounded row, unique ID/flow/event, ordered sequence, both pending slots, epoch
chain and clock before signing anything. Epoch chain may include retired rows
without mutation; committed/completed rows establish the exact final epoch.

### A.4 Current store framing and integrity

The current store uses only these LevelDB keys/values (ASCII keys, raw canonical
JSON values without LF):

| Key | Ordered value |
| --- | --- |
| `meta` | `version, marker_sha256, actions, clock_high_water_ms, current` |
| `action/<capture_id>` | exact §7 CurrentCheckpoint |

`current` is exactly two `CurrentPointer` rows ordered
`account_id, revision, capture_id`; initial revision 0 and capture_id `""`.
Its order matches marker bindings. Nonempty pointers must reference the latest
retained own checkpoint revision; every action has exactly one bound account
and immutable CaptureID. `actions` is the total count 0..128, not a per-account
counter. Every own sequence is contiguous 1..current revision, with
expected_revision=revision-1, monotone capture times, committed times and branch
cursors; capture time may equal the previous time but may not decrease. Global
clock highwater equals the maximum committed_at_ms, zero only when empty.
Reject unknown keys, missing actions/pointers, duplicate own revisions, dangling
references, mismatched hashes or a count inconsistent with actual rows. Database
audit visits at most 130 entries including a refusal witness. Old action
content must remain equal to its canonical encoded bytes.

One commit updates the new action plus meta in one Sync batch, with <=12288
prepared key/value bytes total. Meta caps at 4096 bytes; checkpoint caps at8192
and manifest at4096. Total canonical stored key/value bytes cap is 2097152.
Marshal/hash/allocation, cursor comparisons and whole-store audit are outside
the original account lease, under the pre-acquired store permit. The final
original View/epoch fence executes only the bounded batch commit and required
postcheck, with no new store/account lock acquisition. No JSON parser or raw
store reader turns a Manifest into a live capture capability. There is no
pending-action row or cross-process uncommitted-capture recovery promise.

CurrentSource.Close joins its capture/export, not the borrowed wallet. The
opaque PreparedCurrentExport retains its current owner and destination until
Close; only one can exist per admitted child operation. Its exact public pin is
§8 and its concrete constructor is
`OpenCurrentDestination(ctx, pin CurrentDestinationPin, protectedRoots []string)`.
Protected roots come from the retained runtime/authority owners, never the UI.
No secret callback, generic writer or configurable larger file cap is provided.

### A.5 Wire reuse and implementation boundary

No new private recovery payload or checkpoint family crosses IPC. Existing
Pool/account/backup request/response shapes, full View binding, native selected
file Pin and response-size ceilings stay exact. Only the explicit launch mode
and bounded `hosted_reset_pending` account error are additive. In that state the
existing fixture selection and Reset action target the selected pinned pending
fixture; no provider operation/request/ack is accepted from the webview. Internal
owned Go types above provide the concrete lifecycle consumer. All private
result/error strings remain sanitized as §10 specifies.

The independent input inventory must freeze the two old published fixture
manifests, RFC7515 key/config, old vault envelope/wrapper source and existing
canonical config/Binding/ResetRequest/ResetResult/manifest contracts. Freeze
producer source before its first execution. Size composition separately proves
each new record/aggregate bound using these exact fixed strings and scalar
limits; producer examples do not become runtime trust pins. No opaque capture,
account capability or real secret can be created by a byte vector.
