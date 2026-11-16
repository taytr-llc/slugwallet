# Set 29 — fixture recovery vault and provisioning contract

November 16, 2026. Engineering implementation approved on the stacked
`slug-recovery-vault` branches. This slice uses only the published zero256 and
incrementing256 wallets. It does not issue a production wallet, select a provider,
create an operator key, or change the approved profile, chain, recovery words,
reset assurance, or 24-hour hold.

## Deliverable

Add a provider-neutral envelope-encrypted vault in the **wallet repository**,
package `recoveryvault`. Prove durable same-wallet reservation, retained recovery,
scoped signing, authorized snapshot export, and wrapping-key rotation with a
fixture wrapper. The chain module must not import the wallet module or expand the
node workspace. Existing desktop modes and account schemas retain their defaults.

This set retains **immutable fixture snapshots**: ProvisionFixture
uses the exact existing DefaultAccounts manifest, with no caller cursor metadata; no address allocation,
no cursor updates, and no claim that the initial snapshot stays a complete backup
of a subsequently changing production wallet. Every export carries the exact
retained, validated manifest. A future cursor checkpoint protocol must precede
such a claim. The two fixed public identities remain an explicit allowlist.

## Hold boundary

Full recovery material is an export capability, regardless of its label. A new
device under D72's hold must never receive entropy, mnemonic, BIP32 seed/root
private key, a recovery envelope data key, or a full wallet restore under a
"mining" operation.

Retain two independently encrypted purpose-bound payloads per account:

- `recovery`: original entropy plus the exact validated recovery manifest.
- `gym-signing`: only the fixed gym private scalar, whose public key must match
  that manifest and the independently published fixture tuple.

During the hold, the service may use the gym envelope internally to return only
typed enrollment/recovery or prospect-admission signatures. Neither scalar nor
plaintext is returned. The service does not unwrap the recovery envelope for
these requests. Signing never claims proof validity, freshness, birth, account
login, or fighter ownership; existing verifier/registry boundaries still apply.
There is no withdrawal signer, arbitrary digest/path signer, or generic decrypt
endpoint in this set.

Viewing uses public retained identity and existing public chain observations.
The initial fixed payout is independently verified in acceptance. General new-device
watch-only scanning needs account public descriptors, because a master xpub
cannot derive hardened account xpubs; do not claim that new wallet UI is shipped
by this foundation. Existing copied wallets/exports remain outside a hosted
hold's ability to revoke their keys, as already stated in D72.

## APIs

```go
type KeyWrapper interface {
    ID() string
    Wrap(context.Context, string, [32]byte, []byte) ([]byte, error)
    Unwrap(context.Context, string, []byte, []byte) ([32]byte, error)
}
// Wrap arguments: trusted key reference, DEK, wrapping AAD.
// Unwrap arguments: trusted key reference, wrapped blob, identical wrapping AAD.

type Config struct {
    Version uint32
    WrapperID, RecoveryKeyRef, GymKeyRef string
    AllowedRecoveryKeyRefs, AllowedGymKeyRefs []string
    MaxOperations uint32
    Policy prospectnode.Policy // explicit, immutable admission policy
}

type Binding struct {
    Version uint32
    AuthorityID, AccountID, PrincipalID, ProvisionID string
    Network uint32
    Genesis, Profile, RootPublicKey, GymPublicKey, GymID string
}

type Envelope struct {
    Version uint32
    Binding Binding
    Purpose Purpose // recovery or gym-signing
    ContentRevision uint64
    ManifestHash, Nonce, Ciphertext, WrapperID, KeyRef string
    WrapRevision uint64
    WrappedKey string
}
```

All stored fields have exact snake_case JSON names; byte strings are canonical
lowercase hex. The wrapper identity and allowed key references are trusted
configuration, pinned on create/reopen; they are not supplied by a request.
Recovery/gym key allowlists are disjoint. Initial and rotation target references
must belong to their corresponding configured allowlist. A wrapper must honor
context cancellation and bounded requests. Provider errors are sanitized.
No live KMS adapter or default secret is provided. Test wrapping uses only
explicit published KEKs in test support.

The private service boundary provides these methods:

```go
Create(ctx, path, config, accounts, wrapper) (*Vault, error)
Open(ctx, path, config, accounts, wrapper) (*Vault, error)
(*Vault).ProvisionFixture(ctx, loginToken) (Receipt, bool, error)
(*Vault).EnsureEnrollment(ctx, loginToken) (Receipt, error)
(*Vault).SignAccountChallenge(ctx, loginToken, challenge) (gymaccount.Authorization, error)
(*Vault).SignAdmission(ctx, miningToken, chainContext, proof) (gymauth.Authorization, error)
(*Vault).ExportRecoveryFile(ctx, loginToken, absoluteNewPath) error
(*Vault).Rewrap(ctx, loginToken, recoveryKeyRef, gymKeyRef) (Receipt, bool, error)
(*Vault).Status(ctx, loginToken) (Status, error)
(*Vault).Close() error
```

Receipt contains immutable public Binding, ManifestHash, Manifest and RetentionID.
Status adds phase/revisions/key references; neither output contains envelopes. No exported entropy, scalar, plaintext,
DEK, or generic caller-controlled secret callback is added. Export writes directly
to an explicit new native destination; it does not return an Export object to
an untrusted callback and authorize afterward.

`AuthorityInfo` must acquire the existing context-aware account gate and return
only an owned public schema/version/authority/config-digest/chain/profile snapshot
without principal-map disclosure. `EnrollmentIdentity(ctx, loginToken)` returns
only the current Account and exact configured Identity under its Enrollment lease;
the vault selects the corresponding published fixture internally. No mutable
Config slice aliases and no unlocked metadata reads. Vault creation
requires schema 2, and reopen must match the same authority and complete public
policy. Do not silently reopen against another authority or schema-1 fixture.

## Cryptographic byte contract

Content encryption is AES-256-GCM, 32-byte independent DEK per envelope, 12-byte
nonce, full 16-byte tag. A DEK is used for exactly one content encryption; retries
reuse a durably sealed envelope rather than reusing a key/nonce with new content.
Disposable encryption randomness in tests does not create wallet/provider/operator
identity. Independent vectors use explicitly fixed public test randomness.

Content AAD is this exact concatenation:

```
ASCII "SLUG recovery vault content\x00v1\x00"
Binding.Version LE32 (=1)
AuthorityID raw32 | AccountID raw32 | PrincipalID raw32 | ProvisionID raw32
Network LE32 | Genesis display-hex decoded32
Profile [byteLength LE32 | ASCII]
RootPublicKey [byteLength LE32 | canonical Base58 ASCII]
GymPublicKey compressed33 | GymID raw32
Purpose [byteLength LE32 | ASCII]
ContentRevision LE64 (positive) | ManifestHash raw32
```

`ManifestHash` is SHA256 of the canonical validated `recovery.Manifest` JSON bytes.
Both purposes bind the same manifest. Session generation and provider epoch are
not content identity: reset must preserve the same wallet. Their current values
are authorization checks and audit observations, not permission to replace AAD.

Wrapping AAD is:

```
ASCII "SLUG recovery vault wrap\x00v1\x00"
SHA256(contentAAD)32
SHA256(nonce12 || ciphertextIncludingTag)32
WrapRevision LE64 (positive)
WrapperID [byteLength LE32 | ASCII]
KeyRef [byteLength LE32 | ASCII]
```

Recovery plaintext: `LE32(1) | entropy32 | manifestByteLength LE32 | manifestJSON`.
Gym plaintext: `LE32(1) | scalar32`. Validate decrypted entropy against the whole
manifest and fixture tuple, and gym scalar against the exact compressed public
key. Do not retain mnemonic strings; construct them only during permitted export.
Clear owned buffers/keys best-effort without claiming complete Go heap erasure.

Fixture wrapping may use AES-GCM with public KEKs and blob
`nonce12 | ciphertext(DEK32) | tag16`; the production-neutral interface treats a
wrapped blob as opaque. The corpus reproduces independent published AES-GCM
vectors before deriving SLUG binding vectors. No implementation output is copied
as a golden expectation.

## Durable reservation and cross-store ordering

A unique account index points to one permanent provision reservation. Reserve
under the authenticated schema-2 provisioning lease **before** creating
material. Pin authority/account/principal, chosen fixture, profile/chain, exact
public root/gym and provision ID. Caller input cannot select a replacement
fixture, path or root. Reservation failure, seal failure, lost acknowledgment or
process death never authorizes replacement identity.

States are `reserved -> sealed -> verified -> enrolled`; the final state links
a separately committed account result. Sealed means both purpose envelopes are synced atomically with
the reservation. Verified means unwrap/decrypt/rederive checks succeeded for both
and an immutable public retention receipt was synced. Only then can the vault
sign the existing enrollment challenge. A completed account enrollment can be
linked/reconciled afterward by reading its exact durable tuple. Do not claim an
atomic transaction across the account and vault databases. A crash after account
commit but before vault linking must resume that same completed account/receipt,
not re-enroll or create another seed. Fixed fixtures prove this transaction
protocol; they do not prove a future external random-wallet-generation service.

Reserve bounded journal capacity for every remaining transition and its final
replay receipt before starting. Sync atomic LevelDB batches, validate canonical
bounded records/cross-links at open, refuse missing established records, and
poison the handle on uncertain writes. After an uncertain result, close/reopen
and inspect the same operation; never silently restart or create a replacement.
Exact completed retries return the first public receipt. Old expired/revoked
sessions still cannot retrieve it through a capability bypass.

## Authorization, I/O and reset races

Use only `account -> vault` lock order. Never call the account store while holding
a vault lock. Never hold an account lease across wrapping-provider work, node RPC,
Argon hashing, UI interaction or user input.

1. Check the original token/capability and copy the matching account generation,
   binding and exact envelope revision under short account/vault leases.
2. Release leases, do bounded provider/crypto preparation, retain owned temporary
   plaintext only inside the trusted service. Outage/cancellation has no fallback
   to hardcoded fixture material or a previous session.
3. Reacquire the **original** token's lease; require the same account/generation,
   unchanged binding/revision and final recheck before durable publication or
   signature delivery. Pending reset, logout, expiry, rotation or close fails
   and clears prepared material. A newly issued token cannot rescue an old operation.

Provisioning requires the schema-2 `WithProvisioning` lease: current login,
fresh authentication and no active hold, including an account not yet enrolled.
Its original-session final recheck has the same restrictions. Typed account
challenge signing requires Enrollment and uses only the gym envelope. Admission
signing requires Mining with the exact original parent login and the explicit
immutable Config.Policy; callers cannot replace that policy per request. Full export requires RecoveryExport and uses the recovery envelope
only after that check. Rewrap requires RecoveryAuthority, so the 24-hour hold also
blocks it. New-device gym operations unwrap only the gym envelope. Publish typed
signature output only at the final authorized linearization point.

Export uses a bounded new file with exclusive creation and mode0600. No overwrite,
symlink following of an existing destination, raw path/phrase logging, browser
response or clipboard output. Recheck immediately before protected local write;
write/sync/close and report errors honestly. An I/O error may leave a private
partial or fully committed file; retain it for explicit reconciliation rather
than deleting user files or claiming no disclosure. No dialogue/provider/network
work happens under the final local export lease. The vault excludes its own
canonical storage root. A coordinator must apply its broader protected-root
policy (including account and wallet directories) before calling this direct
file-export API; the desktop native destination checks already do this. There
is no remote arbitrary-path endpoint.

## Rotation, limits and acceptance

Rewrap decrypts only the DEK outside leases, wraps it to an allowed target, and
verifies the new wrapping before publication. It changes only key reference,
wrapped bytes and wrap revision; content ciphertext, nonce, entropy, profile,
manifest, root/gym, prospect evidence and birth remain unchanged. Publish both
purpose wrapping changes in one sync batch with original-revision CAS. An
outage leaves the old committed envelopes authoritative. No KEK deletion or
operator provisioning occurs in this set.

Hard bounds: two accounts; at most128 logical operations; key
references/WrapperID at most128 ASCII bytes; up to8 allowed key references per
purpose; recovery plaintext at most65,576 bytes; wrapped key at most8KiB; one
serialized envelope at most192KiB; row at most256KiB. Bound before allocation and
copy input slices before waits. Provider calls have a30s context deadline; the
adapter must honor it. Physical LevelDB compaction disk use is not represented
as an exact serialized-byte quota.

Acceptance includes independent AEAD/AAD/purpose substitution and tamper vectors;
two-account isolation; concurrent same-account provisioning; lost replies and
real process termination at every durable boundary; reopen with missing/corrupt
state; cancellation/close during unwrap; reset/rotation concurrent with preparation;
hold denial without any recovery unwrap; same-gym enrollment and actual mining
via the gym envelope while held; exact snapshot export after hold using a private
test clock; fresh wallet restore from that file with original data inaccessible;
rewrap+reopen+export equality; rejected keyref/provider/config swaps; capacity
reservation and uncertain-write poisoning. No assistant-created real keys,
provider accounts, KMS resources, public endpoints or seed-chain mining.

## Later decisions and evidence

No new user decision is required to implement this fixture slice. The production
profile/coin allocation and genesis, real provider's demonstrated reset guarantee,
operator-owned vault deployment/region/resources, and later exclusive migration /
fighter-transfer rules remain separate launch decisions. D48/D70/D72 are not
reopened. Do not invent an MFA/manual-assurance requirement. Current cursor
synchronization, watch-only new-device UI, production entropy issuance, external
KMS adapter, anti-rollback storage operations and disaster recovery need concrete
engineering work and acceptance before production claims.

Primary technical references: [NIST SP800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final)
defines GCM authenticated encryption with associated data;
[Go crypto/cipher](https://pkg.go.dev/crypto/cipher#NewGCM) documents nonce use.
The [KMS envelope concept](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#enveloping)
is an architectural example, not selection/provisioning of AWS. Local source
contracts are wallet `recovery`, `wallet.SignAccountChallenge` and
`wallet.SignProspectAdmission`, plus chain `gymaccount` schema2, `gymidentity`, and
BRAWLCHAIN_SPEC D48/D70/D72.
