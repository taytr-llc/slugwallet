# SLUG wallet fork

This is the separate btcwallet fork for SLUG. Mike authorized the new Go gym
shell against slugd/btcwallet RPC, the wallet fork when its workstream starts,
and continued build/test/promotion work toward the desktop pilot. No per-set
approval is needed for that scope. Real signup/custody and production genesis
remain separate decisions.

Mike approved D73's separate production recovery profile on November 16:
dedicated SLUG coin type, four payment scopes, native84 receive/change defaults
and a permanent-chain-bound gym. Preserve existing fixture/legacy profiles;
final allocation/genesis and frozen recovery tests still gate real issuance.
See the paired chain PRODUCTION_WALLET_PROFILE.md. He also requires a thorough
joint design review before friends/tester or public product release (D74);
the paired LAUNCH_READINESS.md tracks that gate. Engineering work continues.

Mike requires strict mandatory MFA for hosted email/password login and passkey
support (D82, November 19). See the paired `HOSTED_AUTHENTICATION.md`. Existing
fixture assertions do not attest MFA; do not infer it from authentication time
or alter frozen codecs silently. Preserve D72's reset/hold without a second-factor
bypass. Mike requires a backup factor/code with no support bypass. The exact
account recovery-code proof is still proposed; the 24-word wallet phrase is not
automatically a hosted-login reset code and must never be requested by support.
This requirement does not change wallet derivation or authorize real credentials.
Mike subsequently deferred login/provider/MFA and account-recovery UX work until
wallet recovery, fighter ownership/transfer and restoration of the same gym and
fighters are complete. Preserve D82 for later; continue core functional work
using existing fixtures. Key recovery alone does not close fighter recovery.

Mike approved D83's chain-ordered fighter transfers on November 19: first valid
competing send wins; later competing sends are void; ownership changes only at
signed checkpoint plus sixty descendants. Pending transfers retain the effective
owner for noon locks. See paired `FIGHTER_TRANSFER_POLICY.md`; actual transfer
and independently restored-gym ownership still require implementation. D72's
hosted-transfer hold and the report-only checkpoint doctrine stay intact.

## Source and branches

- Origin: `taytr-llc/slugwallet`; upstream: `btcsuite/btcwallet`.
- First implementation branch: `slug-wallet-foundation`, based on btcwallet
  v0.18.1, commit `43f2950d2a065a7b3d4a4a1cf17ed1e84af6bcb4`.
- Never open a pull request, force push, or publish changes to upstream.
- Develop numbered change sets on topic branches. The paired chain repository
  is `../slug`; set 23 follows desktop implementation `c0923eca`. Do not edit
  the chain's master branch. Its master auto-deploys the live Railway seed.
- Keep upstream available and record deliberate backend exclusions. The first
  wallet slice uses slugd's full-node WebSocket RPC backend. Bitcoin Core and
  Neutrino are outside this initial SLUG contract; no implicit Bitcoin fallback.

## Keys and recovery

- Never create, read, request, log, paste or commit a real operator/wallet seed
  or private key. In particular, never access `~/slug-checkpoint.seed`.
- Tests use explicitly published deterministic fixture seeds/keys on disposable
  loopback nodes. These are public fixtures, never real accounts or wallets.
- D48 requires hosted normal login plus full recovery export. Set24 implements
  fixture-only retained 24-word English BIP39 export with no additional BIP39
  passphrase plus SLUG metadata. This does not enable hosted custody, normal
  login, real-wallet issuance, secure UI reveal or fighter transfer.
- The approved fixture profile uses four account 0 scopes 44/49/84/86, coin type 0,
  explicit mixed49 schema, at most 4096 next-index per branch, genesis scanning
  and gym path m/1397511495'/1'/0'. New recovery wallets explicitly use standard
  BIP32 and mandatory manager schema 9. Legacy APIs/mode/schema 8 stay unchanged.
  Do not silently migrate existing wallets or change the fixture profile into
  a production custody/derivation decision. Never omit unsupported imported
  material or extra accounts from an export while claiming completeness.

## Chain and validation

- Use the local SLUG modules consistently; never mix upstream and SLUG wire,
  chainhash, address or params identities. Keep the chain workspace unchanged;
  this wallet gets its own workspace covering its six runtime modules and the
  ten SLUG modules.
- SLUG main network: magic `0x534c5547`, genesis
  `7893676099cf9985bb198dfb6a347d9422a19f2422cf3326a999a7230ce246cd`, node RPC
  29332, P2P 29333, HRP `slug`, P2PKH 0x53, P2SH 0x47, WIF 0xd3. Verify both
  network and genesis on connection/reconnection. Use a distinct wallet RPC
  port and file/config namespace.
- Header PoW is production Argon2id at 256 MiB per hash. Transactions, Merkle
  trees and sighashes remain SHA256d. Audit wallet BlockHash calls for repeated
  expensive work; do not add an SPV verification path or accept claimant hashes.
- Independent expected vectors must come from a separate derivation, never
  copying this implementation's output. Real export/restore/spend acceptance
  must eventually include normal production PoW; cheap tagged fixtures alone
  cannot close that requirement.
- Build/test every wallet module and record exact suites, timings and limits.
  Run gofmt and diff checks. Write the current CHANGESET_N_NOTES.md with behavior, deliberate exclusions,
  verification and remaining custody work; do not rewrite historical evidence.
- Keep wallet RPC private. Do not expose credentials through the gym webview,
  deploy a wallet service to Railway, connect fixtures to the seed or transfer
  real funds as part of this foundation.

## Desktop wallet pilot (set 26)

- The Go desktop shell owns a private loopback wallet RPC listener. Ordinary
  addresses, balances and history use that RPC; retained recovery and narrowly
  scoped gym signing remain in-process. Never add secret RPC methods to its
  explicit allowlist or expose a generic RPC console through the webview.
- `AllowedMethods` is immutable after server creation; nil means legacy default
  and an explicitly empty list denies every method. Enforcement must precede
  special shutdown and chain passthrough on every transport. Shutdown drains
  admitted requests before the owner unloads wallet storage.
- The desktop uses only the independently published zero256 fixture, with a
  separate LocalWalletPilot data directory. No real entropy, normal-login
  provider, real custody or public wallet service is authorized by this slice.


## Fixture account enrollment (set 27)

- The explicit account pilot adds only the published zero256 and incrementing256
  identities. The previous local-wallet mode remains zero256-only. Unknown or
  mismatched identities must fail before creating/replacing wallet data.
- `Wallet.SignAccountChallenge` accepts only the frozen enroll/recover contract
  and a separately pinned authority ID. It checks the retained public root/gym
  pair and uses the existing short unlock lease. No generic signer, secret RPC,
  wallet file read by the webview or production path allocation is authorized.
- D72 approves verified login reset recovering the same wallet without the
  phrase, with a 24-hour hold. Existing-wallet mining and viewing stay allowed;
  export, withdrawals, fighter transfer, recovery-authority changes and
  marketplace purchases/listings are blocked. Session revocation, exact reset
  replay and hold checks belong to the paired durable account authority.
- A backup copy does not revoke hosted recovery authority. Do not describe it
  as exclusive migration. Login verification and wallet encryption are distinct;
  private-password rotation is tested without changing the retained identity.

## Fixture recovery vault (set 29)

- Keep recovery and gym-signing envelopes separate and bind both to the exact
  retained authority/account/provision/root/gym tuple. Held enrollment/mining
  opens only the gym envelope and returns typed signatures, never private keys.
- Full-material provisioning requires fresh current authentication and no hold,
  including before first enrollment. Interrupted work resumes the same durable
  reservation. Provider I/O runs outside account/vault leases; publication uses
  the original token/generation and exact envelope revision.
- Recovery export and wrapping-key changes enforce D72 capabilities. No default
  KMS secret, production wrapper, arbitrary decrypt/sign API or live key issuance.
- The default fixture manifest is an immutable snapshot. Do not claim it tracks
  later addresses or is a complete current production-wallet backup. Keep the
  two public fixture allowlists and existing desktop defaults until subsequent
  work explicitly changes them. See `RECOVERY_VAULT.md`.

## Resumable candidate recovery (set 32)

- Explicit schema 11 has an exclusive pending session, bounded steps and the
  unchanged candidate profile2 export. Never silently migrate schemas 8/9/10.
  Pending state cannot become an ordinary wallet or sign/spend. Real issuance
  stays closed behind the existing production-profile gate.
- Preserve imported and issued cursors across interruption and reorg; unused
  lookahead is separate. Reserve 20 future attempts per branch within the
  aggregate 65,536-attempt quota, including after ready-wallet allocation.
- Bind progress to an exact canonical hash, commit ledger/index/progress
  together, audit pending storage on reopen and poison uncertain write outcomes.
  The full-node source rechecks identity on every physical connection and owns
  cancellation through socket close. No claimant-selected genesis or cheap PoW.
- Normal startup/watch costs remain O(total supported inventory), with explicit
  notification, owned-output and serialized request limits. Capacity failures
  keep schema 11 unsynced and unavailable for spending; do not omit a watch.
  See the paired chain `RESUMABLE_RECOVERY.md` for measured limitations.

## Bounded Phase A scratch recovery (set 69)

- Explicit schema12 is a disposable verifier for the unchanged version1 Phase A
  fixture file. It preserves coin0/mixed49, clipped20 lookahead,4096 per branch,
 32768 total raw attempts,128-child or one-block steps. No schema9 migration or
  schema11/profile2 reinterpretation; the approved production profile stays gated.
- Resume requires the original imported manifest from the selected file. Current
  live issued cursors are not a replacement import identity. Ready schema12
  retains version1 export/gym identity and cannot use CandidateWithdrawals.
- First schema12 database-close failure is sticky and retains the cleanup owner
  and Loader reservation. Never retry-to-success, remove uncertain scratch, or
  claim a stopped failed wallet is available. Preserve old schema11 cleanup APIs.
- This restores wallet history into scratch, not the installed app's durable
  withdrawal journal/reservations or hosted recovery authority. Library resume
  does not imply UI task resume after app restart. See CHANGESET_69_NOTES.md;
  its completed qualification and limits are recorded in the final evidence.

## Bounded own-wallet activity (set 70)

- `CaptureOwnActivity` is an atomic, read-only schema-9 Phase-A public snapshot.
  Read public retained root/gym/profile identity and the persisted sync stamp in
  the same transaction as bounded history. Do not load private recovery fields,
  unlock or derive private material, allocate addresses or modify wallet state.
- Keep fixed metadata/block-index traversal and raw-transaction/aggregate bounds;
  never replace them with an unbounded history RPC or whole transaction bucket
  scan. Owned credits/debits are integer storage facts, separate from current
  reservations, spendability and unmined-input conflict bookkeeping.
- Preserve canonical raw framing, checked amount totals and strict storage
  crosslinks. The five direct address forms are P2PKH, P2SH, P2WPKH, P2WSH and
  P2TR; unsupported scripts retain an empty address, not a substituted script.
- The paired desktop fences the original View/source/root/gym, checks live
  synchronization and both tip hash and height around capture, and joins capture
  or detail work before unloading. Existing RPC/history APIs remain unchanged.
  See paired `WALLET_ACTIVITY.md`, portable `wallet/testdata/own-activity`, and
  `CHANGESET_70_NOTES.md`; this does not enable production issuance or custody.

## Current hosted-fixture recovery (set 71)

- `CaptureCurrentRecovery` is a bounded public schema-9 snapshot from a retained
  concrete wallet. Never fetch private retention, decrypt/copy account private
  ciphertext or infer completeness from an unbounded scan. Keep the wallet open
  until the operation joins; its opaque capture is not a database lifetime lease.
- HostedVault and the current-checkpoint store have separate markers and APIs;
  preserve the old immutable vault and export contracts. Bind the exact account,
  retention, vault, wallet owner and source. Original committed capture replay
  may acknowledge its own action after later captures; a fresh export requires
  a fresh current capture, never a historical one presented as current.
- Acquire bounded vault/current permits before original account/epoch fences.
  Keep cryptography/provider calls and capture outside account leases; publish
  only the prepared bounded recovery file inside the final original export
  fence. Retain uncertain publication and failed-cleanup ownership. A held
  session may use typed gym signing, with no recovery-envelope unwrap or local
  signing fallback; full export remains blocked.
- This is public-fixture hosted composition and dated current export, not
  continuous allocation recovery, an external identity/KMS provider or restored
  payment-journal authority. Missing established stores fail closed. Preserve
  the independent references, paired frozen `HOSTED_CURRENT_RECOVERY.md` and
  actual-file recovery evidence. D73 real issuance and D74 remain separate gates.

## Durable hosted allocation recovery (set72)

- Fresh explicit schema13 uses the frozen paired `HOSTED_ALLOCATION_RECOVERY.md`.
  Old schemas, generic APIs and version1 recovery bytes retain their meanings.
  Bind the exact locked guard once; established inventory reopens through the
  full pairing audit. Never rebind a populated inventory or bypass its owner.
- Reserve recovery ceilings before wallet consumption and disclosure. Commit
  address/cursor/local links and reviewed change/input reservations atomically;
  retain burned, unused, abandoned and uncertain ranges. A lost private plan
  requires exact recovery or burn/abandon, never caller-supplied reconstruction.
- Keep generic allocation/import/sign/export bypasses closed, normal watches
  bounded to the audited frontier and the installed concrete RPC owner intact.
  Original account fences cover final bounded commits/disclosure; wallet, DB,
  crypto/network work and joins stay outside. Poisoning/cleanup ownership is sticky.
- Missing-wallet export uses surviving inventory; schema12 Verify remains
  inspection-only and cannot recreate payment journals or install a wallet.
  See `CHANGESET_72_NOTES.md` for independent references, funded recovery and the
  exact desktop/package qualification composite. D83 transfers/restored-gym use
  follow; real login and the final joint D74 review remain deferred.
