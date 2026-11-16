# SLUG wallet fork

This is the separate btcwallet fork for SLUG. Mike authorized the new Go gym
shell against slugd/btcwallet RPC, the wallet fork when its workstream starts,
and continued build/test/promotion work toward the desktop pilot. No per-set
approval is needed for that scope. Real signup/custody and production genesis
remain separate decisions.

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
