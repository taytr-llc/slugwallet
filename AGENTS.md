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
- D48 requires hosted normal login plus real full recovery export. Upstream
  raw-seed-at-creation and database backups do not satisfy a later seed phrase
  reveal. Do not claim custody, login, phrase export or fighter transfer exists
  until implemented and independently verified.
- Recovery/derivation decisions must be settled before real wallet issuance.
  Preserve current coin-type behavior for this fixture-only foundation.

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
  Run gofmt and diff checks. Write CHANGESET_23_NOTES.md with behavior, deliberate
  exclusions, verification and remaining recovery/custody work.
- Keep wallet RPC private. Do not expose credentials through the gym webview,
  deploy a wallet service to Railway, connect fixtures to the seed or transfer
  real funds as part of this foundation.
