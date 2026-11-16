# slugwallet

SLUG wallet foundation, forked from btcsuite/btcwallet **v0.18.1** at
`43f2950d2a065a7b3d4a4a1cf17ed1e84af6bcb4`. The implementation lives on
`slug-desktop-wallet` for set 26 (activation: `slug-phase-a-activation`); the
fork's upstream-tracking `master` is not this release. Upstream source and license history are preserved.

This fork provides a full-node wallet backend and an explicitly public-fixture
recovery/signing profile. Set24 adds retained 24-word English BIP39 recovery
with no extra BIP39 passphrase, a SLUG manifest, and a fixed wallet-derived gym
identity. Hosted login, real custody and real-wallet issuance are not enabled.
Do not issue real wallets from this fixture foundation.

## Build with the paired SLUG checkout

Use Go 1.27.4 and sibling checkouts:

```text
slug/
  slug/        # reviewed paired chain revision, including ConnectContext
  slugwallet/  # slug-desktop-wallet
```

The wallet's `go.work` covers its six runtime modules and the ten SLUG modules.
Every wallet module also has explicit relative replacements for the paired
sources. The chain workspace is unchanged. `rpcclient.ConnectContext` from the
paired set 23 or later chain revision is required; upstream btcd cannot substitute for it.
The pinned paired set 25 chain revision is
`11664083bd87d33b7a127d7950cf170561543c3f`, also pinned in
`.github/workflows/main.yml`.

```sh
go build -o /tmp/slugwallet .
go test ./...
for module in wallet/txauthor wallet/txrules wallet/txsizes walletdb wtxmgr; do
  (cd "$module" && go test ./...)
done
```

`go build ./...` checks the root module's packages. `go build -o ... .` creates
the daemon. `make install` also installs the inherited maintenance utilities;
they are administrative tools, not gym UI flows.

## Full-node connection and namespaces

The supported daemon path connects to **slugd WebSocket RPC**. It verifies the
selected network magic and genesis before delivering wallet notifications.
Every reconnect constructs a fresh client and repeats these checks. Transport
auto-reconnect is disabled so it cannot resend an unacknowledged spend before
checking the replacement server. Callers must resolve an ambiguous send through
transaction lookup; there is no automatic transaction replay on a new transport.
Connection startup has a 30-second context bound, including the handshake.
Daemon shutdown cancels startup/retry work and drains the active chain client.

Neutrino/SPV and Bitcoin Core adapters are deliberately excluded. There is no
backend fallback. The internal full-node backend identifier remains `btcd` for
compatibility with existing wallet logic; its types and RPC client are SLUG.
The experimental gRPC loader can start a pinned connection, but does not offer
the daemon connection loop's automatic replacement after transport loss.
The inherited currentness check waits when the node tip is over two hours old;
a quiet fixture chain needs a new block before wallet synchronization starts.

| Setting | SLUG mainnet foundation |
| --- | --- |
| Node RPC | `127.0.0.1:29332` |
| Wallet RPC | loopback, port `29334` |
| Config / log | `slugwallet.conf` / `slugwallet.log` |
| Database | `mainnet/slugwallet.db` beneath the wallet application directory |
| Application directory | OS-specific `slugwallet` directory; override with `--appdata` |
| Node CA copy | `slugd.cert` (or slugd's `rpc.cert`) |
| Witness prefix | `slug` |

The commented [sample configuration](sample-slugwallet.conf) uses private
loopback examples. Keep credentials in a protected configuration file, not
command arguments or the webview. Wallet RPC must not be exposed on Railway.
Explicit upstream test-network params remain available for tests; they are not
alternate SLUG production deployments. A `slugtestpow` daemon refuses startup
before config or wallet-file operations, and its version output marks it disabled.

## Verification and recovery limits

Run the public-fixture integration against a normal production-PoW node:

```sh
SLUG_WALLET_NODE=/absolute/path/to/slugd ./integration/run-foundation.sh
```

The [fixture gate](integration/README.md) verifies independently derived receive
and change addresses, production Argon2id blocks, the 10 SLUG reward, maturity,
spending, reopen, and fresh raw-seed restoration followed by another confirmed
spend. It uses only the published BIP32 vector seed and a disposable isolated
loopback chain. It never connects to the live seed.

Mainnet HD exports use SLUG's public/private version bytes for every supported
scope. The network prefix alone does not identify purpose or address schema.
The [encoding oracle](waddrmgr/testdata/README.md) independently recomputes SLUG
checksums; the [recovery oracle](recovery/testdata/README.md) independently derives
the phrase, BIP32 keys, addresses, and gym identity.

## Phase-A spending (set 25)

The paired chain activates the approved Phase-A rules at height 62. Wallet RPC
checks the node's explicit Segwit/Taproot activation metadata and a matching tip
snapshot before authoring a spend. A pre-upgrade node with the same chain identity
is refused; network magic and genesis alone do not prove upgraded software.
Update all nodes before mining beyond the agreed activation boundary.

For `sendtoaddress` and account 0 `sendfrom`/`sendmany`, eligible inputs come from
exactly the four default scopes 44/49/84/86. Custom scopes are excluded. Account
names remain resolved within scope 44; nonzero named accounts and the imported
account remain restricted to that scope, never a same-numbered account elsewhere.
All RPC change is explicit legacy P2PKH from scope 44, preserving the Phase-A
payout/change contract and avoiding an implicit Taproot change default.

Before activation, RPC selects legacy inputs and rejects witness/Taproot
recipients. It also conservatively rejects opaque P2SH recipients, whose redeem
script could depend on witness enforcement. After activation, every Phase-A
RPC-authored transaction is signed with locktime 61 and sequence 0xfffffffe, making
it non-final below height 62 even if the tip reorganizes after the readiness
check. This does not enable relative timelocks or opt-in replacement. Existing
wallet-library send defaults remain unchanged; explicit creation options are
available for callers that need scope restrictions or a minimum inclusion height.
Other networks use their node's reported deployment state, without a global
height 62 assumption.

The [set 25 notes](CHANGESET_25_NOTES.md) and [activation integration](integration/README.md)
record normal-PoW spending and export-only restore across all four scopes, plus a
witness-bearing block template. This remains fixture evidence, not real custody.

```sh
SLUG_WALLET_NODE=/absolute/path/to/slugd ./integration/run-activation.sh
```

## Retained fixture recovery (set 24)

The new library APIs are `Loader.CreateNewRecoveryWallet`,
`Wallet.ExportRecovery(context.Context)`, and `Loader.RestoreRecoveryWallet`.
Creation takes caller-owned 32-byte entropy; restoration takes a validated
`recovery.Export`. These APIs are deliberately not exposed as daemon/RPC secret
methods or webview output. The approved phrase is exactly 24 English BIP39 words
with no additional BIP39 passphrase. Wallet unlock passwords are separate and
can be rotated without changing the recovery identity.

Creation commits encrypted recovery material, its public manifest and wallet
initialization in one database transaction. Later export requires the wallet to
be unlocked and works after close/reopen; it reads committed address cursors in
one local transaction. Recovery wallets use mandatory address-manager schema 9
and explicit standard BIP32 derivation. Existing raw-seed wallets retain schema 8
and historical derivation. No migration invents a phrase, changes an old wallet's
paths or converts its keys. Old binaries refuse schema 9. Missing or damaged
recovery state fails closed.

The profile is `slug-phase-a-fixture-bip39-v1`, pinned to normal SLUG mainnet.
It preserves coin type0 and account 0 in scopes44,49,84,86. Scope49 retains the
existing mixed nested-witness receive/native-witness change schema. Each branch
supports next-index 0 through 4096; issuing beyond that limit is refused. Extra
accounts, imported keys/scripts or unsupported scopes cause export/signing to
refuse a partial recovery promise. Root-key neutering and conversion to
watch-only are refused for retained-recovery wallets, since retained entropy
would contradict their private-key erasure semantics.

The manifest records the exact chain, standard derivation, account schemas,
current receive/change high-water indexes, genesis scan start and public gym
identity. Restore into a new database derives every advertised index before
committing, then scans the chain. The phrase **and current manifest** form this
recovery export; a bare phrase does not encode address usage or profile details.
Exports are snapshots: addresses issued after an export need updated metadata
for recovery beyond the ordinary gap window. The format does not export
imported keys, arbitrary accounts or registry receipts.

`Wallet.GymIdentity` returns the fixed public identity even while locked.
`Wallet.SignProspectAdmission` and its pinned worker callback sign only the
versioned admission action after unlock, without returning a private key or
accepting an arbitrary derivation path. The fixture path is
`m/1397511495'/1'/0'`. The authority still separately checks proof work, job
freshness and canonical eligibility. A signature does not establish account
ownership, a new birth, transfer or exclusive migration.

Run the separate retained-material and normal-PoW gate with:

```sh
SLUG_WALLET_NODE=/absolute/path/to/slugd ./integration/run-recovery.sh
```

See [set 24 notes](CHANGESET_24_NOTES.md) and the [integration contract](integration/README.md)
for exact evidence and current chain restrictions. D48 still needs hosted normal
login, custody/account authorization, secure user-facing reveal/export and real
issuance policy. Exported Go values contain secret caller-owned strings; callers
must protect them and avoid logs/RPC/webviews. Memory clearing is best effort.
No production custody, arbitrary-wallet recovery or fighter transfer is claimed.

The [set 23 notes](CHANGESET_23_NOTES.md) preserve the foundation's historical
scope and verification evidence.
SLUG wallet retains the ISC license in [LICENSE](LICENSE).

## Restricted embedded RPC for the desktop pilot

Embedders may set `legacyrpc.Options.AllowedMethods` to an explicit method list.
The server copies the list; nil preserves legacy behavior and a non-nil empty
list denies every method. Enforcement covers HTTP and WebSocket dispatch,
including `stop` and node passthrough. Restricted HTTP requires POST `/` without
query strings or an Origin header. Set `MaxWebsocketClients` to zero to disable
WebSockets. Authentication and the existing request/concurrency limits still
apply; an allowlist is not a substitute for a private listener.

The local desktop fixture uses only public address/balance/history methods over
its owned loopback listener. Private recovery and gym signing stay in-process.
See [set 26 notes](CHANGESET_26_NOTES.md); this does not enable real custody.
