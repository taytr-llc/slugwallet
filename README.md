# slugwallet

SLUG wallet foundation, forked from btcsuite/btcwallet **v0.18.1** at
`43f2950d2a065a7b3d4a4a1cf17ed1e84af6bcb4`. The implementation lives on
`slug-wallet-foundation`; the fork's upstream-tracking `master` is not this
release. Upstream source and license history are preserved.

This foundation provides a full-node wallet backend and public-fixture recovery
evidence. It is not a production signup, hosted custody, recovery-phrase export,
or gym-key derivation product. Do not issue real wallets from this foundation.

## Build with the paired SLUG checkout

Use Go 1.27.4 and sibling checkouts:

```text
slug/
  slug/        # reviewed paired chain revision, including ConnectContext
  slugwallet/  # slug-wallet-foundation
```

The wallet's `go.work` covers its six runtime modules and the ten SLUG modules.
Every wallet module also has explicit relative replacements for the paired
sources. The chain workspace is unchanged. `rpcclient.ConnectContext` from the
paired set23 chain revision is required; upstream btcd cannot substitute for it.
The paired chain implementation is
`4dc49e103ce271981a20a08a115dbfacc6aa6891`, also pinned in
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

Mainnet HD exports use SLUG's public/private version bytes for all supported
scopes. The network prefix alone does not identify purpose, address type, or a
mixed receive/change schema; that metadata must accompany an eventual recovery
export. Existing coin type 0 is preserved for fixture compatibility and is not
a new production derivation decision. The [encoding oracle](waddrmgr/testdata/README.md)
recomputes SLUG checksums independently of the wallet implementation.

D48 still requires normal hosted login, custody and account authorization,
retained/exportable recovery material, a complete export format with derivation
metadata, and independent restore testing of that exact format. Raw seed
restoration is narrower evidence. No BIP39 phrase contract, later phrase reveal,
gym identity path, or fighter transfer is introduced here. Ordinary wallet
`signmessage` is not the prospect admission authorization protocol.

See [change set 23 notes](CHANGESET_23_NOTES.md) for the complete scope and checks.
SLUG wallet retains the ISC license in [LICENSE](LICENSE).
