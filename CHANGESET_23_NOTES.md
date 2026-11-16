# Change set 23: SLUG wallet foundation

## Source and scope

Separate fork `taytr-llc/slugwallet`, branch `slug-wallet-foundation`, deliberately
based on upstream btcwallet v0.18.1 commit
`43f2950d2a065a7b3d4a4a1cf17ed1e84af6bcb4`. The fork's upstream master is preserved;
merging later upstream backend changes is not part of this release. The paired
chain set23 commit `4dc49e103ce271981a20a08a115dbfacc6aa6891` adds backward-compatible
`rpcclient.ConnectContext`, required by wallet startup. No consensus, network, reward, or key derivation rule changes.

This is a fixture-only foundation for the separate wallet workstream. No real
wallet/operator keys were used, no production wallet was issued, and no wallet
service was exposed to the public network or Railway.

## Changes

- Migrated all six runtime module identities and imports to
  `github.com/taytr-llc/slugwallet`; use the ten paired SLUG modules throughout.
  The new wallet workspace is separate from the unchanged chain workspace.
- Kept only the full-node WebSocket adapter. Removed Bitcoin Core and Neutrino
  adapters and their exclusive helpers/tests rather than leaving an accidental
  Bitcoin fallback. Generic Neutrino LRU cache code remains a dependency of the
  address cache; it has no chain/network types or backend capability.
- Preserved the small pinned lnd/tlv implementation locally under `internal/tlv`
  with its ISC license, provenance, and tests; only import paths were adapted.
  This avoids mixing upstream Bitcoin wire/key identities into the wallet.
- Distinct slugwallet binary/application/config/log/database namespace, slugd
  credentials/CA names, node RPC 29332, and wallet RPC 29334. Other explicit
  fixture network params remain inherited. Cheap-PoW daemon startup fails closed.
- Validate network and genesis before publishing any wallet event. Disable
  transport auto-reconnect and pending-request replay. The daemon creates a
  fresh validated transport on reconnect. Custom notification callbacks cannot
  bypass the gate. Initial best-block failure closes the notification channel.
- Use cancellation-aware connection establishment with a 30-second overall
  startup bound. Daemon stop cancels attempts/retry waits and drains the active
  client before unloading the wallet. The experimental gRPC loader remains a
  one-connection API without the daemon's replacement loop.
- Hardened the inherited derived-private-key cache after reproducing access
  after lock, watch-only conversion, and close. Each lookup checks lifecycle
  state; transitions and ordinary LRU eviction zero retained cache entries.
  Dedicated locking prevents key wiping during derivation without reversing
  existing root/scope lock order. Returned copies remain caller-owned. An
  imported watch-only account now returns an error rather than attempting
  private derivation and panicking.
- Mainnet scoped HD exports use SLUG version bytes rather than Bitcoin
  xpub/ypub/zpub. Import requires explicit address type; the prefix does not
  encode recovery schema. Coin type 0 is unchanged.
- Regenerated the RPC descriptor with protoc 29.4 and the pinned legacy
  golang/protobuf generator v1.4.3 (internal generator v1.23.0), matching the
  original generated version header. Only Go package metadata/import grouping
  changes; RPC message fields, methods and wire names are unchanged. The Docker
  regeneration wrapper now pins the compiler and source-relative output too,
  using Debian/glibc for the official Linux compiler binary. Native exact-tool
  regeneration and shell syntax were checked; the complete Docker wrapper was
  not executed locally.
- Adapted wallet CI to sibling pinned SLUG and wallet checkouts, six-module
  build/test/vet, race checks, independent oracles, and isolated normal-PoW
  integration. Removed the inherited agent-triggered workflow. CI does not
  publish, open PRs, or operate a wallet service. A green remote run must be
  observed after publishing; local checks are not that evidence.

## Hash work audit

The retained full-node adapter uses identifiers returned by the identity-checked
node for height lookup and wallet synchronization. It does not perform a header
Argon hash on every notification, recovery lookup, or debug summary. This is a
trusted full-node wallet, not an SPV verifier. Transaction hashes, Merkle paths,
and signature checks retain the SLUG library implementations.

The birthday/time lookup test mock previously hashed thousands of unmined
synthetic headers. It now uses explicit deterministic synthetic lookup IDs and
the selected params' genesis. All lookup/time/maturity assertions remain; those
mock tests never validated PoW. The real 102-block integration separately uses
the unchanged 256 MiB Argon2id profile.

## Validation

Validation on Go 1.27.4, macOS arm64:

- After the final cache fix, all six runtime modules build and pass
  `go vet ./...`.
- Final root module `go test -count=1 -timeout=5m ./...` passes: wallet
  **40.589 s**, chain 1.348 s, address manager 3.827 s, and all other packages
  passing after cache hardening. All five child module suites
  pass (txrules has no unit tests).
- The five child modules pass race tests; txauthor 2.162 s, txsizes 1.307 s,
  walletdb/bdb/migrations each under 1.8 s, and wtxmgr 2.519 s. Daemon cancellation
  race test 1.468 s and chain identity/cancellation race suite 1.453 s pass.
  After cache hardening, focused cache race tests pass in 2.542 s, the full
  address-manager race suite in 5.326 s, and its normal suite in 1.841 s. These
  cover lifecycle refusal, zeroization, eviction, independent returned copies,
  refill, concurrent lock/unlock, imported watch-only accounts, and lock order.
  A first whole-wallet race
  run with two parallel tests hit a five-minute timeout while still processing
  encrypted-wallet fixtures (no wallet race report). The complete rerun with
  four parallel tests passes in **420.805 s** (423.72 s wall time), using a
  fifteen-minute budget. Log: `/private/tmp/slug-wallet-race-final.log`. This
  is the baseline before the separately reviewed private-key-cache hardening.
  CI limits parallelism to two with a twenty-minute timeout.
- Tagged cheap-profile daemon refusal and chain tests pass (0.642 s/0.263 s).
  The test verifies refusal before a missing config or wallet directory is used.
- Final-source macOS build plus Linux/amd64 and Windows/amd64 CGO-disabled
  cross-builds pass after cache hardening. Cross-building is not Windows/Linux wallet runtime validation. Normal
  version is `0.18.1-slug-foundation`; cheap-profile output explicitly says
  `slugtestpow-disabled`.
- Sample config check covers all 35 exposed options; both independent oracles,
  gofmt, and `git diff --check` pass. The runtime package graph contains no
  `github.com/btcsuite/btcd` or `github.com/btcsuite/btcwallet` packages.
- The local normal production-PoW integration passes in **69.72 s** (package
  70.060 s), after the completed cancellation change and before cache hardening:
  four independent addresses,
  10 SLUG subsidy, 99/100-confirmation maturity boundary, confirmed spend, exact
  reopen history/balance, fresh raw-seed restore/rescan, and a second confirmed
  spend at height 102. Fixture nodes/listeners drain; no public peer is contacted.

That pre-cache-hardening integration evidence is beside the checkouts in
`set23-wallet-foundation-connect-context-smoke.json` and `.log`; the earlier
65.81-second run remains in `set23-wallet-foundation-smoke.json` and `.log`.
The final report records the paired RPC and wallet runtime source hashes.
The paired chain RPC race suite independently passes in 5.052 s.

The first broad test attempt was stopped because the lookup mock performed
thousands of unnecessary production hashes. A subsequent run exposed one
remaining Bitcoin witness-address literal in a fee-selection test; the oracle
independently re-encoded it and the test now also checks decode errors. New
daemon test setup was corrected to use a disabled test logger, explicit fixture
credentials, and joined cleanup. The passing gates above use those fixes.

The deterministic encoding oracle preserves upstream public fixture payloads
and independently recalculates Base58Check/Bech32 checksums. Runtime output was
not copied into expected vectors. Connection regression tests cover wrong
network/genesis, premature notifications, lost spend acknowledgement followed
by a foreign replacement server, unsupported custom callbacks, initial lookup
failure, and cancellation during handshake.

## Remaining product work

This does not satisfy full D48 export: upstream wallet creation can accept a raw
seed, but later recovery-phrase reveal/retention is not implemented. Hosted
normal login, custody/account authorization, exact recovery export format,
phrase format, production coin type and wallet-tied gym-key derivation remain
separate decisions. The tested restore lookahead is 20 addresses per branch for
the public fixture, not a claim about every possible recovery gap or imported
key. No new gym identity or fighter transfer behavior is included.
