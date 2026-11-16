# Change set 30 — candidate production recovery profile

Branch: `slug-production-profile`, stacked on set 29 `slug-recovery-vault`.
This implements D73's approved design using two published candidate fixtures.
Local integration and module regression have passed; exact-source CI remains
required before promotion.

## Behavior

- Strict versioned descriptor/manifest/export with explicit account public keys,
  key origins, address cursors, gym binding and a canonical descriptor digest.
- Standard BIP32 payment scopes 44/49/84/86 with candidate coin 1397511495;
  uniform nested49 and native84 receive/change defaults in actual wallet APIs.
- Separate SLIP10 secp256k1 gym derivation with a genesis-bound SLIP13 identity.
  Independent retry transcripts cover the rare invalid-key cases without
  changing payment-path semantics.
- Explicit manager schema 10, retained recovery, exact fixture-only creation,
  export and fresh restore. Per-wallet scopes drive address membership during
  rescan. Unsupported inventory mutations refuse before changing the database.
- Public index derivation covers the nonhardened range. The bounded candidate
  wallet stops at 4096 next indexes per branch; larger manifests require a
  future resumable scanner and are refused before creating wallet storage.

## Deliberate boundaries

The production descriptor table remains empty. The numeric coin and Phase-A
genesis are conformance candidates, not final production allocations. There is
no caller finalization flag, real entropy input, production provider, KMS setup,
new secret RPC or public wallet endpoint. Existing schemas 8/9, v1 fixture
exports, coin-0 paths, mixed49 behavior, old gym identities and desktop defaults
remain unchanged. No node consensus or seed configuration changes are needed.

## Verification

The independent oracle first reproduces published BIP39/BIP32/SLIP10/SLIP13 and
address standards, then derives both candidate fixtures. It covers 80 payment
vectors, both branches, boundary indexes, canonical bytes and gym bindings.
Exact regeneration and the complete profile package pass: normal 0.327s, race
2.409s, tagged 0.382s and vet. Malformed keys, strict parsing, substitution,
cancellation and retry bounds pass. Workspace evidence is retained in
`set30-profile-reference-checks.json` outside the repository.

Expanded manager race passed 7.287s: required-state corruption, profile/version
separation, retained cursor minima, 4096 allocation boundary, unsupported
mutations, canceled creation rollback and safe reopen. Candidate account balance
race passed 45.837s; actual incoming-transaction notification race passed 23.355s.
RPC address/default/cursor-reopen race passed 48.855s. Cheap-profile creation and
restore refused before storage changes (0.505s); the future-version gate race
passed 1.589s. The earlier candidate wallet race passed 148.428s before the final
creation-cursor hardening; subsequent normal tests and final CI cover that change.

Final normal-PoW acceptance passed 75.86s through height 103 with unchanged source
hashes: four independently derived index-25 address types funded and recovered
from the retained export with the original wallet path unavailable; exact root,
gym, history and balance restored; all four input classes signed in one confirmed
RPC spend, followed by a confirmed spend of native84 change. The first attempt
exposed a real old-coin scope filter in credit discovery, fixed with per-wallet
membership. The second exposed a test expectation that omitted fees returned
in the local miner's reward; only the test accounting changed.

All ten chain and six wallet module builds, relevant vet and native/Linux node
builds pass with stable runtime hashes. Four existing normal-PoW desktop/account/
vault flows passed 124.229s (wrapper 127.510s) with unchanged captured sources;
all 15 listeners closed and no owned processes remained. Preliminary runs that
overlapped source changes are preserved separately. Final root-module normal
tests passed in 166.511s wall time (wallet package 158.751s), with all 251 captured
source/fixture files unchanged. All five unchanged leaf-module suites passed and
their results are retained. Packaged desktop checks, chain smoke and exact-source
CI are tracked in workspace release evidence; promotion remains gated on completion.

## Remaining launch work

Finalize coin/chain identity and descriptor, implement bounded resumable recovery
and evolving-wallet metadata, prove production-profile restore, and integrate
operator-owned custody and authentication. D74 requires a thorough joint design
review with Mike before friends/tester or public product release. See the paired
chain `LAUNCH_READINESS.md` and this repository's `PRODUCTION_PROFILE.md`.
