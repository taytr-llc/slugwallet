# D73 production recovery profile foundation

Set 30 implements the approved recovery design with two explicitly published
candidate fixtures. It does not enable real wallet issuance. The finalized
production descriptor table is empty; passing a candidate digest, different
genesis or claimed finalization flag cannot enable production mode.

The profile uses 24 English BIP39 words with no additional phrase passphrase.
Payment keys use standard BIP32 paths `m/purpose'/coin'/0'/branch/index`, with
purposes 44, 49, 84 and 86. Scope 49 uses nested witness addresses on both
branches. Ordinary candidate receive and change default to native witness
scope 84. Scope 86 uses BIP86 single-key Taproot. Login and wallet encryption
passwords do not participate in derivation.

The proposed dedicated coin value is 1397511495. It is an unregistered candidate,
not a final allocation. The runnable fixture descriptor uses the existing
disposable Phase-A network and genesis; permanent genesis remains a separate
decision. Production activation needs exact final descriptor bytes and digest,
independent recovery acceptance, and an explicit reviewed source change.

## Public metadata and retained recovery

The `productionprofile` package defines a strict descriptor, version-2 manifest
and version-2 export. The manifest includes the complete descriptor and digest,
payment root public key, four account public keys and origins, per-branch address
cursors, and gym identity. Hardened account public keys are included because a
root public key cannot derive them. Structural validation alone cannot prove key
ancestry; fixture validation recomputes every identity from the published fixture.

Gym derivation starts a separate SLIP10 secp256k1 master from the BIP39 seed.
SLIP13 binds its path to `slug://<genesis>/gym/v1` and identity index zero. Its
same-index invalid-child retry semantics are distinct from BIP32 payment
derivation. Public gym metadata is available through a dedicated candidate API;
the existing account authorities and signers retain their old fixture identities.

Only `candidate-zero256` and `candidate-incrementing256` are accepted by the
candidate wallet constructors. Their entropy is public test data. Restore takes
a complete matching export; it does not accept an arbitrary seed or descriptor.
No new secret RPC or webview export endpoint is introduced.
Candidate integration is supported through the wallet library and legacy HTTP
RPC surface. The experimental gRPC service is not a candidate-profile interface;
its old coin-0 paths fail rather than substitute another wallet identity.

Candidate wallets use explicit manager schema 10. Creation commits the profile,
encrypted retained recovery material and address inventory together. Opening
established data validates mandatory profile markers and exact scope schemas.
Export checks retained private material and current committed cursors under an
unlock lease. Existing schemas 8/9, coin-0 paths, mixed scope 49 and old gym
derivation remain unchanged; there is no automatic profile migration.

## Recovery bounds and remaining work

Public derivation supports address indexes 0 through 2147483647. A next-index
cursor of 2147483648 means exhausted and is never derivable. The candidate
runtime supports at most 4096 next indexes per branch and stops allocation at
that bound before changing the wallet. Larger valid manifests
require resumable scanning and are refused before database creation rather than
truncated. This fixture bound is not the production wallet's lifetime limit.

Production readiness still requires final coin/chain allocation, a bounded
resumable scanner with durable progress, evolving-wallet metadata and independent
fresh restore/spend acceptance without the original database or hosted service.
Real provider/KMS provisioning, real entropy generation, account integration and
desktop distribution are separate milestones. D74 additionally requires a thorough
joint design review with Mike before friends/tester or public product release.

The independent oracle and its pinned primary references are documented in
`productionprofile/testdata/README.md`. Current validation results and limitations
belong in `CHANGESET_30_NOTES.md`; this document defines behavior rather than
asserting a completed release.
