# Change set 29: encrypted fixture retention and scoped gym signing

`recoveryvault` adds provider-neutral encrypted retention for the two published
wallet fixtures. It binds separate recovery and gym-signing envelopes to one
permanent authority/account/provision/root/gym identity. AES-256-GCM content
encryption and authenticated key wrapping have separate versioned AAD contracts.
Configured recovery/gym wrapping-key allowlists are disjoint. Rotation changes
wrapping metadata while preserving content, recovery material and public identity.

Provisioning reserves one wallet identity before retaining material, verifies
both envelopes and durably links the original gym enrollment. Protected work
checks the original account session before provider work and again before
publication. Reset revokes old operations; the approved hold denies full export
and recovery-authority changes. Typed gym signing can continue without opening
the recovery envelope. The exact contract is in `RECOVERY_VAULT.md`.

No generic decryption, arbitrary digest signing or secret RPC is added. There
is no production wrapper or default provider secret. Independent test material
reproduces published NIST AES-GCM examples before deriving SLUG envelopes.
Fixture wallet derivation, storage schemas and D70's phrase contract are unchanged.

The retained manifest is an immutable initial snapshot. This slice allocates
no addresses and does not update cursors; it does not establish complete current
production backup after later wallet activity. A new-device watch-only wallet
also needs explicit account public descriptors, since a master xpub cannot
derive hardened account xpubs.

## Verification

Five published NIST AES-GCM examples and four independent SLUG envelopes match.
The full vault race suite passed in 14.843 seconds, normal suite in 11.086
seconds and tagged suite in 0.454 seconds. Five real SIGKILL boundaries preserve
the original reservation and reconcile account/vault commits. Reset, close,
rotation races, missing material, clock rollback and capacity checks pass.
The otherwise-valid cheap-profile constructor tests were mutation-tested:
removing the production-profile guard makes both Create and Open fail their
refusal tests. Vet, formatting and diff checks pass.

Independent review found and fixed widened capacity accounting, coherent paired
wrapping revisions and protected-directory aliases. An initial capacity test
exposed incorrect error classification; publication now reports ErrCapacity.
A clock-test fixture initially changed signed timestamps; it now raises only
persisted clock high-water, preserving signatures. Prior outcomes remain in
set29-vault-store-checks.json rather than being relabelled successful.

Final frozen-source normal-PoW desktop acceptance passed four flows in 119.657
seconds (wrapper 120.959): existing continuation, signed identity/reset, existing
account lifecycle, and the vault flow. Vault recovery/export/fresh restore,
provider outage without local fallback, reset/reopen, held gym-only mining and
historical birth all passed. All 291 captured sources and the frozen node were
unchanged; all 15 distinct listeners closed and no owned processes remained.
The first run during store hardening is separately labelled preliminary.
This proves the declared immutable snapshot, not later address-cursor recovery
or a new funded-spend claim.

All ten chain and six wallet modules build; native/Linux node builds and scoped
vet pass. CI pins shared account authority commit
`9c7640e0f82bc0d213c8e6a749a99b7b9eaccbbd`. Exact-source remote CI and final
artifact/deployment evidence are recorded in the workspace release report.

Real entropy issuance, production derivation allocation, provider/KMS setup,
anti-rollback operations and disaster recovery remain subsequent work. All
tests use published fixtures on disposable local chains.
