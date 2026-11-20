# Set73 wallet component — fighter transfers and restored spending

This component adds explicit schema14 allocation2 wallets and schema15 activation
of fully scanned restored wallets. It preserves original export bounds, watches
issued paths in all four supported scopes and signs new funding only through
native84. Carrier and withdrawal records share durable input exclusions; signed
funds stay reserved across restart. The concrete carrier owner requires original
account authority and chain-derived preparation. Public DTOs cannot mint it.

The vault has a separate typed inventory2 recovery export and a gym-only transfer
signer. Reset holds and original-session revocation remain enforced. Lost prepare
acknowledgment can recover an exact owned projection; signing still needs fresh
concrete chain eligibility. Uncertain committed writes preserve records and
poison the original owner. No real secret or production wallet was issued.

Qualification artifacts live in ../artifacts/set73. carrier-owner-attempt3 passed
normal16.753/race119.327s but failed a tagged test expectation; the preserved
tagged successor passed2.212s and vet1.895s. carrier-funding-reconcile-attempt1
passed normal20.778/race106.083/profile4.707/vet0.709s with1,223 unchanged inputs.
It includes independent signed transaction bytes, funding selection, original
authority fences and lost-ack inspection. export2-focused-attempt1 passed
normal6.913/race16.984/vet4.784s; withdrawal2-focused-attempt1 passed
normal23.838/race124.814/vet3.945s, including old withdrawal regressions.
Earlier guard/codec qualification and every failed attempt remain recorded in
the chain repo's CHANGESET_73_NOTES.md and artifact history.

This is a qualified component checkpoint, not Set73 completion. Actual reviewed
transfers, independent gym/fighter restoration followed by spending, app wiring,
full suites and packaging remain. Production genesis and the final joint design
review are separate gates. After transfers/recovery, Mike's order is the public
pool and scheduled payouts, followed by sign-in and onboarding.
