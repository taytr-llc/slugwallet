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

The next wallet delta adds exact unsigned-intent reservation abandonment without
releasing consumed or uncertain funds. It also corrects the final live watch
audit for schema14 allocation2 and schema15's already-issued four payment scopes;
schema13 behavior and the finite frontier stay unchanged. Finally, callers may
inspect an unloaded ready12 activation guard, retain it before mutation, and
activate15 only if the same-transaction audit still matches that exact guard.
Failed cleanup remains sticky; the original activation API is preserved.

carrier-abandon-attempt4 passed normal16.708/race118.376/profile4.466/vet0.595s
with1,239 unchanged inputs. carrier-watch-attempt1 passed
normal8.300/race56.556/profile3.293/vet0.547s with1,240 unchanged inputs.
restored-activation-attempt1 passed normal17.255/race145.481/profile4.650/vet0.707s
with1,248 unchanged inputs, including the old independent recovery-signature
test. All use the bound candidate no-CSE compiler profile and joined processes.
These are focused scopes; they do not claim the unfinished full-set regression.

restored-carrier-actual-attempt5 passed215.782s on fresh normal-PoW loopback nodes,
with4,898 unchanged inputs. An original hosted export alone restored12 then15,
the same gym and public fighter, exact lost-Prepare acknowledgment, signed bytes
across close/reopen without automatic send, and actual commit/reveal spending.
The sender remained effective at59 descendants and the recipient became owner
at60; an independently owned public HTTP/node-only replay agreed at height163.
Original hosted files and the selected export were unchanged. Both nodes closed
cleanly. Scope is same-process independent owners, not process isolation or
commit-only recovery. Public report SHA256:
493db2375f1d0eb3ea2e3a577e53c44b2815cd36f8157aad5db737c5a4d29260.

Failed actual1 exposed the watch dispatch omission corrected above. Actual2 used
the wrong hosted admission signer in the harness; actual3 attempted unsupported
mining-child Logout; actual4 mined on the peer before observing its exact mempool
transaction. Reviewed harness successors retained the same miner, economics and
finality expectations. All failures remain preserved, not relabeled passes.
Earlier abandon failures were infrastructure, an unused test import, and a test
fixture missing the existing recovery challenge; their successor evidence is
separate. The new activation seam has focused lifecycle evidence after actual5;
actual5 itself used the preserved original activation API.

The intent-free recovery matcher now separates bounded public original-export
path lookup from journal admission. Discovery retains the exact restored owner
and concrete public recovery capability without creating a request or consuming
the128-operation journal budget. An explicitly selected match still requires an
exact durable intent, fresh public checks and the original preparation/signing
path. The previous selected-recovery API remains unchanged.

restored-match-attempt1 passed compile3.567/normal14.040/race115.795/
profile3.560/vet0.509s with1,250 unchanged inputs, the exact candidate compiler
and all processes joined. It proves the public lookup leaf can exceed128
candidate probes while the empty journal remains held/unchanged, the wallet
stays locked and its database bytes remain unchanged; prior restored signature
and bounded-inventory checks also pass. These tests do not manufacture a public
capability or establish the later automatic-discovery/commit-only composition.
The paired root observation checkpoint06740477 is separate evidence; the set
remains open.

This is a qualified component checkpoint, not Set73 completion. The separate
restored-gym command, automatic commit discovery, original-file commit-only
reveal/refund recovery, app wiring, full suites and packaging remain.
Production genesis and the final joint design
review are separate gates. After transfers/recovery, Mike's order is the public
pool and scheduled payouts, followed by sign-in and onboarding.
