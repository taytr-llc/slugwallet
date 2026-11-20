# Change set 72 — durable hosted allocation recovery

Implementation and local qualification complete on the stacked
`slug-hosted-allocation-recovery` branch. The paired chain's
`CHANGESET_72_NOTES.md` records full desktop/package qualification and preserved
failures; `../artifacts/set72/final-binding` records final source and publication
bindings. This remains published-fixture engineering, not production custody.

## What changed

Fresh explicit schema13 wallets have a locked allocation guard, an audited local
link namespace and an independently retained recovery inventory. The exact guard
is bound once to the account, source, wallet owner and inventory. Established
wallets reopen through a full pairing audit. Old schema9/11/12 APIs and formats
retain their meanings; generic openers refuse schema13 before mutation.

A concrete plan reserves the recovery ceiling before consumption. The wallet
transaction commits the address/cursor and local link together; reviewed change
also commits its unsigned withdrawal draft and input reservations atomically.
Address disclosure follows acknowledgment, successful watch registration and the
original account View check. Reserved, burned, abandoned, uncertain and unused
ranges remain covered and are never recycled. Lost private withdrawal plans
require explicit burn/abandon rather than reconstruction from caller JSON.

Generic address/account/import growth, PSBT/dry-run authoring, key disclosure,
signing and export routes refuse guarded bypasses. Allocated withdrawals retain
the existing native review, durable payment authorization and permanent signed
input exclusions. Separate public readers provide schema13 identity, current
metadata and activity. Synchronization watches the audited frontier without
automatic gap growth. The exact installed RPC client remains under its original
owner; bounded watch failure shuts down, joins and poisons that allocator.

Hosted export combines retained recovery material with the inventory's complete
reserved prefix. The paired desktop can export and independently verify a file
after the wallet database or directory disappears, provided all other required
authorities survive. It never fabricates missing payment journals or installs a
replacement wallet through the inspection route. D72's reset hold remains enforced.

Each inventory and local link store supports 1,024 operations with separate 4 MiB
logical limits; a plan permits 128 raw derivation attempts within the existing
4,096-per-branch bound. Watch collection has its own 32,768-script,
16,384-outpoint and 8 MiB limits. These are bounded-work/storage rules, not a total
process memory claim. Account fences cover short commits/disclosure only; wallet,
database, crypto/network work and joins remain outside them.

## Verification

Frozen paired contract SHA256:
`8e6036d0bb1dac60a0e513427fe71bcc42cb5909bfdc67fb0c42a61de6790307`.
Portable independent corpus SHA256:
`221fc42f6848fed27912a43454a1fa9ebe2d4e16b383aad9e294c31316424e6b`.
Python 3.14.3 and 3.9.6 reproduced identical bytes; the installed repository-only
reproducer passed. New Go output did not supply expected values.

Manager, inventory/vault, guarded Loader, allocation/withdrawal, held-session,
read-only lookup, watch and archive tests passed their scoped normal/race/profile
checks. The final wallet source passed all six modules' full normal suites in
404.762s and all six build/vet pairs, with 1,197 inputs unchanged. The final tagged
successor passed all five intended refusal tests in 1.596s with 1,103 tagged inputs,
closing an earlier selector's omitted Loader case. All owned groups closed.

The full funded two-fixture rehearsal passed in 423.781s: two receive addresses
and two reviewed withdrawals per wallet, expected 144-atom fees, no preloss manual
export, exact database and whole-directory loss, current external 3/internal 2
exports, stale-file refusal, reset holds, old-session denial and unchanged original
wallets. An independently file-restored wallet recovered its latest change and
confirmed a controlled spend. Original submitted operations could not pay twice.
A separate 18.107s interrupted-setup replay retained the original identities and
one recipient allocation per fixture without mining or payment.

Desktop and packaged-helper qualification use the exact composite documented in
the paired notes. Both hosted naming routes completed on package4; its subsequent
legacy startup exposed a typed nil interface bug. The unchanged allocated branch
retains that acceptance. The legacy-only correction passed normal/race/vet,
the complete pilot suite and exact rebuilt-package initial/reopen acceptance.
The other six desktop packages had passed the original full run. Failed overall
attempts remain failed; no final-byte rerun is implied for their successful scopes.
The normal build72 package and required node smoke passed; no seed input changed.

## Preserved defects and limits

Production corrections preserve the failed evidence: namespace validation before
schema lookup, complete namespace-byte accounting, correct directory validation,
the concrete RPC readiness-wrapper accessor, one-time inventory binding and the
legacy typed-nil assignment. Test/harness mistakes, sandbox listener failures and
the interrupted race run retain their original outcomes and named successors.
Earlier focused checks retain their executed source/compiler-evidence scope;
the final binding documents subsequent changes explicitly.

Recovery covers supported reserved allocations, not independently derived paths
beyond the frontier, lost application payment authority, hostile filesystem
rollback or off-device service backup. Existing CurrentStore 128-action policy,
profile1, fixture identities and inspection-only schema12 Verify remain intact.
Real issuance, provider/MFA, production custody and exclusive migration are not
enabled. D83 transfers and independent same-gym/fighter restoration are the next
functional milestone; login work stays deferred and the joint D74 review stays last.
