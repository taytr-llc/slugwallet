# Change set 76: explicit daily operator settlement wallet

The schema16 operator wallet now has separately selected daily constructors and
backend/signing entry points for the paired chain's Config2 settlement profile.
`CreateDailyPoolSettlementWallet/OpenDailyPoolSettlementWallet` require the
exact Binding2, independent Source2/config digests and original operator
profile. Schema16, the guard's canonical grammar and the fixed Phase A path
`m/84'/0'/0'/0/0` remain unchanged. New guards carry the explicitly selected new
identities; old guards and custody roots are not repinned or migrated.

The daily backend claims the original wallet once and binds once to the same
concrete daily settlement Store and daily node owner. Signing requires that
Store's active synchronous capability; caller coins, configuration or a copied
DTO cannot authorize a payment. The manager takes bounded owned copies of the
inputs, uses a cheap original-capability lifetime check during each signature
and script check, and repeats the complete request check before returning bytes.
There is no generic signing callback or escaped Loader/Wallet.

Daily transactions allow at most 1,464 inputs and 256 payees subject to the
complete native P2WPKH 400,000-weight limit. The raw envelope is bounded at
400,000 bytes; this is not permission to exceed standard weight. Input claims
are bounded at 32,768 and their textual admission budget at 320 MiB, using
owned slices with immutable strings rather than an all-body JSON clone.
Legacy constructors and signing retain their existing V1 identity, 256-input
and 100,000-byte restrictions. Generic derivation, allocation, import/export,
private-key access and ordinary spending remain unavailable for this purpose.

The original lifecycle is preserved: explicit startup unlock with a positive
lifetime no longer than 24 hours, network evidence before the short unlock
lease, cancellation and Close joining admitted work, and sticky ownership after
uncertain cleanup. Sign never loads a passphrase, renews an unlock, broadcasts
or creates its own ledger. The original Store alone owns payments, fees,
reservations and the daily slot. D84 defers the entire oversized payout without
signing a subset or debiting balances.

## Evidence and scope

Paired component qualification passed normal and race modes, cheap-profile
refusals and vet with unchanged source. The selected wallet controls passed in
26.1 seconds normal and 146.6 seconds race, including the existing legacy
controls. Tests retain the independent exact transaction vectors, verify daily
binding/guard identities, fresh encrypted creation and locked reopen, mode and
generic-operation refusals, cancellation and the conditional 721-input signing
leaf. A cheap-profile selector correction preserves the normal binding test's
execution-profile boundary; dedicated cheap constructor refusals still run.

The daily wallet reference is retained in the paired chain repository at
`poolsettle/testdata/operator-wallet/daily-v1.json`, SHA256
`9b8e52f41690db7ca1fee37c34f99dfcd0a7266b81a7793859871bd9b006ae30`.
Its producer and immutable inputs are adjacent. The original signature corpus
remains `c1f2d725fcdbc3af7ba1b0a30f4dd4dfc6983352ffb0b4f72d83f7c09ac7b087`;
no product output was used to generate new expected signatures. The paired
chain's evidence index records the separate shape/signing/source/ledger models.

**Actual attempt3 passed in 1,116.386 seconds within its in-process scope.**
The concrete daily source, ledger capability, this original wallet and normal
node produced the 721-input second payout to 64 fixture gyms: 7,128 SLUG,
109,086 raw bytes and a 51,236-atom fee. Both A/B economic bodies stayed exact
through accepted reply loss and owner reopen; only their two original sends
occurred, with final balances and 721 change origins verified. Cleanup joined.
This is stronger than the conditional signing fixtures, but it is not a
fresh-process proof: the same test process retained the 4,096-header wire hash
cache. **Fresh-process attempt4 passed in 1,255.733 seconds.** A separate child
opened the same original roots once, audited retained source proofs in 142.534
seconds, recovered B without another broadcast, and confirmed exact A/B economic
bodies, balances and 721 change origins. B used 721 inputs and 109,102 raw bytes,
with the same 7,128 SLUG payment and 51,236-atom fee. The child and both nodes
closed cleanly. All 2,531 captured source inputs and profile artifacts remained
unchanged. Exact-tip paired GitHub qualification is tracked separately.

Closeout passed all 17 chain/wallet/desktop build targets and full operator
normal/race/vet checks, with 7,388 source inputs unchanged. The normal-PoW seed
smoke/restart passed without mining on the public chain. Earlier actual test
import and missing `bdb` registration failures remain preserved; neither
reached a payout or required a wallet product change.

This remains paired operator custody engineering, not a hosted-gym wallet,
recovery-v1 export, production key ceremony, D73 finalization or public pool
release. Explicit V2 operator/transport and signed-authority capacity, a V2
full-intake late-winner proof, real scheduled payouts, final CI and D74 remain
separate gates. No real keys were read and no old wallet root was adopted.
