# Set69 independent reference plan — adopted and unexecuted

Input inventory was copied and SHA-256 locked **before** writing the new producer:
`input-lock-v1.json`, SHA
`0b8007ed401a1be08e7495a636149cf7b468da09a6030a59b1a089cd4f7673f9`.
The inventory lists 15 exact inputs, their sources, roles, lengths and hashes.
All copies and new files are outside both repositories. No new Go code, wallet
runtime output, profile-2 key material or real secret is an expected-value input.
The seed phrases in inherited files are the already published test fixtures.

## A. Stable v1 address/script reference

`address_model.py` imports the copied, unchanged old
`recovery/testdata/reference_recovery.py` and its pinned standards oracle. Before
new derivation it calls that old producer without its writing CLI and requires
byte-exact reproduction of the entire old `recovery_v1.json`. That also checks
all inherited BIP39/BIP32 and BIP86 reference cases, including the third
leading-zero-account case. The copied Set68 public fixture corpus must equal
that original corpus. No profile-2 module is present in the input inventory.

New cases are only `zero256` and `incrementing256`, with the exact existing
profile1 root/gym tuple, network/genesis and account0/coin0 paths. Four purposes,
two branches and ten sparse raw indices produce **160 address rows**, not a full
32,768-address inventory:

- Purposes: 44, 49, 84, 86; branch0 external and branch1 internal.
- Indices: 0, 1, 19, 20, 127, 128, 4076, 4077, 4094, 4095.
- Purpose44: P2PKH on both branches.
- Purpose49: P2SH-P2WPKH externally; **P2WPKH internally**.
- Purpose84: P2WPKH on both branches.
- Purpose86: BIP86 P2TR on both branches, old even-Y/tweak/Bech32m recipe.

Each branch includes its public extended key and script type. Each row includes
path, raw index, compressed public key, canonical SLUG address and scriptPubKey.
Index0 must match the previously frozen row exactly. Existing 25/26 cases remain
covered by the mandatory full old-corpus reproduction; they are not regenerated
as new expected values. Output includes only public manifest/key/address data;
it does not emit seed words, seed bytes, extended private keys or private scalars.
No row above4095 is derived or implied by these vectors.

## B. Adopted bounded progress reference — separate output

`progress_model.py` models the bounded arithmetic adopted by the frozen
`PHASE_A_BACKUP_RECOVERY.md` contract, SHA
`ea502f20fa91a313e62ba9dc1f577fd1e49456747fa1283726371d5b6583237e`.
The exact copy and review metadata are in `frozen/` and `contract-review.json`.
The original input lock remains unchanged: its initial proposal is preserved
as historical provenance, while this frozen contract is the progress authority.
The model does not execute a schema12 wallet/scanner.

1. Ordered scopes44/49/84/86, each branch0 then1, all coin0/account0.
2. Cursor ceiling4096; raw indices0..4095. Initial imported=issued, derived=0,
   target=min(imported+20,4096), with all eight facts retained independently.
3. Root-approved greedy ordered packing across branches up to128 raw attempts
   per derivation step, matching the inherited DeriveRecoveryChunk ordering:
   scopes44/49/84/86, branch0 then1. Invalid-child attempts consume budget. Root
   approved this engineering rule and the frozen contract now states it. The
   model covers valid-child chunks only and does not fabricate invalid-child
   proofs; full producer execution still requires the root-created lock.
4. Adopted236-byte layout: LE32 version/ready/address-count, then eight records
   of seven LE32 values in order purpose,coin,branch,imported,issued,derived,target.
   Version1; ready always0 in these models. No canonical block source is supplied.
5. All modeled children are valid. Count is therefore the sum of derived raw
   indices; this deliberately does not invent invalid-child cryptographic proof.

Finite cases:

- Six uniform eight-branch plans at imported cursor0,1,4076,4077,4095,4096.
- One mixed plan `[0,1,4076,4077,4095,4096,0,1]` to expose branch-order/crossing errors.
- Each plan contains initial rows/bytes, total attempts and chunk count, compact
  run-length attempt counts, selected steps1/2/31/32/33/penultimate/final where
  applicable, and final rows' packed bytes. It never emits all address children.
- Eight discovery transitions on native84/internal: imported0 with used0/19;
  imported1 with used0/20; imported4076/4077/4095/4096 with used4095. Expected
  imported stays unchanged; issued advances monotonically; target clips; derived
  remains unchanged until another step. Additional work and historical-rescan
  scheduling are explicitly adopted arithmetic, not validated block history.
- Invalid imported cursors−1 and4097 refuse at the model boundary. These are
  independent model labels, not required implementation error strings.

The derivation-complete output still says `wallet_ready:false` and leaves the
packed ready word0. It makes no database atomicity, resume, KDF bound, PoW,
invalid-child proof, transaction ledger, final tip or complete-history claim.
Those need meaningful implementation/runtime tests, not invented golden data.

## Execution boundary

No producer has been run, imported or used to create expected outputs. Only
static AST syntax parsing and JSON/hash inspection of inherited files occurred.
`generate.py` refuses without a separately created `producer-lock.json` whose
hash inventory covers `generate.py`, both models and this plan, exact input-lock
SHA, and explicitly approved kinds. It never creates its own approval lock.
Both stable `addresses` and adopted `progress` models passed the root finite
review. The producer source lock additionally covers `contract-review.json`
and the exact frozen contract copy; neither can change after locking. Full
producer execution remains unapproved until the root creates that lock. A revised proposal or model gets a new reviewed
lock; do not silently overwrite old inputs, attempts or outputs.

After review/freeze, planned commands (NOT executed):

```
python3 -B generate.py --kind addresses --output <fresh-attempt>/addresses-v1.json
python3 -B generate.py --kind progress --output <fresh-attempt>/progress-v1.json
```

Outputs use exclusive creation. The producer rechecks locked bytes before and
after computation. `sys.dont_write_bytecode=True` prevents repository/source
cache artifacts. First execution, a second available Python, and a portable
copied-directory reproduction should be retained byte-for-byte with the exact
producer/input inventories before any implementation consumes the vectors.
