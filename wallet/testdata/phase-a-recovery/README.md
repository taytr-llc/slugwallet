# Independent Phase-A recovery references

Run `python3 -B reproduce.py` from this directory, or pass its absolute path from
any directory. The wrapper verifies the frozen output hashes, runs the reviewed
standalone producer into exclusive temporary files, and compares every byte. It
never overwrites the checked-in vectors or imports the new Go implementation.
The first execution used Python 3.14.3; Python 3.9.6 independently reproduced both
files byte for byte before they were installed here.

`addresses-v1.json` contains 160 sparse address/script rows for the two previously
published public fixtures. The unchanged old v1 producer must first reproduce its
entire frozen standards/fixture corpus. The new rows cover scopes 44/49/84/86,
coin 0, both branches, and indices 0, 1, 19, 20, 127, 128, 4076, 4077, 4094 and 4095.
Purpose 49 remains nested witness externally and native witness internally.
No profile-2 key, coin type or derivation oracle is used.

`progress-v1.json` separately models the adopted cursor arithmetic and 236-byte
little-endian progress encoding: seven plans, eight discovery cases and two
invalid cursor cases. The plans preserve imported and issued cursors, clip the
20-attempt lookahead at 4096, and pack at most 128 raw attempts in scope/branch
order. Every modeled child is valid. Derivation completion always leaves the
ready flag zero. These vectors do not verify scanning, invalid-child proofs,
wallet database transactions, funds, canonical history, or runtime readiness.

The exact reviewed producer and all frozen inputs are in `producer/`.
`provenance.json` and `evidence/` retain the first executions and source bindings.
Absolute paths in those historical reports identify provenance; reproduction
uses only this directory. Historical draft or unexecuted wording in immutable
inputs records its original status; the root-created `producer-lock.json`
authorized execution after the contract and source review. The old input corpus
contains only deliberately published fixture material, never real wallet keys.

Do not repair a failing implementation by copying its output into these vectors.
Runtime, cancellation, storage, overflow, invalid-child and normal-chain recovery
tests remain separate obligations under the frozen contract.

| Output | SHA256 |
| --- | --- |
| `addresses-v1.json` | `1558bf4a134ab01acfe84fdbb2edc3e8af842b602cb5150feaa9ce2df26b9cf7` |
| `progress-v1.json` | `fb0c9a5b1d59711ecb6d855534358f09175df5eb547c1bf88d0474b4b3515801` |
