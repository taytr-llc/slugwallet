# Independent D73 candidate fixtures

These are public test values, not production wallets. `candidate-zero256` uses
32 zero entropy bytes; `candidate-incrementing256` uses bytes00 through1f. The
phrase, seed and synthetic private scalars are deliberately public. Never fund
these wallets. The Phase-A genesis and coin candidate1397511495 do not represent
a finalized production descriptor or a reserved SLIP44 allocation.

Run from the wallet repository:

```sh
python3 productionprofile/testdata/reference_profile.py --check
go test ./productionprofile -run TestReference -count=1
```

`--generate` explicitly regenerates `candidate_v1.json`. No network access, Go
execution or private files are used. The expected values were generated before
the Go implementation was inspected. The reference uses Python standard-library
hashes/HMAC/PBKDF2 plus the independently written secp256k1/BIP32 arithmetic in
`recovery/testdata/oracle/reference.py`. Its arithmetic is variable time and is
not suitable for handling private production material.

Before emitting any candidate values, the generator verifies:

- 24 published English BIP39 mnemonic/seed/root vectors,17 BIP32 paths including
  both leading-zero cases, and16 invalid serialized BIP32 keys;
- 12 published SLIP10 secp256k1 paths, including normal and hardened children;
- the SLIP13 `https://satoshi@bitcoin.org/login`, index0 worked example;
- the published BIP49 nested address, three BIP84 native addresses and three
  BIP86 internal/output keys, scripts and Bech32m addresses.

The first group and BIP84/86 use the primary source files and checked hashes in
`recovery/testdata/oracle/sources.json`. BIP49 is pinned to
[bitcoin/bips c0614759](https://github.com/bitcoin/bips/blob/c0614759ed8c878c7ff45a1d0326e88711bab13e/bip-0049.mediawiki),
SHA256 `307b62faf7b9927233b5112e93d591272ba0c48303b5dbb6f0bbfbaf2347e695`.
The extracted SLIP10 vectors include their original file hash and
[pinned source a0031249](https://github.com/satoshilabs/slips/blob/a00312491693714d9bc1b6e4cb5b2e356e6c511e/slip-0010.md).
Their checked extraction-file hash is
`f50069548afdccd82a9d0e167e34c081c12f9ea22533f6a01384b06b0d16316a`.
The SLIP13 worked example is from
[pinned specification55de0335](https://github.com/satoshilabs/slips/blob/55de03357a0eb1dc3df31ce5f548ec8cc553fef2/slip-0013.md).

`candidate_v1.json` includes exact canonical descriptor/manifest/export strings,
the domain-separated descriptor hash, both roots, all four account xpubs, and80
payment vectors: every purpose/branch at indexes0,25,26,4096 and2147483647. Index
2147483648 is an exhausted cursor, not a derivable child. These sparse derivations
do not claim to scan a wallet or prove a production recovery scanner. The fixture
manifests retain native84 cursors26/27, with all other cursors zero.

Each candidate has its SLIP13 input/hash, actual hardened numbers, serialized
big-endian child indices, gym key and GymID. A second synthetic genesis changes
the gym identity while retaining payment paths; it is not a runnable candidate.
The gym master is separately derived by SLIP10 from the same BIP39 seed, not from
the payment root. Uniform nested49 on both branches intentionally differs from
the old fixture profile's mixed49 policy.

Synthetic HMAC transcripts force master scalar0/order retries, child left-at-
order and zero-result retries, fixed32-byte leading-zero parent serialization,
and a nonhardened retry followed by valid zero I_L. Each records exact key, input
and prescribed output bytes. SLIP10 retries the same child with `01||I_R||index`;
the independent BIP32 counterpart reports the invalid requested child after one
HMAC. Runtime tests separately bound retries/cancellation and prove the payment
path adapter propagates `ErrInvalidChild` without silently shifting a semantic
path. This synthetic coverage does not claim a naturally occurring HMAC collision.
