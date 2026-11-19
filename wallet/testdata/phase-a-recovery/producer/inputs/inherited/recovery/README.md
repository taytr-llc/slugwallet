# Independent recovery profile vectors

These are explicitly public deterministic fixtures. None may hold funds.
`reference_recovery.py` imports only the standalone Python oracle in `oracle/`;
it never imports Go, reads runtime output or opens a wallet. It validates the
pinned primary BIP39/BIP32 vectors and BIP86 Taproot vectors before deriving the
SLUG fixture profile. Run:

```sh
python3 recovery/testdata/reference_recovery.py --check
```

Without `--check`, it regenerates only `recovery_v1.json`. The output contains
three cases with entropy, standard empty-passphrase BIP39 seed, exact export,
and independent payment public keys/addresses/scripts. Native witness index25
and change index26 support recovery beyond a 20-address gap. Native branch
next-index metadata is26/27; other fixture counters begin at zero.

- `zero256`: the published BIP39 all-zero 256-bit entropy vector, with empty
  additional passphrase for the approved profile.
- `incrementing256`: explicitly public bytes00 through1f, no randomness.
- `official-leading-zero-account`: published English vector14, entropy
  `68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c`.
  With empty passphrase, the standard private key at `m/86'/0'` has a leading
  zero before hardened account derivation. It distinguishes standard BIP32
  recovery from the inherited wallet's legacy derivation.

The fixed profile uses English24 words, empty additional passphrase, standard
BIP32, account0 in scopes44/49/84/86, explicit mixed49 schemas, and fixture coin0.
The gym path `m/1397511495'/1'/0'` is an explicit Phase-A convention, not a BIP
registration or future production allocation. All full root and gym public
identities are independently calculated from these fixture inputs.

## Primary sources and licenses

`oracle/sources.json` pins exact commits, raw URLs and SHA256 digests for every
copied source. Its verification is offline; it does not authenticate signatures.

- [BIP32](https://github.com/bitcoin/bips/blob/c0614759ed8c878c7ff45a1d0326e88711bab13e/bip-0032.mediawiki), BSD-2-Clause: standard derivation and leading-zero/invalid-key vectors.
- [BIP39](https://github.com/bitcoin/bips/blob/c0614759ed8c878c7ff45a1d0326e88711bab13e/bip-0039.mediawiki), MIT, and its [English wordlist](https://github.com/bitcoin/bips/blob/c0614759ed8c878c7ff45a1d0326e88711bab13e/bip-0039/english.txt). `../english.txt` is this exact wordlist, embedded unchanged.
- [BIP84](https://github.com/bitcoin/bips/blob/c0614759ed8c878c7ff45a1d0326e88711bab13e/bip-0084.mediawiki) and [BIP86](https://github.com/bitcoin/bips/blob/c0614759ed8c878c7ff45a1d0326e88711bab13e/bip-0086.mediawiki), CC0-1.0: native-witness and Taproot reference vectors.
- [Trezor python-mnemonic vectors](https://github.com/trezor/python-mnemonic/blob/b57a5ad77a981e743f4167ab2f7927a55c1e82a8/vectors.json), the reference vectors linked by BIP39, and its [MIT license](https://github.com/trezor/python-mnemonic/blob/b57a5ad77a981e743f4167ab2f7927a55c1e82a8/LICENSE), retained as `oracle/sources/mnemonic-LICENSE`.

The oracle checks all24 official English vectors using their `TREZOR` fixture
passphrase. That is reference-algorithm coverage; the application profile has
no additional-passphrase parameter and rejects such JSON fields. Standard
wallet compatibility is not inferred from ordinary samples alone: preserve
legacy wallets and test the explicit new derivation mode with the leading-zero
fixture. The Python arithmetic is variable-time reference code, not production
key handling.
