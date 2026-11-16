# Independent fixture vault envelopes

Every key, data key, nonce, entropy value and gym scalar in this directory is
explicitly public test material. None may configure a real vault or protect a
real wallet. The wrapper used by the Go reference tests exists only in a test
file; there is no production fixture-key default.

`reference_vault.py` independently implements AES-256 key expansion and block
encryption, counter mode, and GHASH using Python's standard library. Before
generating vault envelopes it reproduces examples 1–5 in NIST's published
[AES-GCM examples](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_GCM.pdf),
pages 21–28: empty messages, full blocks, authenticated data, and partial blocks.
This is a correctness cross-check, **not NIST validation or certification**.
The variable-time reference is unsuitable for handling private keys.

The two wallet identities are rederived using the earlier independent
`recovery/testdata/oracle/reference.py` BIP39/BIP32 implementation, and checked
against `recovery/testdata/recovery_v1.json`. Canonical manifest bytes and both
AAD layouts follow the frozen English contract. No runtime Go code or output
was read to derive the expected bytes.

Four vectors cover both purposes (`recovery`, `gym-signing`) for both published
wallets. Each contains its exact plaintext, content AAD, wrapping AAD, complete
envelope, and a rewrapped envelope under the next purpose-specific key reference.
The primitive fixture's manifest is an exact retained snapshot, including its
existing branch cursors; no address updates or invented production profile are
performed. The set-29 store deliberately has a narrower policy: it provisions
only new zero-cursor fixture snapshots. These cipher vectors exercise nonzero
metadata binding without claiming the store supports address allocation or a
current backup of an active wallet.

The public fixture wrapper uses AES-256-GCM with `nonce || ciphertext || tag`
over the 32-byte data key. Its four role-disjoint key references use consecutive
public byte ranges: recovery-v1 `00..1f`, recovery-v2 `20..3f`, gym-v1 `40..5f`,
gym-v2 `60..7f`. Data keys and nonces are SHA256 outputs of explicitly public
case labels in the generator. Determinism is a fixture property only; the
runtime cipher obtains a fresh data key and nonce from its private randomness
source and treats the provider's wrapping blob as opaque.

Run `python3 reference_vault.py --check` to regenerate and compare all expected
bytes, or `--generate` to print the complete public corpus. The generator needs
no network or external cryptography package. Go tests cross-check the NIST and
vault bytes, reject cross-account/purpose/reference/revision substitution, and
require failed or cancelled operations to return no material.

Primitive envelope authentication does not grant a session capability, attest
provisioning, or prevent replay of an entire valid old vault database. Durable
store revision checks and final account-session rechecks are tested separately.
In particular, hold-time enrollment/mining must unwrap only the gym envelope;
recovery export remains a distinct held capability.
