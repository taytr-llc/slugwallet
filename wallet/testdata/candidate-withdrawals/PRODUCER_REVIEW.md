# Independent Set68 transaction-producer review

Read-only review before producer-lock/first execution. The producer was not imported or run, no expected corpus was generated, and no repository source changed. Input JSON was inspected as data only.

No blocking formula, serialization, signature or draft-digest defect was found in the reviewed sources.

Checked against frozen wallet-v1 and the inherited inputs: fixed native84 fee estimate base10+41*n+recipient output size+31 and witness weight3+109*n; integer ceiling and dust thresholds; successful no-change still consumes internal0; descending value/displayed-txid/numeric-vout selection; final BIP69 order; lowest equal output recipient role; all ordered draft/input/change fields and SHA256 domain/LE32 byte-length framing; BIP143 SIGHASH_ALL preimage; inherited RFC6979 bits2octets and low-S DER; exact witness serialization, stripped TxID, wtxid and single-SHA signed checksum.

The inherited baseline puts the original payout in the retained tip at height109, confirmations1, so the generator's default original-input block hash/height matches that recorded evidence. Both original payment outputs come from those same pinned transaction bytes. Synthetic outpoints and identical-output examples are explicitly labeled models, not chain observations.

Coverage boundaries to keep explicit:

- CASE_PLAN lists insufficient funds, seventeenth input, invalid amount/dust/unsupported scripts/total overflow, missing/wrong sighash witness, noncanonical CompactSize and extra output. The current emitted cases do not represent all of these. Preserve them as later acceptance/test debt unless the pre-lock producer is extended; do not claim the current corpus covers the whole plan.
- The same-parent tie case selects vouts1 and2 while excluding256; it tests numeric selection tie-breaking against little-endian-byte selection. It does not independently exercise final BIP69 numeric-vout ordering for an included256. To claim that distinct final-sort case, add a separately named synthetic amount requiring all three same-parent inputs, or explicitly retain that as coverage debt.
- The five added signed mutations are consistent with their labels for the chosen one-input native84 case: its recipient is output0, and raw[-5] is the final compressed-public-key byte before locktime.

Review-bound bytes (before any producer execution):

```json
{
  "reference-producer/transaction_model.py": "05ee7a66d91dd436663cf6081203e9d7bc053407eeee0867298ee0037cdbb6f3",
  "reference-producer/generate.py": "4bb0a7077911956eabea593bd4f70989935719708e8adbc9c59b4b472e010077",
  "reference-producer/CASE_PLAN.md": "cbc956436defefd2f55ed86304da95da96a94dc2a7bbcc91a4dafed4ccd8f890",
  "frozen/wallet-v1.md": "e1da62fdf3785cd6e7cf1c24ae5269ff2d7409b4b9366a13f95a5c88d7fa8524",
  "reference-inputs/input-lock.json": "9871f524dd2f1060ef37ef45c3e13d895ddf7963cfac2c269a5225d7b196e59c"
}
```
