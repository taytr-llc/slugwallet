# Set68 independent withdrawal reference plan

Draft plan before producer execution. Inputs are the preimplementation public
fixture JSON and inherited reference sources in ../reference-inputs. No current
wallet API, runtime output or new Go implementation may supply an expectation.
Private arithmetic uses only the two explicitly published fixture identities.
The final adopted contracts and producer source hashes must be locked before
producing corpus bytes; preserve this draft and any failed expectations.

Transaction cases:

- Both original Set61 payouts, spending the original native84/index0 outpoint,
  paying exactly 1 SLUG to the other public fixture's native84/index0 address.
  Fresh fixture change starts at native84 internal0. Compare exact stripped
  bytes, selected inputs, integer fee/debit, change allocation, BIP143 preimages,
  deterministic low-S DER witnesses, signed bytes, txid and signed SHA256.
- All four supported recipient forms (44 P2PKH,49 external P2SH,84 P2WPKH,
  86 P2TR) using the inherited independently derived public address/script pairs.
- Exact no-change, one-atom change remainder, largest native84 dust remainder,
  and first nondust remainder. The consumed internal0 change path/script remains
  recorded even when no output is retained; no second allocation on recovery.
- Input counts 1,2,3,15,16, with synthetic labeled public outpoints owned by the
  same published fixture. Cover descending-value selection, equal-value txid
  ordering and numeric vout tie breaks, then separate final BIP69 ordering.
  Synthetic UTXOs are serialization models, not chain-spendability evidence.
- Insufficient funds, seventeenth-input capacity, zero/negative/too-large amount,
  recipient dust, unsupported script and total-input overflow.
- Identical recipient/change script and amount: roles must be deterministic
  despite identical serialized outputs. No unsafe first-equal change lookup.
- Mutation refusals: changed recipient/value/fee, outpoint, sequence, locktime,
  version, additional output, scriptSig, sighash type, missing/wrong witness,
  noncanonical CompactSize and appended transaction bytes.

Independent lifecycle and private-wire fixtures follow the adopted app journal
and desktop contracts. Cover intent/prepare/signed/delivery persistence gaps,
reset-before-commit versus reset-after-intent, held read versus fresh retry,
exact action recovery (never latest), capacity and original capture isolation.
Do not label a model as a real wallet/node observation.

Before adoption verify the producer's exact dust and conservative size formulas
against the locked pre-Set68 txauthor/txrules/txsizes sources. Preserve inherited
fee estimator behavior even where its conservative size differs from actual
signed size. No network policy change is being proposed by an oracle.
