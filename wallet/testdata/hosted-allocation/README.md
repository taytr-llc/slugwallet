# Hosted allocation reference, Set72

`reference.json` is the independent public model corpus for the paired
`HOSTED_ALLOCATION_RECOVERY.md` contract. It was generated with the source and
public inputs in this directory before the dependent implementation tests.
The historical README inside `reference-producer` is preserved as part of the
frozen source set; its pre-execution status is superseded by this record.

The adopted contract SHA256 is
`8e6036d0bb1dac60a0e513427fe71bcc42cb5909bfdc67fb0c42a61de6790307`.
The successful producer lock is `producer-lock.json`, SHA256
`bfe9086f70c64702163d6c14a74245d4369718a31331752501e0516b832c8801`.
The corpus is 4,004,018 bytes with SHA256
`221fc42f6848fed27912a43454a1fa9ebe2d4e16b383aad9e294c31316424e6b`.
Python 3.14.3 and Python 3.9.6 produced identical bytes. See
`generation-report.json` for the recorded execution.

The first producer attempt failed before writing its output because inherited
Set69 comparison examples used nonzero cursors while the original Set71
manifest has zero cursors. Its exact lock/source/log are retained under
`pre-execution-attempt1`. The successor normalizes only copied comparison
examples, records their original provenance, and leaves all staged inputs and
the adopted contract unchanged. No failed attempt is classified as passing.

To reproduce into a new file from this directory:

```sh
python3 reference-producer/generate_reference.py --execute \
  --approved-producer-lock producer-lock.json \
  --approved-lock-sha256 bfe9086f70c64702163d6c14a74245d4369718a31331752501e0516b832c8801 \
  --input-lock reference-inputs/input-lock.json \
  --inputs reference-inputs/inputs --contract contract.md \
  --output /absolute/path/to/new-reference.json
```

The model uses public branch keys and CKDpub. It contains no wallet databases,
recovery phrases, private keys, or implementation-derived expected values.
Its 37 states, two bindings, replay and storage/refusal cases, and 1024-row
boundary establish finite codec/model expectations. Concrete account authority,
disk durability, wallet ownership, watches, cancellation, and actual restoration
require the separately recorded implementation and integration tests.
