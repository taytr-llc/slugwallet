# Own-wallet activity independent references

Frozen before Set70 wallet implementation. `core-v1.json` contains 44 positive
transaction projections, 18 negatives (three explicitly fixture-parser-only),
18 raw framing controls, 27 storage models and four aggregate-byte precharge
controls. Raw/atom inputs come from the locked prior independent withdrawal
corpus and qualified public Set68 fixture artifacts. Modeled metadata and edge
transactions are explicitly labeled; they are not new chain, signature,
ownership or complete-history evidence.

The exact reviewed producer and 18 locked inputs are copied without byte
changes. Original absolute source paths in `inputs/input-lock.json` are
provenance only; reproduction uses the bundled relative paths and checks every
input/source digest. No repository implementation, wallet, node or private
export is used. Run `python3 -B reproduce.py` from any working directory.

Python 3.14.3 and Python 3.9.6 produced byte-identical output before implementation.
Corpus SHA256:
`4b3880f7facb9286502aa6a3bdcf38db7821a96e1d1b622f4d27a898a057598e`.
Approved producer-lock SHA256:
`e8a3e83f7146be21b72ad821a3372e9ae1c7953ce649070ad99046bef2fccc9e`.

Fixture-parser-only cases cannot be converted to typed Go input and relabeled
as binary wallet rejections. In particular uppercase raw hex decodes to the
same valid bytes; its failure belongs only to the reference fixture grammar.
