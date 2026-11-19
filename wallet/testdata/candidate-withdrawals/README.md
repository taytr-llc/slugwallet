# Independent Set68 references

Run `python3 reproduce.py` from any directory. The launcher verifies the checked-in output hash, runs the locked standalone Python producer into a temporary file, and compares every byte. It never replaces the checked-in reference or imports the new Go implementation. Python3.9 and3.14 reproduced the initial corpus identically.

Coverage: 24 positive unsigned/signed transactions,13 invalid drafts and5 invalid signed transactions. All private arithmetic uses the two previously published deterministic fixture seeds. Synthetic UTXOs, account IDs and chain outcomes are explicitly labeled; none claims a newly observed withdrawal. The original payout input is a read-only public transaction from Set61, with its existing Set67 legacy RPC baseline. Freeze records and hashes preserve provenance; draft headings in frozen inputs describe their original review status and are not current authorization.

The broader CASE_PLAN (where present) includes property-test obligations beyond this finite corpus. Runtime failure, cancellation, storage and node tests provide separate evidence. Never copy a new implementation result into this reference to fix a failing test.

Expected SHA256: `d7c7b1e4c94e02f734a162b5974749853c91828ea1a0a4c4446c379bddc841c3`.
