# Additional public recovery-index vectors

`recovery_indices_v1.json` adds 112 sparse public payment vectors for the two
published candidate fixtures, across all four purposes and both branches at
indices 4096, 4097, 4116, 4128, 8191, 8192 and 65535. Original
`candidate_v1.json` and its oracle are unchanged.

```sh
python3 -B productionprofile/testdata/reference_recovery_indices.py --check
go test ./productionprofile -run TestReferenceRecoveryHighIndices -count=1
```

The new Python wrapper pins the original independent oracle, its lower-level
arithmetic and original corpus. It regenerates the original corpus and checks
published BIP/SLIP vectors before deriving the new addresses. No expected bytes
come from Go output. `--generate` writes only this new corpus. All fixture seeds
are already public; these addresses must never receive real funds.

4096 must match the original corpus exactly. 4097 crosses the old synchronous
runtime ceiling. 4116/4128 let recovery tests fund an initially covered address
after an earlier, initially out-of-lookahead address, requiring history replay
after discovery expands coverage. 8191/8192 exercise another boundary. 65535
is a valid sparse derivation, not permission to exceed the scanner's aggregate
65,536-attempt ceiling and reserved lookahead. These vectors alone make no claim
about scanner completion, transactional recovery, maturity, or spendability.
