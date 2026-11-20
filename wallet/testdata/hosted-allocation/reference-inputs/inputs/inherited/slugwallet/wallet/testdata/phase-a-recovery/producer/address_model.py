"""Stable v1 public-fixture address math; imports only copied old reference code.

This is a prospective independent producer, not production cryptography. It
never imports a wallet implementation or the profile-2 reference. No execution
is authorized until root reviews and locks all producer sources.
"""
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
INDICES = (0, 1, 19, 20, 127, 128, 4076, 4077, 4094, 4095)
PURPOSES = (44, 49, 84, 86)
FIXTURES = ("zero256", "incrementing256")


def inherited_oracle():
    source = HERE / "inputs/inherited/recovery/reference_recovery.py"
    spec = importlib.util.spec_from_file_location("set69_old_v1_reference", source)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def generate_addresses(input_lock_sha256):
    old = inherited_oracle()
    # The unchanged old producer independently checks its pinned BIP39/BIP32
    # standards and BIP86 tweaks. Reproduce its ENTIRE old corpus first, including
    # its third leading-zero test. Only the two published runtime fixtures enter
    # the new sparse corpus. This call does not write anything.
    original = old.generate()
    expected = (HERE / "inputs/inherited/recovery/recovery_v1.json").read_text()
    if json.dumps(original, indent=2) + "\n" != expected:
        raise ValueError("frozen original v1 corpus does not reproduce")
    published = json.loads((HERE / "inputs/public/fixture-recovery-v1.json").read_text())
    if published != original:
        raise ValueError("published fixture corpus differs from original v1 reference")
    by_name = {row["name"]: row for row in original["cases"]}
    cases = []
    for name in FIXTURES:
        row = by_name[name]
        # Re-derive seed from the known public fixture entropy, not from a new
        # implementation or a runtime file. Private scalars/seed/words are never
        # included in the sparse output.
        phrase = old.r.mnemonic_from_entropy(bytes.fromhex(row["entropy"]))
        seed = old.r.mnemonic_to_seed(phrase, "")
        if seed.hex() != row["seed"]:
            raise ValueError("old fixture seed mismatch")
        manifest = row["export"]["manifest"]
        if manifest["version"] != 1 or manifest["profile"] != "slug-phase-a-fixture-bip39-v1":
            raise ValueError("wrong inherited recovery profile")
        root = old.r.ExtendedPrivate.master(seed).serialize(True, True)
        gym = old.r.gym_identity(seed, old.GYM_PATH, old.r.SLUG_NETWORK, old.r.SLUG_GENESIS)
        if root != manifest["root_public_key"] or gym["public_key"] != manifest["gym_public_key"] or gym["gym_id"] != manifest["gym_id"]:
            raise ValueError("old public fixture identity mismatch")
        branches = []
        for purpose in PURPOSES:
            account = old.r.derive_path(seed, f"m/{purpose}'/0'/0'")
            for branch in (0, 1):
                parent = account.derive(branch)
                script_type = ("p2pkh" if purpose == 44 else
                               "p2sh-p2wpkh" if purpose == 49 and branch == 0 else
                               "p2tr" if purpose == 86 else "p2wpkh")
                addresses = []
                for index in INDICES:
                    key = parent.derive(index)
                    address, script = old.address(key, purpose, branch)
                    path = f"m/{purpose}'/0'/0'/{branch}/{index}"
                    value = {"path": path, "index": index,
                             "public_key": old.r.public_key(key.scalar).hex(),
                             "address": address, "script_pub_key": script}
                    # The index-zero overlap must equal the previously frozen
                    # address bytes; it is never a new expected-output source.
                    if index == 0:
                        overlap = next(x for x in row["addresses"] if x["path"] == path)
                        if {k: value[k] for k in overlap} != overlap:
                            raise ValueError("old index-zero address changed")
                    addresses.append(value)
                branches.append({"purpose": purpose, "coin": 0, "account": 0,
                                 "branch": branch, "script_type": script_type,
                                 "branch_public_key": parent.serialize(True, True),
                                 "addresses": addresses})
        cases.append({"name": name, "manifest": manifest, "branches": branches})
    return {"version": 1, "scope": "Frozen Phase-A v1 coin0 public-fixture sparse address derivation only",
            "input_lock_sha256": input_lock_sha256,
            "original_v1_corpus_reproduced": True,
            "standard_checks": ["pinned old BIP39 vectors", "pinned old BIP32 vectors", "pinned old BIP86 vectors"],
            "raw_index_limit": 4095, "indices": list(INDICES), "address_count": 160,
            "cases": cases,
            "limits": ["No schema12, scanner, wallet readiness, resume, funds, ownership or complete-history claim.",
                       "Mixed purpose49 is nested witness externally and native witness internally.",
                       "No profile2 coin, key or script reference is imported.",
                       "No real secret, runtime wallet or new implementation output is an oracle input."]}
