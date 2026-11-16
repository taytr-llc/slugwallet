#!/usr/bin/env python3
"""Independent published-fixture high-water addresses; no Go/wallet outputs."""
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
source = ROOT.parents[1] / "recovery/testdata/reference_recovery.py"
spec = importlib.util.spec_from_file_location("recovery_oracle", source)
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)


def generate():
    oracle.r.verify_official_vectors()
    oracle.verify_bip86()
    entropy = bytes(32)
    phrase = oracle.r.mnemonic_from_entropy(entropy)
    seed = oracle.r.mnemonic_to_seed(phrase, "")
    result = {"fixture_only": True, "entropy": entropy.hex(), "addresses": []}
    for purpose in (44, 49, 84, 86):
        for branch, index in ((0, 25), (1, 26)):
            path = f"m/{purpose}'/0'/0'/{branch}/{index}"
            key = oracle.r.derive_path(seed, path)
            address, script = oracle.address(key, purpose, branch)
            result["addresses"].append({"path": path,
                "public_key": oracle.r.public_key(key.scalar).hex(),
                "address": address, "script_pub_key": script})
    return result


if __name__ == "__main__":
    expected = json.dumps(generate(), indent=2) + "\n"
    path = ROOT / "recovery_highwater_v1.json"
    if sys.argv[1:] == ["--check"]:
        if path.read_text() != expected:
            raise SystemExit("independent recovery high-water fixture differs")
        print("Independent four-scope high-water addresses verified.")
    elif not sys.argv[1:]:
        path.write_text(expected)
    else:
        raise SystemExit("usage: reference_recovery_highwater.py [--check]")
