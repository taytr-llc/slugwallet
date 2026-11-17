#!/usr/bin/env python3
"""Additional sparse public-fixture addresses for bounded recovery tests.

The frozen independent profile oracle and all original outputs are verified
before deriving new indexes. No Go implementation, key files, or network is
used. These public fixtures must never receive real funds.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
PINNED = {
    "productionprofile/testdata/reference_profile.py": "00a19814452f8d767e1c83b5756c456abee6ac9c31e9df52887d4c2a3859544a",
    "productionprofile/testdata/candidate_v1.json": "35dec1ef9ae2553f5c4fd37e63dd4b7dd3bee993219e0062e3a084b59dc091ed",
    "recovery/testdata/oracle/reference.py": "60e1527ce408213fd89bc2cf6b4d2d8ecaedbd3c811ef4d40b6f888bb608202f",
    "recovery/testdata/reference_recovery.py": "7fa363566bb3ae003f646a89accc029045b083b643f4fb921121ed00eeb8d6c8",
}
INDICES = (4096, 4097, 4116, 4128, 8191, 8192, 65535)


def generate():
    for path, expected in PINNED.items():
        if hashlib.sha256((REPO / path).read_bytes()).hexdigest() != expected:
            raise ValueError("frozen independent input changed: " + path)
    import reference_profile as profile
    original = profile.generate()
    if json.dumps(original, indent=2) + "\n" != (HERE / "candidate_v1.json").read_text():
        raise ValueError("original independent profile corpus no longer reproduces")
    cases = []
    for item in original["cases"]:
        seed = bytes.fromhex(item["seed"])
        payments = []
        for purpose in (44, 49, 84, 86):
            account = profile.r.derive_path(seed, f"m/{purpose}'/{profile.COIN}'/0'")
            for branch in (0, 1):
                parent = account.derive(branch)
                for index in INDICES:
                    public = profile.payment(parent.derive(index), purpose, branch, index)
                    if index == 4096:
                        prior = next(p for p in item["payments"] if p["purpose"] == purpose
                                     and p["branch"] == branch and p["index"] == index)
                        if public != prior:
                            raise ValueError("old 4096 vector changed")
                    payments.append(public)
        cases.append({"name": item["name"], "root_public_key": item["export"]["manifest"]["root_public_key"],
                      "gym_public_key": item["export"]["manifest"]["gym_public_key"],
                      "gym_id": item["export"]["manifest"]["gym_id"], "payments": payments})
    return {"public_fixtures_only": True, "corpus_version": 1,
            "input_sha256": PINNED, "published_standards_rechecked": original["standards_checks"],
            "indices": list(INDICES), "cases": cases,
            "limits": ["Sparse pure derivations do not prove scanner completion or expand runtime quotas.",
                       "Index65535 can be derived by the profile but may exceed a recovery manifest's aggregate/lookahead quota.",
                       "4096 overlaps and must exactly match the unchanged original corpus."]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--generate", action="store_true")
    action.add_argument("--check", action="store_true")
    args = parser.parse_args()
    actual = json.dumps(generate(), indent=2) + "\n"
    path = HERE / "recovery_indices_v1.json"
    if args.generate:
        path.write_text(actual)
        print("Wrote 112 independent sparse recovery payment vectors; original corpus unchanged.")
    elif path.read_text() != actual:
        raise SystemExit("independent recovery index corpus differs")
    else:
        print("Verified published standards, original profile corpus and 112 additional payment vectors.")
