#!/usr/bin/env python3
"""Review-gated independent Set69 reference producer. Never imports Go code."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
INPUT_LOCK_SHA256 = "0b8007ed401a1be08e7495a636149cf7b468da09a6030a59b1a089cd4f7673f9"
PRODUCER_FILES = ("generate.py", "address_model.py", "progress_model.py", "CASE_PLAN.md",
                  "contract-review.json", "frozen/PHASE_A_BACKUP_RECOVERY.md")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(kind):
    lock = ROOT/"input-lock-v1.json"
    if sha(lock) != INPUT_LOCK_SHA256:
        raise ValueError("original input inventory changed")
    for row in json.loads(lock.read_text())["files"]:
        path = ROOT/row["path"]
        if path.is_symlink() or path.stat().st_size != row["bytes"] or sha(path) != row["sha256"]:
            raise ValueError("frozen input changed: "+row["path"])
    # Intentionally absent until the root reviews this producer. Neither this
    # command nor an import creates its own approval/lock or expected outputs.
    review = json.loads((ROOT/"producer-lock.json").read_text())
    if review["version"] != 1 or kind not in review["approved_kinds"] or review["input_lock_sha256"] != INPUT_LOCK_SHA256:
        raise ValueError("producer kind is not reviewed and locked")
    if set(review["files"]) != set(PRODUCER_FILES):
        raise ValueError("producer inventory differs")
    for name, expected in review["files"].items():
        if sha(ROOT/name) != expected:
            raise ValueError("reviewed producer changed: "+name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", choices=("addresses","progress"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    verify(args.kind)
    name = "address_model" if args.kind == "addresses" else "progress_model"
    spec = importlib.util.spec_from_file_location(name, ROOT/(name+".py"))
    model = importlib.util.module_from_spec(spec)
    sys.modules[name] = model
    spec.loader.exec_module(model)
    value = (model.generate_addresses if args.kind == "addresses" else model.generate_progress)(INPUT_LOCK_SHA256)
    raw = (json.dumps(value,indent=2)+"\n").encode()
    verify(args.kind)
    # Never overwrite a prior oracle or attempt, including the first result.
    with args.output.open("xb") as stream:
        stream.write(raw)
    print(json.dumps({"kind":args.kind,"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}))


if __name__ == "__main__":
    main()
