#!/usr/bin/env python3
"""Reproduce the approved independent Set70 corpus using only this bundle."""
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
EXPECTED = "4b3880f7facb9286502aa6a3bdcf38db7821a96e1d1b622f4d27a898a057598e"
LOCK = "e8a3e83f7146be21b72ad821a3372e9ae1c7953ce649070ad99046bef2fccc9e"

def main():
    expected = (HERE / "core-v1.json").read_bytes()
    if hashlib.sha256(expected).hexdigest() != EXPECTED:
        raise SystemExit("frozen corpus digest mismatch")
    with tempfile.TemporaryDirectory(prefix="slug-activity-reference-") as scratch:
        output = Path(scratch) / "core-v1.json"
        subprocess.run([sys.executable, "-B", str(HERE / "producer/generate_core.py"),
            "--execute", "--inputs", str(HERE / "inputs"),
            "--approved-producer-lock", str(HERE / "core-producer-lock.json"),
            "--approved-lock-sha256", LOCK, "--output", str(output)], check=True, timeout=60)
        if output.read_bytes() != expected:
            raise SystemExit("independent reproduction differs")
    print("PASS: byte-identical independent Set70 reference " + EXPECTED)

if __name__ == "__main__":
    main()
