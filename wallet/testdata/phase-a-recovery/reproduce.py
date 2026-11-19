"""Reproduce locked independent expectations without replacing checked-in files."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
LOCK = "0a0762cf3d51a3e35505494a6afa995e2292fce742c4a92cb1478aa0712abc29"
EXPECTED = {
    "addresses": "1558bf4a134ab01acfe84fdbb2edc3e8af842b602cb5150feaa9ce2df26b9cf7",
    "progress": "fb0c9a5b1d59711ecb6d855534358f09175df5eb547c1bf88d0474b4b3515801",
}

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

if sha(ROOT / "producer/producer-lock.json") != LOCK:
    raise SystemExit("reviewed producer lock differs")
for kind, digest in EXPECTED.items():
    if sha(ROOT / (kind + "-v1.json")) != digest:
        raise SystemExit("checked-in output differs from independent first execution: " + kind)
with tempfile.TemporaryDirectory(prefix="slug-phase-a-reference-") as directory:
    outputs = {}
    for kind in EXPECTED:
        target = Path(directory) / (kind + ".json")
        subprocess.run([sys.executable, "-B", str(ROOT / "producer/generate.py"),
                        "--kind", kind, "--output", str(target)], check=True,
                       env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
        if target.read_bytes() != (ROOT / (kind + "-v1.json")).read_bytes():
            raise SystemExit("independent reproduction differs: " + kind)
        outputs[kind] = {"bytes": target.stat().st_size, "sha256": sha(target)}
    print(json.dumps({"status": "passed", "outputs": outputs}))
