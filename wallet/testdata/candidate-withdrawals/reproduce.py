"""Reproduce locked independent expectations without replacing checked-in files."""
import hashlib,json,os,subprocess,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent
EXPECTED='d7c7b1e4c94e02f734a162b5974749853c91828ea1a0a4c4446c379bddc841c3'
if hashlib.sha256((ROOT/'reference-v1.json').read_bytes()).hexdigest()!=EXPECTED:
    raise SystemExit('checked-in reference does not match independently locked output')
with tempfile.TemporaryDirectory(prefix='slug-withdrawal-reference-') as directory:
    out=Path(directory)/'reference.json'
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1')
    subprocess.run([sys.executable,str(ROOT/'reference-producer/generate.py'),'--output',str(out)],check=True,env=env)
    actual=out.read_bytes()
    if actual!=(ROOT/'reference-v1.json').read_bytes():raise SystemExit('independent reproduction differs')
    print(json.dumps(dict(status='passed',sha256=hashlib.sha256(actual).hexdigest(),bytes=len(actual))))
