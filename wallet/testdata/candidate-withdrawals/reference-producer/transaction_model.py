"""Independent public-fixture reviewed-withdrawal transaction model.

DRAFT SOURCE, not executed to produce expectations until the Set68 contract and
producer lock are frozen. No Go/project runtime imports or wallet file access.
All private arithmetic is confined to already-published deterministic fixtures.
"""
import hashlib
import importlib.util
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / 'reference-inputs'

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module

R = load('withdrawal_public_recovery', ROOT / 'inherited/recovery/reference.py')
E = load('withdrawal_public_ecdsa', ROOT / 'inherited/ecdsa/reference_authorizations.py')
MAX_MONEY = 21000000 * 100000000
MAX_INPUTS = 16
FEE_RATE = 1000
MAX_FEE = 100000
H = lambda b: hashlib.sha256(b).digest()
D = lambda b: H(H(b))
u32 = lambda n: struct.pack('<I', n)
u64 = lambda n: struct.pack('<Q', n)

def compact(n):
    assert type(n) is int and 0 <= n < 2**64
    if n < 253:
        return bytes([n])
    if n < 65536:
        return b'\xfd' + struct.pack('<H', n)
    if n < 2**32:
        return b'\xfe' + u32(n)
    return b'\xff' + u64(n)

def blob(b):
    return compact(len(b)) + b

def outpoint(coin):
    return bytes.fromhex(coin['txid'])[::-1] + u32(coin['index'])

def output(row):
    return u64(row['atoms']) + blob(bytes.fromhex(row['script']))

def native(seed, branch, index):
    path = f"m/84'/0'/0'/{branch}/{index}"
    key = R.derive_path(seed, path)
    public = R.public_key(key.scalar)
    script = b'\x00\x14' + R.hash160(public)
    return dict(path=path, public_key=public.hex(), address=R.witness_v0(script[2:]),
                script=script.hex()), key.scalar

def supported_script(script):
    return ((len(script) == 25 and script[:3] == b'\x76\xa9\x14' and script[-2:] == b'\x88\xac') or
            (len(script) == 23 and script[:2] == b'\xa9\x14' and script[-1:] == b'\x87') or
            (len(script) == 22 and script[:2] == b'\x00\x14') or
            (len(script) == 34 and script[:2] == b'\x51\x20'))

def dust_threshold(script):
    assert supported_script(script)
    witness = script[:2] in (b'\x00\x14', b'\x51\x20')
    return 3 * (8 + len(compact(len(script))) + len(script) + 41 + (107 // 4 if witness else 107))

def estimated_fee(n, recipient_script):
    # Frozen inherited txsizes estimate, including its conservative input-count
    # contribution to witness weight. This models current wallet authoring;
    # it is not a claim that the result equals an actual signed vsize.
    base = 8 + len(compact(n)) + 1 + n * 41 + 8 + len(compact(len(recipient_script))) + len(recipient_script) + 31
    witness = 2 + len(compact(n)) + n * 109
    return (base + (witness + 3) // 4) * FEE_RATE // 1000

def prepare(coins, recipient_atoms, recipient_script, change):
    script = bytes.fromhex(recipient_script)
    if not supported_script(script) or type(recipient_atoms) is not int or not dust_threshold(script) <= recipient_atoms <= MAX_MONEY:
        raise ValueError('invalid_recipient')
    candidates = sorted(coins, key=lambda c: (-c['atoms'], bytes.fromhex(c['txid']), c['index']))
    selected = []
    total = 0
    target_fee = estimated_fee(1, script)
    for coin in candidates[:MAX_INPUTS]:
        if len(bytes.fromhex(coin['script'])) != 22 or not coin['script'].startswith('0014') or not 0 < coin['atoms'] <= MAX_MONEY:
            raise ValueError('invalid_coin')
        selected.append(dict(coin))
        total += coin['atoms']
        if total > MAX_MONEY:
            raise ValueError('invalid_total')
        if total >= recipient_atoms + max(target_fee, estimated_fee(len(selected), script)):
            break
    else:
        raise ValueError('insufficient_funds_or_input_capacity')
    fee = estimated_fee(len(selected), script)
    remainder = total - recipient_atoms - fee
    outputs = [dict(atoms=recipient_atoms, script=recipient_script, role='recipient')]
    if remainder >= dust_threshold(bytes.fromhex(change['script'])):
        outputs.append(dict(atoms=remainder, script=change['script'], role='change'))
    else:
        fee += remainder
    if fee > MAX_FEE:
        raise ValueError('fee_capacity')
    selected.sort(key=lambda c: (bytes.fromhex(c['txid']), c['index']))
    outputs.sort(key=lambda o: (o['atoms'], bytes.fromhex(o['script'])))
    serialized_inputs = b''.join(outpoint(c) + b'\x00' + u32(0xffffffff) for c in selected)
    serialized_outputs = b''.join(output(o) for o in outputs)
    stripped = u32(1) + compact(len(selected)) + serialized_inputs + compact(len(outputs)) + serialized_outputs + u32(0)
    return dict(inputs=selected, outputs=outputs, recipient_atoms=recipient_atoms,
                fee_atoms=fee, total_debit_atoms=recipient_atoms + fee,
                consumed_change=change, change_index=next((i for i,o in enumerate(outputs) if o['role']=='change'), -1),
                unsigned_hex=stripped.hex(), txid=D(stripped)[::-1].hex())

def sign(draft, private_by_script):
    coins = draft['inputs']
    outputs = b''.join(output(o) for o in draft['outputs'])
    prevouts = D(b''.join(outpoint(c) for c in coins))
    sequences = D(u32(0xffffffff) * len(coins))
    output_hash = D(outputs)
    witnesses = []
    evidence = []
    for coin in coins:
        script = bytes.fromhex(coin['script'])
        secret = private_by_script[coin['script']]
        public = E.public_key(secret)
        assert R.hash160(public) == script[2:]
        code = b'\x76\xa9\x14' + script[2:] + b'\x88\xac'
        preimage = (u32(1) + prevouts + sequences + outpoint(coin) + blob(code) + u64(coin['atoms']) +
                    u32(0xffffffff) + output_hash + u32(0) + u32(1))
        digest = D(preimage)
        sig_r, sig_s = E.sign(secret, digest)
        assert E.verify(E.multiply(secret), digest, sig_r, sig_s)
        signature = E.der_signature(sig_r, sig_s) + b'\x01'
        witnesses.append(b'\x02' + blob(signature) + blob(public))
        evidence.append(dict(bip143_preimage=preimage.hex(), sighash=digest.hex(), signature=signature.hex(), public_key=public.hex()))
    stripped = bytes.fromhex(draft['unsigned_hex'])
    raw = stripped[:4] + b'\x00\x01' + stripped[4:-4] + b''.join(witnesses) + stripped[-4:]
    return dict(raw_hex=raw.hex(), txid=D(stripped)[::-1].hex(), wtxid=D(raw)[::-1].hex(),
                raw_sha256=H(raw).hex(), signatures=evidence)
