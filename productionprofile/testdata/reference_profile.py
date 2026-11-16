#!/usr/bin/env python3
"""Independent, variable-time public-fixture oracle. Never imports SLUG Go.

The Python arithmetic/BIP39/BIP32 primitives predate this profile and are checked
against pinned primary vectors before any SLUG candidate output is generated.
This is not a secret-handling implementation or a production issuance tool.
"""
import hashlib
import hmac
import json
from pathlib import Path
import re
import struct
import sys

ROOT = Path(__file__).resolve().parent
RECOVERY = ROOT.parents[1] / 'recovery' / 'testdata'
sys.path.insert(0, str(RECOVERY / 'oracle'))
import reference as r
sys.path.insert(0, str(RECOVERY))
import reference_recovery as old

COIN = 1397511495
GENESIS = r.SLUG_GENESIS
LIMIT = 256
KINDS = {44: 'p2pkh', 49: 'p2sh-p2wpkh', 84: 'p2wpkh', 86: 'p2tr'}


def compact(value):
    return json.dumps(value, separators=(',', ':'), ensure_ascii=True)


def descriptor():
    return {'version': 1, 'profile': 'slug-production-bip39-v1',
            'seed': 'bip39-english-24-empty-v1',
            'payment_derivation': 'bip32-standard-v1',
            'network': r.SLUG_NETWORK, 'genesis': GENESIS, 'coin_type': COIN,
            'encodings': {'p2pkh': '53', 'p2sh': '47', 'wif': 'd3',
                          'witness_hrp': 'slug', 'hd_public': '534c5547',
                          'hd_private': '736c7567'},
            'payments': [{'purpose': p, 'account': 0, 'external_type': k,
                          'internal_type': k} for p, k in KINDS.items()],
            'default_receive_purpose': 84, 'default_change_purpose': 84,
            'gym_scheme': 'slug-gym-slip13-slip10-secp256k1-v1',
            'gym_identity_index': 0, 'scan_from_height': 0}


def mac512(key, data):
    return hmac.digest(key, data, 'sha512')


def slip10_master(seed, mac=mac512):
    if not 16 <= len(seed) <= 64:
        raise ValueError('seed size')
    for _ in range(LIMIT):
        digest = mac(b'Bitcoin seed', seed)
        scalar = int.from_bytes(digest[:32], 'big')
        if 0 < scalar < r.N:
            return r.ExtendedPrivate(scalar, digest[32:])
        seed = digest  # entire previous I, not just I_R
    raise ValueError('SLIP10 master exhausted')


def child_input(parent, index):
    if not 0 <= index <= 0xffffffff:
        raise ValueError('child index')
    prefix = (b'\0' + parent.scalar.to_bytes(32, 'big')
              if index & r.HARDENED else r.public_key(parent.scalar))
    return prefix + struct.pack('>I', index)


def slip10_child(parent, index, mac=mac512):
    data = child_input(parent, index)
    for _ in range(LIMIT):
        digest = mac(parent.chain_code, data)
        left = int.from_bytes(digest[:32], 'big')
        child = (left + parent.scalar) % r.N
        if left < r.N and child != 0:
            return r.ExtendedPrivate(child, digest[32:], parent.depth + 1,
                                     r.hash160(r.public_key(parent.scalar))[:4], index)
        data = b'\1' + digest[32:] + struct.pack('>I', index)
    raise ValueError('SLIP10 child exhausted')


def exact_payment_child(parent, index, mac):
    """BIP32 exact path reports invalidity; it never uses SLIP10 retry data."""
    digest = mac(parent.chain_code, child_input(parent, index))
    left = int.from_bytes(digest[:32], 'big')
    child = (left + parent.scalar) % r.N
    if left >= r.N or child == 0:
        raise ValueError('invalid exact BIP32 child')
    return r.ExtendedPrivate(child, digest[32:])


def slip13(uri, index=0):
    data = struct.pack('<I', index) + uri.encode('ascii')
    digest = r.sha256(data)
    path = [r.HARDENED + 13] + [w | r.HARDENED for w in struct.unpack('<4I', digest[:16])]
    return {'identity_uri': uri, 'identity_index': index,
            'identity_input': data.hex(), 'identity_hash': digest.hex(),
            'path': path,
            'path_text': 'm/' + '/'.join(str(i & 0x7fffffff) + "'" for i in path),
            'serialized_indices': [struct.pack('>I', i).hex() for i in path]}


def gym(seed, genesis=GENESIS):
    out = slip13('slug://' + genesis + '/gym/v1')
    key = slip10_master(seed)
    for index in out['path']:
        key = slip10_child(key, index)
    pub = r.public_key(key.scalar)
    out.update({'genesis': genesis, 'public_key': pub.hex(),
                'gym_id': r.sha256(b'SLUG gym identity\0v1\0' +
                                  struct.pack('<I', r.SLUG_NETWORK) +
                                  bytes.fromhex(genesis) + pub).hex()})
    return out


def payment(key, purpose, branch, index):
    pub = r.public_key(key.scalar)
    payload = r.hash160(pub)
    internal = output = None
    if purpose == 44:
        script = b'\x76\xa9\x14' + payload + b'\x88\xac'
        addr = r.base58check(b'\x53' + payload)
    elif purpose == 49:  # deliberately UNIFORM nested, unlike old fixture49
        redeem = b'\x00\x14' + payload
        script = b'\xa9\x14' + r.hash160(redeem) + b'\x87'
        addr = r.base58check(b'\x47' + r.hash160(redeem))
    elif purpose == 84:
        script = b'\x00\x14' + payload
        addr = old.witness(0, payload)
    elif purpose == 86:
        x, y = r.point_multiply(key.scalar)
        internal = x.to_bytes(32, 'big')
        even_point = (x, r.P - y if y & 1 else y)
        tweak = int.from_bytes(old.tagged_hash('TapTweak', internal), 'big')
        if tweak >= r.N:
            raise ValueError('invalid TapTweak')
        point = r.point_add(even_point, r.point_multiply(tweak)) if tweak else even_point
        if point is None:
            raise ValueError('invalid taproot output')
        output = point[0].to_bytes(32, 'big')
        script = b'\x51\x20' + output
        addr = old.witness(1, output)
    else:
        raise ValueError('purpose')
    result = {'purpose': purpose, 'branch': branch, 'index': index,
              'path': f"m/{purpose}'/{COIN}'/0'/{branch}/{index}",
              'public_key': pub.hex(), 'script_pub_key': script.hex(), 'address': addr}
    if purpose == 86:
        result.update(internal_key=internal.hex(), output_key=output.hex())
    return result


def verify_standards():
    checks = r.verify_official_vectors()
    old.verify_bip86()
    checks['bip86_scripts'] = 3
    sources = {'bip-0049.mediawiki': '307b62faf7b9927233b5112e93d591272ba0c48303b5dbb6f0bbfbaf2347e695',
               'slip10_secp256k1.json': 'f50069548afdccd82a9d0e167e34c081c12f9ea22533f6a01384b06b0d16316a'}
    for name, digest in sources.items():
        assert r.sha256((ROOT / name).read_bytes()).hex() == digest, name
    vectors = json.loads((ROOT / 'slip10_secp256k1.json').read_text())['vectors']
    for case in vectors:
        key = slip10_master(bytes.fromhex(case['seed']))
        for index in r.parse_path(case['path']):
            key = slip10_child(key, index)
        assert key.scalar.to_bytes(32, 'big').hex() == case['private']
        assert key.chain_code.hex() == case['chain_code']
        assert key.parent_fingerprint.hex() == case['fingerprint']
        assert r.public_key(key.scalar).hex() == case['public']
    checks['slip10_secp256k1_paths'] = len(vectors)
    published = slip13('https://satoshi@bitcoin.org/login')
    assert published['identity_hash'] == 'd0e2389d4c8394a9f3e32de01104bf6e8db2d9e2bb0905d60fffa5a18fd696db'
    assert published['path'] == [2147483661, 2637750992, 2845082444, 3761103859, 4005495825]
    checks['slip13_worked_example'] = 1
    text = (ROOT / 'bip-0049.mediawiki').read_text()
    phrase = re.search(r'masterseedWords = (.+)', text).group(1)
    key = r.derive_path(r.mnemonic_to_seed(phrase, ''), "m/49'/1'/0'/0/0")
    assert key.scalar == int(re.search(r'account0recvPrivateKeyHex = 0x(\w+)', text).group(1), 16)
    assert r.public_key(key.scalar).hex() == re.search(r'account0recvPublicKeyHex = 0x(\w+)', text).group(1)
    address = r.base58check(b'\xc4' + r.hash160(b'\x00\x14' + r.hash160(r.public_key(key.scalar))))
    assert address == re.search(r'address = base58check\(prefix \| addressBytes\) = (\w+)', text).group(1)
    checks['bip49_nested_script'] = 1
    text = (RECOVERY / 'oracle/sources/bip-0084.mediawiki').read_text()
    phrase = re.search(r'mnemonic = (.+)', text).group(1)
    cases = re.findall(r'address = (m/[^\n]+)\n  privkey = \w+\n  pubkey  = (\w+)\n  address = (\w+)', text)
    assert len(cases) == 3
    for path, pub, addr in cases:
        key = r.derive_path(r.mnemonic_to_seed(phrase, ''), path)
        assert r.public_key(key.scalar).hex() == pub
        assert old.witness(0, r.hash160(bytes.fromhex(pub)), 'bc') == addr
    checks['bip84_native_scripts'] = len(cases)
    return checks


class Transcript:
    def __init__(self, outputs):
        self.outputs, self.calls = outputs, []

    def __call__(self, key, data):
        output = self.outputs[len(self.calls)]
        self.calls.append({'key': key.hex(), 'data': data.hex(), 'output': output.hex()})
        return output


def injected_transcripts():
    result = []
    seed = bytes(range(16))
    outputs = [n.to_bytes(32, 'big') + bytes([i]) * 32
               for n, i in [(0, 0x11), (r.N, 0x22), (1, 0x33)]]
    log = Transcript(outputs)
    key = slip10_master(seed, log)
    result.append({'name': 'master-zero-order-retry', 'kind': 'master',
                   'seed': seed.hex(), 'calls': log.calls,
                   'expected_key': key.scalar.to_bytes(32, 'big').hex(),
                   'expected_chain': key.chain_code.hex()})
    parent = r.ExtendedPrivate(7, bytes(range(32)))
    index = r.HARDENED + 42
    outputs = [n.to_bytes(32, 'big') + bytes([i]) * 32
               for n, i in [(r.N, 0x44), (r.N - 7, 0x55), (2, 0x66)]]
    log = Transcript(outputs)
    key = slip10_child(parent, index, log)
    result.append({'name': 'child-order-zero-same-index-retry', 'kind': 'child',
                   'parent_key': parent.scalar.to_bytes(32, 'big').hex(),
                   'parent_chain': parent.chain_code.hex(), 'index': index,
                   'calls': log.calls,
                   'expected_key': key.scalar.to_bytes(32, 'big').hex(),
                   'expected_chain': key.chain_code.hex()})
    for invalid_name, output in [('left-at-order', outputs[0]), ('zero-child', outputs[1])]:
        log = Transcript([output])
        try:
            exact_payment_child(parent, index, log)
            raise AssertionError('BIP32 must fail requested child')
        except ValueError:
            pass
        assert len(log.calls) == 1
        result.append({'name': 'bip32-' + invalid_name, 'kind': 'payment-invalid',
                       'parent_key': parent.scalar.to_bytes(32, 'big').hex(),
                       'parent_chain': parent.chain_code.hex(), 'index': index,
                       'calls': log.calls, 'expected_error': 'invalid-child'})
    # A zero I_L is valid for child derivation when the resulting scalar is
    # nonzero. Nonhardened first input still becomes 01||I_R||same-index on retry.
    outputs = [r.N.to_bytes(32, 'big') + b'\x77' * 32,
               bytes(32) + b'\x88' * 32]
    log = Transcript(outputs)
    key = slip10_child(parent, 5, log)
    result.append({'name': 'normal-child-retry-zero-left-valid', 'kind': 'child',
                   'parent_key': parent.scalar.to_bytes(32, 'big').hex(),
                   'parent_chain': parent.chain_code.hex(), 'index': 5,
                   'calls': log.calls,
                   'expected_key': key.scalar.to_bytes(32, 'big').hex(),
                   'expected_chain': key.chain_code.hex()})
    return result


def generate():
    checks = verify_standards()
    desc = descriptor()
    desc_bytes = compact(desc)
    desc_hash = r.sha256(b'SLUG recovery profile\0v1\0' + desc_bytes.encode()).hex()
    cases = []
    for name, entropy in [('candidate-zero256', bytes(32)),
                          ('candidate-incrementing256', bytes(range(32)))]:
        mnemonic = r.mnemonic_from_entropy(entropy)
        seed = r.mnemonic_to_seed(mnemonic, '')
        root = r.ExtendedPrivate.master(seed)
        identity = gym(seed)
        accounts, payments = [], []
        for purpose, kind in KINDS.items():
            path = f"m/{purpose}'/{COIN}'/0'"
            account = r.derive_path(seed, path)
            accounts.append({'purpose': purpose, 'coin': COIN, 'account': 0,
                             'external_type': kind, 'internal_type': kind,
                             'key_origin': path,
                             'account_public_key': account.serialize(True, True),
                             'next_external': 26 if purpose == 84 else 0,
                             'next_internal': 27 if purpose == 84 else 0})
            for branch in (0, 1):
                parent = account.derive(branch)
                for index in (0, 25, 26, 4096, 2147483647):
                    payments.append(payment(parent.derive(index), purpose, branch, index))
        manifest = {'version': 2, 'descriptor': desc, 'descriptor_hash': desc_hash,
                    'root_public_key': root.serialize(True, True),
                    'gym_identity_uri': identity['identity_uri'],
                    'gym_path': identity['path'], 'gym_public_key': identity['public_key'],
                    'gym_id': identity['gym_id'], 'accounts': accounts}
        export = {'version': 2, 'mnemonic': mnemonic, 'manifest': manifest}
        cases.append({'name': name, 'entropy': entropy.hex(), 'seed': seed.hex(),
                      'export': export, 'canonical_manifest': compact(manifest),
                      'canonical_export': compact(export), 'payments': payments,
                      'gym': identity,
                      'non_runnable_genesis_example': gym(seed, '01' + '00' * 31)})
    return {'candidate_fixtures_only': True, 'production_issuance_enabled': False,
            'standards_checks': checks, 'descriptor': desc,
            'canonical_descriptor': desc_bytes, 'descriptor_hash': desc_hash,
            'cases': cases, 'injected_hmac': injected_transcripts(),
            'bip32_published': r.official_bip32_cases()}


if __name__ == '__main__':
    actual = json.dumps(generate(), indent=2) + '\n'
    target = ROOT / 'candidate_v1.json'
    if sys.argv[1:] == ['--check']:
        if target.read_text() != actual:
            raise SystemExit('independent candidate fixture differs')
        print('Published standards and independent candidate profile fixtures match.')
    elif sys.argv[1:] == ['--generate']:
        target.write_text(actual)
        print('Wrote public candidate fixtures after published standards checks.')
    else:
        raise SystemExit('usage: reference_profile.py --check|--generate')
