#!/usr/bin/env python3
"""Independent public-fixture BIP32/address oracle; never reads wallet or Go data.

Seed is BIP32 test vector 1, publicly known and unusable for real funds.
https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vector-1
SLUG foundation retains coin type 0; this does not choose future custody rules.
"""
import argparse
import hashlib
import hmac
import json
from pathlib import Path

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
SEED = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

def add(a, b):
    if a is None: return b
    if b is None: return a
    x, y = a
    u, v = b
    if x == u and (y + v) % P == 0: return None
    slope = ((3*x*x)*pow(2*y, -1, P) if a == b else (v-y)*pow(u-x, -1, P)) % P
    xx = (slope*slope - x - u) % P
    return xx, (slope*(x-xx)-y) % P

def point(k):
    value, q = None, G
    while k:
        if k & 1: value = add(value, q)
        q, k = add(q, q), k >> 1
    return value

def public(k):
    x, y = point(k)
    return bytes([2+(y&1)])+x.to_bytes(32, 'big')

def hash160(raw):
    return hashlib.new('ripemd160', hashlib.sha256(raw).digest()).digest()

def base58check(raw):
    raw += hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4]
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    n, out = int.from_bytes(raw, 'big'), ''
    while n:
        n, r = divmod(n, 58)
        out = alphabet[r]+out
    return '1'*(len(raw)-len(raw.lstrip(b'\x00')))+out

def derive(path):
    digest = hmac.digest(b'Bitcoin seed', SEED, 'sha512')
    key, code = int.from_bytes(digest[:32], 'big'), digest[32:]
    for index in path:
        data = b'\x00'+key.to_bytes(32,'big') if index >= 2**31 else public(key)
        digest = hmac.digest(code, data+index.to_bytes(4,'big'), 'sha512')
        left = int.from_bytes(digest[:32],'big')
        assert left < N and (left+key) % N != 0
        key, code = (left+key) % N, digest[32:]
    return key, code

def bech32(program):
    hrp = 'slug'
    values = [0]
    accumulator = bits = 0
    for byte in program:
        accumulator = (accumulator << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            values.append((accumulator >> bits) & 31)
    if bits: values.append((accumulator << (5-bits)) & 31)
    def polymod(data):
        check = 1
        generators = [0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3]
        for value in data:
            top, check = check >> 25, ((check & 0x1ffffff) << 5) ^ value
            for bit, generator in enumerate(generators):
                if (top >> bit) & 1: check ^= generator
        return check
    expanded = [ord(c)>>5 for c in hrp]+[0]+[ord(c)&31 for c in hrp]
    checksum = polymod(expanded+values+[0]*6) ^ 1
    values += [(checksum >> (5*(5-i))) & 31 for i in range(6)]
    alphabet = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
    return hrp+'1'+''.join(alphabet[v] for v in values)

def fixture():
    key, code = derive([])
    master = base58check(bytes.fromhex('0488b21e')+bytes(9)+code+public(key))
    assert master == 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8'
    assert point(N) is None
    result = {'fixture_only': True, 'seed': SEED.hex(), 'bip32_master_xpub': master, 'coin_type': 0, 'addresses': []}
    for purpose, kind in [(44, 'legacy'), (84, 'bech32')]:
        for branch, name in [(0, 'receive'), (1, 'change')]:
            path = [purpose+2**31,2**31,2**31,branch,0]
            pub = public(derive(path)[0])
            payload = hash160(pub)
            result['addresses'].append({'type':kind,'branch':name,'path':f"m/{purpose}'/0'/0'/{branch}/0",'public_key':pub.hex(),'hash160':payload.hex(),'address':base58check(b'\x53'+payload) if kind=='legacy' else bech32(payload)})
    result['external_sink'] = base58check(b'\x53'+hash160(public(2)))
    return result

if __name__ == '__main__':
    args = argparse.ArgumentParser()
    args.add_argument('--check', action='store_true')
    options = args.parse_args()
    data = json.dumps(fixture(), indent=2)+'\n'
    path = Path(__file__).with_name('addresses_v1.json')
    if options.check:
        assert path.read_text() == data, 'independent fixture mismatch'
        print('independent address fixture verified')
    else:
        path.write_text(data)
