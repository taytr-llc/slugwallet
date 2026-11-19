#!/usr/bin/env python3
"""Public-fixture BIP39/BIP32/SLUG oracle, independent of all SLUG Go code.

Variable-time reference math, not production cryptography. CLI inputs select
published fixtures only. A supplied gym path is a test parameter, not a policy.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import hmac
import json
from pathlib import Path
import re
import struct
import unicodedata

ROOT = Path(__file__).resolve().parent
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
HARDENED = 1 << 31
BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
BECH32 = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
BTC_PUBLIC = 0x0488B21E
BTC_PRIVATE = 0x0488ADE4
SLUG_PUBLIC = 0x534C5547
SLUG_PRIVATE = 0x736C7567
SLUG_NETWORK = 0x534C5547
SLUG_GENESIS = '7893676099cf9985bb198dfb6a347d9422a19f2422cf3326a999a7230ce246cd'
WORDS = tuple((ROOT / 'sources/english.txt').read_text().splitlines())
WORD_INDEX = {word: index for index, word in enumerate(WORDS)}
if len(WORDS) != 2048 or len(WORD_INDEX) != 2048:
    raise ValueError('invalid pinned English wordlist')


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hash160(data: bytes) -> bytes:
    return hashlib.new('ripemd160', sha256(data)).digest()


def mnemonic_from_entropy(entropy: bytes) -> str:
    if len(entropy) not in (16, 20, 24, 28, 32):
        raise ValueError('entropy must be 128/160/192/224/256 bits')
    checksum_bits = len(entropy) // 4
    value = (int.from_bytes(entropy, 'big') << checksum_bits) | (sha256(entropy)[0] >> (8 - checksum_bits))
    count = (len(entropy) * 8 + checksum_bits) // 11
    return ' '.join(WORDS[(value >> (11 * (count - 1 - i))) & 2047] for i in range(count))


def entropy_from_mnemonic(mnemonic: str) -> bytes:
    # This oracle intentionally requires canonical English spelling/spacing.
    words = mnemonic.split(' ')
    if len(words) not in (12, 15, 18, 21, 24) or any(word not in WORD_INDEX for word in words):
        raise ValueError('invalid canonical English mnemonic')
    value = 0
    for word in words:
        value = (value << 11) | WORD_INDEX[word]
    checksum_bits = len(words) // 3
    entropy_bits = len(words) * 11 - checksum_bits
    entropy = (value >> checksum_bits).to_bytes(entropy_bits // 8, 'big')
    if (value & ((1 << checksum_bits) - 1)) != (sha256(entropy)[0] >> (8 - checksum_bits)):
        raise ValueError('mnemonic checksum mismatch')
    return entropy


def mnemonic_to_seed(mnemonic: str, passphrase: str) -> bytes:
    entropy_from_mnemonic(mnemonic)
    return hashlib.pbkdf2_hmac(
        'sha512', unicodedata.normalize('NFKD', mnemonic).encode(),
        b'mnemonic' + unicodedata.normalize('NFKD', passphrase).encode(), 2048, 64)


def point_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    ax, ay = a
    bx, by = b
    if ax == bx:
        if (ay + by) % P == 0:
            return None
        slope = (3 * ax * ax) * pow(2 * ay, -1, P) % P
    else:
        slope = (by - ay) * pow(bx - ax, -1, P) % P
    x = (slope * slope - ax - bx) % P
    return x, (slope * (ax - x) - ay) % P


def point_multiply(scalar: int):
    if not 0 < scalar < N:
        raise ValueError('invalid private scalar')
    out, addend = None, G
    while scalar:
        if scalar & 1:
            out = point_add(out, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    return out


def public_key(scalar: int) -> bytes:
    x, y = point_multiply(scalar)
    return bytes([2 | (y & 1)]) + x.to_bytes(32, 'big')


def validate_public_key(key: bytes) -> None:
    if len(key) != 33 or key[0] not in (2, 3):
        raise ValueError('invalid compressed public key')
    x = int.from_bytes(key[1:], 'big')
    if x >= P:
        raise ValueError('public coordinate exceeds field')
    square = (pow(x, 3, P) + 7) % P
    y = pow(square, (P + 1) // 4, P)
    if y * y % P != square:
        raise ValueError('point not on secp256k1')


def base58check(payload: bytes) -> str:
    data = payload + sha256(sha256(payload))[:4]
    value, encoded = int.from_bytes(data, 'big'), ''
    while value:
        value, remainder = divmod(value, 58)
        encoded = BASE58[remainder] + encoded
    return '1' * (len(data) - len(data.lstrip(b'\x00'))) + encoded


def decode_base58check(text: str) -> bytes:
    if not text or len(text) > 160:
        raise ValueError('invalid Base58 length')
    value = 0
    for char in text:
        if char not in BASE58:
            raise ValueError('invalid Base58 character')
        value = value * 58 + BASE58.index(char)
    data = b'\x00' * (len(text) - len(text.lstrip('1'))) + value.to_bytes((value.bit_length() + 7) // 8, 'big')
    if len(data) < 5 or sha256(sha256(data[:-4]))[:4] != data[-4:]:
        raise ValueError('Base58 checksum mismatch')
    if base58check(data[:-4]) != text:
        raise ValueError('noncanonical Base58')
    return data[:-4]


def polymod(values):
    check = 1
    for value in values:
        high = check >> 25
        check = ((check & 0x1FFFFFF) << 5) ^ value
        for bit, polynomial in enumerate((0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)):
            if (high >> bit) & 1:
                check ^= polynomial
    return check


def witness_v0(program: bytes, hrp='slug') -> str:
    if len(program) not in (20, 32):
        raise ValueError('invalid witness v0 program')
    data, acc, bits = [0], 0, 0
    for byte in program:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            data.append((acc >> bits) & 31)
    if bits:
        data.append((acc << (5 - bits)) & 31)
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    checksum = polymod(expanded + data + [0] * 6) ^ 1
    return hrp + '1' + ''.join(BECH32[v] for v in data + [(checksum >> (5 * (5 - i))) & 31 for i in range(6)])


@dataclass(frozen=True)
class ExtendedPrivate:
    scalar: int
    chain_code: bytes
    depth: int = 0
    parent_fingerprint: bytes = bytes(4)
    child_number: int = 0

    @classmethod
    def master(cls, seed: bytes):
        if not 16 <= len(seed) <= 64:
            raise ValueError('BIP32 seed length out of bounds')
        digest = hmac.digest(b'Bitcoin seed', seed, 'sha512')
        scalar = int.from_bytes(digest[:32], 'big')
        if not 0 < scalar < N:
            raise ValueError('invalid BIP32 master')
        return cls(scalar, digest[32:])

    def derive(self, index: int):
        if not 0 <= index <= 0xFFFFFFFF or self.depth >= 255:
            raise ValueError('BIP32 child/depth out of bounds')
        pub = public_key(self.scalar)
        data = b'\x00' + self.scalar.to_bytes(32, 'big') if index >= HARDENED else pub
        digest = hmac.digest(self.chain_code, data + struct.pack('>I', index), 'sha512')
        left = int.from_bytes(digest[:32], 'big')
        child = (left + self.scalar) % N
        if left >= N or child == 0:
            # Exact-path oracle: report invalid child instead of silently using
            # another index. A production iterator must record any skipped index.
            raise ValueError('invalid BIP32 child at requested index')
        return ExtendedPrivate(child, digest[32:], self.depth + 1, hash160(pub)[:4], index)

    def serialize(self, public=False, slug=False):
        version = (SLUG_PUBLIC if public else SLUG_PRIVATE) if slug else (BTC_PUBLIC if public else BTC_PRIVATE)
        key = public_key(self.scalar) if public else b'\x00' + self.scalar.to_bytes(32, 'big')
        payload = struct.pack('>IB', version, self.depth) + self.parent_fingerprint + struct.pack('>I', self.child_number) + self.chain_code + key
        return base58check(payload)


def validate_extended(text: str) -> bytes:
    data = decode_base58check(text)
    if len(data) != 78:
        raise ValueError('invalid extended-key length')
    version = int.from_bytes(data[:4], 'big')
    if version not in (BTC_PUBLIC, BTC_PRIVATE, SLUG_PUBLIC, SLUG_PRIVATE):
        raise ValueError('unknown extended-key version')
    if data[4] == 0 and data[5:13] != bytes(8):
        raise ValueError('nonzero root parent/index')
    key = data[45:]
    if version in (BTC_PUBLIC, SLUG_PUBLIC):
        validate_public_key(key)
    elif key[0] != 0 or not 0 < int.from_bytes(key[1:], 'big') < N:
        raise ValueError('invalid extended private key')
    return data


def parse_path(path: str, hardened_only=False) -> tuple[int, ...]:
    if not isinstance(path, str) or len(path) > 4096 or not re.fullmatch(r"m(?:/(?:0|[1-9][0-9]*)(?:')?)*", path):
        raise ValueError('invalid canonical BIP32 path')
    components = path.split('/')[1:]
    if len(components) > 255 or (hardened_only and not components):
        raise ValueError('invalid path depth')
    indexes = []
    for component in components:
        hardened = component.endswith("'")
        index = int(component[:-1] if hardened else component)
        if index >= HARDENED or (hardened_only and not hardened):
            raise ValueError('path index/hardening mismatch')
        indexes.append(index + (HARDENED if hardened else 0))
    return tuple(indexes)


def derive_path(seed: bytes, path: str) -> ExtendedPrivate:
    key = ExtendedPrivate.master(seed)
    for index in parse_path(path):
        key = key.derive(index)
    return key


def gym_identity(seed: bytes, path: str, network: int, genesis: str) -> dict:
    parse_path(path, hardened_only=True)
    if type(network) is not int or not 0 < network <= 0xFFFFFFFF:
        raise ValueError('invalid network')
    if not re.fullmatch('[0-9a-fA-F]{64}', genesis) or int(genesis, 16) == 0:
        raise ValueError('invalid genesis')
    pub = public_key(derive_path(seed, path).scalar)
    binding = b'SLUG gym identity\x00v1\x00' + struct.pack('<I', network) + bytes.fromhex(genesis) + pub
    return {'path': path, 'network': network, 'genesis': genesis.lower(), 'public_key': pub.hex(), 'gym_id': sha256(binding).hex()}


def official_bip32_cases():
    text = (ROOT / 'sources/bip-0032.mediawiki').read_text()
    cases = []
    for number in range(1, 5):
        section = text.split(f'===Test vector {number}===')[1].split('===Test vector')[0]
        seed = re.search(r'Seed \(hex\): ([0-9a-f]+)', section).group(1)
        for path, pub, prv in re.findall(r'\* Chain (.+)\n\*\* ext pub: (\S+)\n\*\* ext prv: (\S+)', section):
            cases.append({'vector': number, 'seed': seed, 'path': path.replace('<sub>H</sub>', "'"), 'xpub': pub, 'xprv': prv})
    return cases


def official_invalid_keys():
    text = (ROOT / 'sources/bip-0032.mediawiki').read_text().split('===Test vector 5===')[1]
    return re.findall(r'^\* (\S+) \((.+)\)$', text, re.M)


def verify_sources():
    manifest = json.loads((ROOT / 'sources.json').read_text())
    for entry in manifest['sources']:
        if sha256((ROOT / entry['local']).read_bytes()).hex() != entry['sha256']:
            raise ValueError('source checksum mismatch: ' + entry['local'])


def verify_official_vectors() -> dict:
    verify_sources()
    english = json.loads((ROOT / 'sources/mnemonic-vectors.json').read_text())['english']
    for entropy, mnemonic, seed_hex, xprv in english:
        assert mnemonic_from_entropy(bytes.fromhex(entropy)) == mnemonic
        assert entropy_from_mnemonic(mnemonic).hex() == entropy
        seed = mnemonic_to_seed(mnemonic, 'TREZOR')
        assert seed.hex() == seed_hex
        assert ExtendedPrivate.master(seed).serialize() == xprv
    bip32 = official_bip32_cases()
    assert len(bip32) == 17
    for case in bip32:
        key = derive_path(bytes.fromhex(case['seed']), case['path'])
        assert key.serialize() == case['xprv']
        assert key.serialize(public=True) == case['xpub']
        validate_extended(case['xpub'])
        validate_extended(case['xprv'])
    invalid = official_invalid_keys()
    assert len(invalid) == 16
    for key, reason in invalid:
        try:
            validate_extended(key)
        except ValueError:
            continue
        raise AssertionError('accepted invalid official key: ' + reason)
    return {'bip39_english': len(english), 'bip32_valid_paths': len(bip32), 'bip32_invalid_keys': len(invalid)}


def derive_fixture(index=0, passphrase='TREZOR', gym_path=None) -> dict:
    fixtures = json.loads((ROOT / 'sources/mnemonic-vectors.json').read_text())['english']
    if type(index) is not int or not 0 <= index < len(fixtures) or passphrase not in ('', 'TREZOR'):
        raise ValueError('CLI derives only published fixtures and explicit test passphrases')
    entropy, mnemonic, _, _ = fixtures[index]
    seed = mnemonic_to_seed(mnemonic, passphrase)
    records = []
    for purpose in (44, 84):
        for branch in (0, 1):
            path = f"m/{purpose}'/0'/0'/{branch}/0"
            key = derive_path(seed, path)
            pub = public_key(key.scalar)
            script = b'\x76\xa9\x14' + hash160(pub) + b'\x88\xac' if purpose == 44 else b'\x00\x14' + hash160(pub)
            records.append({'path': path, 'public_key': pub.hex(), 'slug_xpub': key.serialize(True, True),
                            'slug_xprv_public_fixture_only': key.serialize(False, True),
                            'address': base58check(b'\x53' + hash160(pub)) if purpose == 44 else witness_v0(hash160(pub)),
                            'script_pub_key': script.hex()})
    out = {'fixture_only': True, 'official_english_vector_index': index, 'entropy': entropy, 'mnemonic': mnemonic,
           'passphrase': passphrase, 'bip32_seed_public_fixture_only': seed.hex(), 'coin_type_fixture_only': 0,
           'payment_keys': records, 'gym_path_is_not_production_policy': True}
    if gym_path is not None:
        out['gym'] = gym_identity(seed, gym_path, SLUG_NETWORK, SLUG_GENESIS)
    return out


def golden_records():
    # Example paths only; deliberately not SLUG production path candidates.
    return {'notice': 'Published public fixtures only. No production phrase, coin type, gym path or custody policy is chosen.',
            'cases': [derive_fixture(0, '', "m/0'/1'/2'"), derive_fixture(0, 'TREZOR', "m/1'/2'/3'"),
                      derive_fixture(8, '', "m/0'/1'/2'")]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--check', action='store_true', help='check official vectors, source hashes and frozen derived fixtures')
    group.add_argument('--write', action='store_true', help='regenerate derived public fixture JSON only')
    parser.add_argument('--fixture-index', type=int, default=0)
    parser.add_argument('--passphrase', choices=('', 'TREZOR'), default='TREZOR', help='published fixture test passphrase only')
    parser.add_argument('--gym-path', help="explicit all-hardened example path; no default gym derivation policy")
    args = parser.parse_args()
    counts = verify_official_vectors()
    if args.check or args.write:
        expected = json.dumps(golden_records(), indent=2) + '\n'
        path = ROOT / 'reference_vectors.json'
        if args.write:
            path.write_text(expected)
        elif path.read_text() != expected:
            raise SystemExit('derived fixture JSON differs')
        print(json.dumps({'passed': counts, 'derived_fixture_cases': 3, 'mode': 'write' if args.write else 'check'}))
    else:
        print(json.dumps(derive_fixture(args.fixture_index, args.passphrase, args.gym_path), indent=2))


if __name__ == '__main__':
    main()
