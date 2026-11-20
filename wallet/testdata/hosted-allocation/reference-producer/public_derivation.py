"""Independent CKDpub from locked public branch keys; no private fixture input.

The inherited Set24 arithmetic module is loaded only by the reviewed generator
AFTER its complete source/input/contract execution guard. Never imports Go.
"""
import hashlib
import hmac
import importlib.util
import struct
import sys


def load_oracle(path):
    spec = importlib.util.spec_from_file_location('set72_inherited_public_math', path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = value
    spec.loader.exec_module(value)
    return value


class PublicDerivation:
    def __init__(self, inherited, address_case):
        self.old = inherited
        self.branches = {}
        self.cache = {}
        for row in address_case['branches']:
            if row['purpose'] != 84:
                continue
            assert row['coin'] == row['account'] == 0
            assert row['branch'] in (0, 1) and row['script_type'] == 'p2wpkh'
            payload = inherited.decode_base58check(row['branch_public_key'])
            assert len(payload) == 78 and int.from_bytes(payload[:4], 'big') == inherited.SLUG_PUBLIC
            assert payload[4] == 4 and int.from_bytes(payload[9:13], 'big') == row['branch']
            inherited.validate_public_key(payload[45:])
            self.branches[row['branch']] = payload
        assert set(self.branches) == {0, 1}

    def point(self, encoded):
        old = self.old
        old.validate_public_key(encoded)
        x = int.from_bytes(encoded[1:], 'big')
        y = pow((x*x*x+7) % old.P, (old.P+1)//4, old.P)
        if (y & 1) != (encoded[0] & 1):
            y = old.P-y
        return x, y

    def child(self, branch, index):
        assert type(branch) is int and branch in (0, 1)
        assert type(index) is int and 0 <= index < 4096
        key = (branch, index)
        if key in self.cache:
            return self.cache[key]
        old, payload = self.old, self.branches[branch]
        digest = hmac.new(payload[13:45], payload[45:]+struct.pack('>I', index), hashlib.sha512).digest()
        scalar = int.from_bytes(digest[:32], 'big')
        # BIP32 CKDpub: IL >= n or point-at-infinity is invalid. IL == 0
        # itself is valid and leaves the public point unchanged.
        if scalar >= old.N:
            result = None
        else:
            parent = self.point(payload[45:])
            child = parent if scalar == 0 else old.point_add(old.point_multiply(scalar), parent)
            if child is None:
                result = None
            else:
                x, y = child
                encoded = bytes([2 | (y & 1)]) + x.to_bytes(32, 'big')
                program = old.hash160(encoded)
                result = (old.witness_v0(program), (b'\x00\x14'+program).hex())
        self.cache[key] = result
        return result

    def verify_overlap(self, address_case):
        count = 0
        for branch in address_case['branches']:
            if branch['purpose'] != 84:
                continue
            for row in branch['addresses']:
                assert self.child(branch['branch'], row['index']) == (row['address'], row['script_pub_key'])
                count += 1
        assert count == 20
        return count

    def with_injected_invalid(self, pairs):
        injected = frozenset(tuple(p) for p in pairs)
        def selected(branch, index):
            return None if (branch, index) in injected else self.child(branch, index)
        return selected


def address_for_script(raw):
    """Canonical SLUG forms inherited from the frozen public v1 vectors."""
    alphabet='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    if len(raw)==25 and raw[:3]==b'\x76\xa9\x14' and raw[-2:]==b'\x88\xac':
        payload=b'\x53'+raw[3:-2]
    elif len(raw)==23 and raw[:2]==b'\xa9\x14' and raw[-1:]==b'\x87':
        payload=b'\x47'+raw[2:-1]
    else:
        assert (len(raw)==22 and raw[:2]==b'\x00\x14') or (len(raw)==34 and raw[:2]==b'\x51\x20')
        version=0 if raw[0]==0 else 1
        data=[version];acc=bits=0
        for x in raw[2:]:
            acc=(acc<<8)|x;bits+=8
            while bits>=5:
                bits-=5;data.append((acc>>bits)&31)
        if bits:data.append((acc<<(5-bits))&31)
        hrp='slug';values=[ord(c)>>5 for c in hrp]+[0]+[ord(c)&31 for c in hrp]+data+[0]*6
        check=1
        for value in values:
            high=check>>25;check=((check&0x1ffffff)<<5)^value
            for bit,poly in enumerate((0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3)):
                if (high>>bit)&1:check^=poly
        check^=1 if version==0 else 0x2bc830a3
        return hrp+'1'+''.join('qpzry9x8gf2tvdw0s3jn54khce6mua7l'[x] for x in data+[(check>>(5*(5-i)))&31 for i in range(6)])
    payload+=hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    value=int.from_bytes(payload,'big');out=''
    while value:
        value,mod=divmod(value,58);out=alphabet[mod]+out
    return '1'*(len(payload)-len(payload.lstrip(b'\x00')))+out
