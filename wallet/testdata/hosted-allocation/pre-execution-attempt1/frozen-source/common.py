"""Independent source-only draft. No imports of Go or live wallet/provider code."""
import copy
import hashlib
import json
import re
import struct

FIXTURES = ('zero256', 'incrementing256')
TIME_MAX = 253402300799999
U32_MAX = 2**32 - 1
U64_MAX = 2**64 - 1
ISSUER = 'https://identity.slug.invalid'
MODE = 'local-hosted-fixture-pool'
DRIVER = 'local-published-fixture-evidence-v1'
WRAPPER = 'public-fixture-wrapper-v1'

class Rejected(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code

def need(ok, code='invalid'):
    if not ok:
        raise Rejected(code)

def integer(value, minimum=0, maximum=U32_MAX):
    need(type(value) is int and minimum <= value <= maximum)
    return value

def text(value, maximum):
    need(type(value) is str)
    try:
        raw = value.encode('utf-8', 'strict')
    except UnicodeError:
        raise Rejected('invalid')
    need(len(raw) <= maximum)
    return value

def hex64(value, nonzero=False):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None)
    need(not nonzero or value != '0'*64)
    return value

def exact(value, fields):
    need(type(value) is dict and set(value) == set(fields))
    return {name: value[name] for name in fields}

def canonical(value):
    # Match encoding/json: UTF8, short control escapes and HTML/line escapes.
    try:
        raw = json.dumps(value, ensure_ascii=False, allow_nan=False,
                         separators=(',', ':'))
        raw = raw.replace('<', '\\u003c').replace('>', '\\u003e').replace('&', '\\u0026')
        raw = raw.replace('\u2028', '\\u2028').replace('\u2029', '\\u2029')
        return raw.encode('utf-8', 'strict')
    except (UnicodeError, TypeError, ValueError):
        raise Rejected('invalid')

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def framed(value):
    raw = text(value, 1024).encode('utf8')
    return struct.pack('<I', len(raw)) + raw

def principal_id(issuer, subject):
    need(issuer and subject)
    return sha(b'SLUG account principal\x00v1\x00' + framed(issuer) + framed(subject))

def event_id(principal, event):
    hex64(principal)
    need(event and len(event.encode('utf8')) <= 256)
    return sha(b'SLUG account recovery event\x00v1\x00' + bytes.fromhex(principal) + framed(event))

def parse(raw, cap, file=False):
    need(type(raw) is bytes and 0 < len(raw) <= cap)
    if file:
        need(raw.endswith(b'\n') and not raw.endswith(b'\n\n'))
        raw = raw[:-1]
    def pairs(items):
        obj = {}
        for key, value in items:
            need(key not in obj)
            obj[key] = value
        return obj
    def number(value):
        need(re.fullmatch('0|[1-9][0-9]*', value) is not None)
        return int(value)
    def forbidden(value):
        raise Rejected('invalid')
    try:
        value = json.loads(raw.decode('utf8', 'strict'), object_pairs_hook=pairs,
                           parse_int=number, parse_float=forbidden,
                           parse_constant=forbidden)
    except (UnicodeError, ValueError) as err:
        if isinstance(err, Rejected):
            raise
        raise Rejected('invalid')
    # Schema callers reorder to declared field order before their equality check.
    return value, raw

def packed(value, cap, file=False):
    raw = canonical(value) + (b'\n' if file else b'')
    need(len(raw) <= cap, 'capacity')
    return raw

def own(value):
    return copy.deepcopy(value)
