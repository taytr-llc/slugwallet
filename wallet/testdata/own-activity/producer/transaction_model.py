"""Independent Set70 transaction/accounting model. SOURCE ONLY until approved.

Uses the frozen public contract and Python standard library, never Go output.
This validates supplied local-record consistency, not signatures or chain state.
"""
import hashlib
import re
import struct

MONEY = 2100000000000000
MAX_MS = 253402300799999
MAX_HEIGHT = 2147483647
MAX_RAW = 262144
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX = re.compile(r"(?:[0-9a-f]{2})*\Z")


class Refusal(ValueError):
    def __init__(self, category):
        super().__init__(category)
        self.category = category


def require(condition, category="corrupt"):
    if not condition:
        raise Refusal(category)


def integer(x, lo, hi):
    return type(x) is int and lo <= x <= hi


def hash_text(x, nonzero=False):
    return isinstance(x, str) and HEX64.fullmatch(x) and (not nonzero or x != "0" * 64)


def raw_bytes(text):
    require(isinstance(text, str) and HEX.fullmatch(text))
    require(len(text) <= 2 * MAX_RAW, "capacity")
    return bytes.fromhex(text)


def fields(value, names):
    require(type(value) is dict and set(value) == set(names))


def compact(n):
    require(integer(n, 0, 0xffffffffffffffff))
    if n < 253:
        return bytes([n])
    if n <= 0xffff:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xffffffff:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


class Reader:
    def __init__(self, raw):
        self.raw, self.at = raw, 0

    def take(self, n):
        require(integer(n, 0, len(self.raw)) and self.at + n <= len(self.raw))
        out = self.raw[self.at:self.at+n]
        self.at += n
        return out

    def number(self, fmt):
        return struct.unpack(fmt, self.take(struct.calcsize(fmt)))[0]

    def compact(self):
        tag = self.number("<B")
        if tag < 253:
            return tag
        fmt, low = {253: ("<H", 253), 254: ("<I", 65536),
                    255: ("<Q", 4294967296)}[tag]
        n = self.number(fmt)
        require(n >= low)
        return n

    def blob(self, maximum):
        n = self.compact()
        require(n <= maximum, "capacity")
        return self.take(n)


def serialize(tx, witness=True):
    has = witness and tx["has_witness"]
    out = bytearray(struct.pack("<i", tx["version"]))
    if has:
        out.extend(b"\x00\x01")
    out.extend(compact(len(tx["inputs"])))
    for row in tx["inputs"]:
        out.extend(row["previous_hash"])
        out.extend(struct.pack("<I", row["previous_index"]))
        out.extend(compact(len(row["script"])))
        out.extend(row["script"])
        out.extend(struct.pack("<I", row["sequence"]))
    out.extend(compact(len(tx["outputs"])))
    for row in tx["outputs"]:
        out.extend(struct.pack("<q", row["atoms"]))
        out.extend(compact(len(row["script"])))
        out.extend(row["script"])
    if has:
        for row in tx["inputs"]:
            out.extend(compact(len(row["witness"])))
            for value in row["witness"]:
                out.extend(compact(len(value)))
                out.extend(value)
    out.extend(struct.pack("<I", tx["lock_time"]))
    return bytes(out)


def parse_transaction(raw):
    require(type(raw) is bytes)
    require(len(raw) <= MAX_RAW, "capacity")
    r = Reader(raw)
    version = r.number("<i")
    count = r.compact()
    has = count == 0
    if has:
        require(r.number("<B") == 1)
        count = r.compact()
    require(count > 0)
    require(count <= 256, "capacity")
    inputs = []
    previous = set()
    for _ in range(count):
        h, index = r.take(32), r.number("<I")
        require((h, index) not in previous)
        previous.add((h, index))
        inputs.append({"previous_hash": h, "previous_index": index,
                       "script": r.blob(10240), "sequence": r.number("<I"),
                       "witness": []})
    count = r.compact()
    require(count > 0)
    require(count <= 256, "capacity")
    outputs = []
    total = 0
    for _ in range(count):
        amount = r.number("<q")
        require(0 <= amount <= MONEY)
        total += amount
        require(total <= MONEY)
        outputs.append({"atoms": amount, "script": r.blob(10240)})
    items = 0
    if has:
        for row in inputs:
            count = r.compact()
            require(count <= 128, "capacity")
            items += count
            require(items <= 4096, "capacity")
            row["witness"] = [r.blob(MAX_RAW) for _ in range(count)]
        # A stack containing one empty byte string is still nonempty.
        require(items > 0)
    lock_time = r.number("<I")
    require(r.at == len(raw))
    nulls = [i for i, row in enumerate(inputs)
             if row["previous_hash"] == bytes(32) and row["previous_index"] == 0xffffffff]
    require(not nulls or len(inputs) == 1 and nulls == [0])
    tx = {"version": version, "inputs": inputs, "outputs": outputs,
          "lock_time": lock_time, "has_witness": has, "coinbase": bool(nulls)}
    require(serialize(tx) == raw)
    tx["txid"] = hashlib.sha256(hashlib.sha256(serialize(tx, False)).digest()).digest()[::-1].hex()
    return tx


def base58check(prefix, payload):
    body = bytes([prefix]) + payload
    data = body + hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4]
    number, result = int.from_bytes(data, "big"), ""
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    while number:
        number, rem = divmod(number, 58)
        result = alphabet[rem] + result
    leading = len(data) - len(data.lstrip(b"\0"))
    return "1" * leading + result


def segwit_address(version, program):
    values, acc, bits = [], 0, 0
    for value in program:
        acc = (acc << 8) | value
        bits += 8
        while bits >= 5:
            bits -= 5
            values.append((acc >> bits) & 31)
    if bits:
        values.append((acc << (5-bits)) & 31)
    hrp = "slug"
    data = [version] + values
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    check = 1
    generators = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    for value in expanded + data + [0]*6:
        high = check >> 25
        check = ((check & 0x1ffffff) << 5) ^ value
        for i, generator in enumerate(generators):
            if (high >> i) & 1:
                check ^= generator
    check ^= 1 if version == 0 else 0x2bc830a3
    checksum = [(check >> (5*(5-i))) & 31 for i in range(6)]
    alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    return hrp + "1" + "".join(alphabet[x] for x in data + checksum)


def output_address(script):
    if len(script) == 25 and script[:3] == b"\x76\xa9\x14" and script[-2:] == b"\x88\xac":
        return base58check(0x53, script[3:-2])
    if len(script) == 23 and script[:2] == b"\xa9\x14" and script[-1:] == b"\x87":
        return base58check(0x47, script[2:-1])
    if len(script) in (22, 34) and script[:2] == bytes([0, len(script)-2]):
        return segwit_address(0, script[2:])
    if len(script) == 34 and script[:2] == b"\x51\x20":
        return segwit_address(1, script[2:])
    return ""


def project_record(record, height):
    fields(record, ("txid", "raw_hex", "recorded_at_ms", "block", "credits", "debits"))
    require(hash_text(record["txid"]))
    require(integer(height, 0, MAX_HEIGHT))
    require(integer(record["recorded_at_ms"], 0, MAX_MS))
    raw = raw_bytes(record["raw_hex"])
    tx = parse_transaction(raw)
    require(tx["txid"] == record["txid"])
    block = record["block"]
    if block is None:
        confirmations = 0
    else:
        fields(block, ("height", "hash", "time_ms"))
        require(integer(block["height"], 0, height) and hash_text(block["hash"], True))
        require(integer(block["time_ms"], 0, MAX_MS))
        confirmations = height - block["height"] + 1
    require(type(record["credits"]) is list and type(record["debits"]) is list)
    require(len(record["credits"]) <= len(tx["outputs"]) and len(record["debits"]) <= len(tx["inputs"]))
    credits, last = {}, -1
    received, change, spent = 0, 0, 0
    for row in record["credits"]:
        fields(row, ("index", "atoms", "change"))
        index = row["index"]
        require(integer(index, 0, len(tx["outputs"])-1) and index > last)
        require(integer(row["atoms"], 0, MONEY) and type(row["change"]) is bool)
        require(row["atoms"] == tx["outputs"][index]["atoms"])
        credits[index], last = row, index
        received += row["atoms"]
        if row["change"]:
            change += row["atoms"]
    last = -1
    for row in record["debits"]:
        fields(row, ("index", "atoms"))
        require(integer(row["index"], 0, len(tx["inputs"])-1) and row["index"] > last)
        require(integer(row["atoms"], 0, MONEY))
        last = row["index"]
        spent += row["atoms"]
    require(received <= MONEY and spent <= MONEY)
    require(record["credits"] or record["debits"])
    require(not tx["coinbase"] or not record["debits"])
    fee = None
    if not tx["coinbase"] and len(record["debits"]) == len(tx["inputs"]):
        fee = spent - sum(row["atoms"] for row in tx["outputs"])
        require(0 <= fee <= MONEY)
    item = {"txid": tx["txid"], "raw_sha256": hashlib.sha256(raw).hexdigest(),
            "recorded_at_ms": record["recorded_at_ms"], "coinbase": tx["coinbase"],
            "block": block, "confirmations": confirmations,
            "received_atoms": received, "spent_atoms": spent, "change_atoms": change,
            "net_atoms": received-spent, "fee_atoms": fee,
            "input_count": len(tx["inputs"]), "output_count": len(tx["outputs"]),
            "owned_input_count": len(record["debits"]), "owned_output_count": len(record["credits"])}
    outputs = [{"index": i, "atoms": row["atoms"], "owned": i in credits,
                "change": i in credits and credits[i]["change"],
                "address": output_address(row["script"])} for i, row in enumerate(tx["outputs"])]
    return {"item": item, "outputs": outputs}
