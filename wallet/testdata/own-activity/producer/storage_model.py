"""Independent bounded legacy-bucket selection/ownership model; source only.

Inputs are synthetic or archived public hex bucket rows, not a wallet database.
Python dictionary sorting models a DB cursor; charged visits model the contract,
not Python's own allocation strategy. No new Go implementation is imported.
"""
import json
import struct
from transaction_model import MAX_MS, MAX_HEIGHT, MONEY, Refusal, fields, integer, parse_transaction, project_record, require


def be32(n):
    return struct.pack(">I", n)


def be64(n):
    return struct.pack(">Q", n)


def number(raw, width):
    require(len(raw) == width)
    return int.from_bytes(raw, "big")


def time_ms(raw):
    seconds = number(raw, 8)
    require(seconds <= MAX_MS // 1000)
    return seconds * 1000


def display(raw):
    require(len(raw) == 32)
    return raw[::-1].hex()


class Store:
    def __init__(self, encoded):
        require(type(encoded) is dict)
        require(set(encoded) == {"m", "t", "b", "c", "d", "u", "mc", "mi"})
        self.buckets = {}
        for name, rows in encoded.items():
            require(type(rows) is dict)
            self.buckets[name] = {bytes.fromhex(k): bytes.fromhex(v) for k, v in rows.items()}
        self.metadata_visits = 0
        self.gets = 0
        self.index_positions = 0
        self.raw_parsed = 0
        self.mi_reads = 0

    def charge(self, count=1):
        if count > 8192 - self.metadata_visits:
            self.metadata_visits += 1  # refusal probe, no whole-block copy
            raise Refusal("capacity")
        self.metadata_visits += count

    def get(self, bucket, key):
        self.gets += 1
        if bucket == "mi":
            self.mi_reads += 1
        return self.buckets[bucket].get(key)

    def indexed(self, bucket, prefix, bound):
        # A real cursor starts with Seek(prefix); it never scans foreign rows.
        matching = sorted(k for k in self.buckets[bucket] if k.startswith(prefix))
        rows = []
        for k in matching:
            self.index_positions += 1
            require(len(rows) < bound)
            rows.append((k, self.buckets[bucket][k]))
        self.index_positions += 1  # foreign-prefix/EOF refusal probe
        return rows

    def select(self, height):
        require(integer(height, 0, MAX_HEIGHT))
        unmined = []
        for key in sorted(self.buckets["m"]):
            self.charge()
            require(len(unmined) < 4096, "capacity")
            value = self.buckets["m"][key]
            require(len(key) == 32 and len(value) >= 8)
            unmined.append((key, time_ms(value[:8])))
        unmined.sort(key=lambda r: (-r[1], display(r[0])))
        selected = [(key, None) for key, _ in unmined[:256]]
        if len(unmined) > 256:
            return selected, True
        seen = {key for key, _ in unmined}
        for key in sorted(self.buckets["b"], reverse=True):
            self.charge()
            value = self.buckets["b"][key]
            require(len(key) == 4 and len(value) >= 44)
            h = number(key, 4)
            require(h <= height)
            block_hash = value[:32]
            require(block_hash != bytes(32))
            timestamp = time_ms(value[32:40])
            count = number(value[40:44], 4)
            require(count > 0)
            require(count <= 4096, "capacity")
            require(len(value) == 44 + 32 * count)
            self.charge(count)
            hashes = [value[44+32*i:76+32*i] for i in range(count)]
            require(len(set(hashes)) == count)
            hashes.sort(key=display)
            block = {"height": h, "hash": display(block_hash), "time_ms": timestamp}
            for tx_hash in hashes:
                if tx_hash in seen:
                    continue
                if len(selected) == 256:
                    return selected, True
                selected.append((tx_hash, block))
                seen.add(tx_hash)
        return selected, False

    @staticmethod
    def credit(value, unmined=False, must_unspent=False, must_spent=False):
        require(value is not None and len(value) in (9, 81))
        amount, flag = number(value[:8], 8), value[8]
        require(amount <= MONEY and not flag & ~3)
        spent = bool(flag & 1)
        require(len(value) == (81 if spent else 9))
        if unmined or must_unspent:
            require(not spent and len(value) == 9)
        if must_spent:
            require(spent and len(value) == 81)
        return amount, bool(flag & 2)

    def record(self, tx_hash, block, remaining_raw):
        if block is None:
            prefix, bucket = tx_hash, "m"
        else:
            prefix = tx_hash + be32(block["height"]) + bytes.fromhex(block["hash"])[::-1]
            bucket = "t"
        value = self.get(bucket, prefix)
        require(value is not None and len(value) >= 8)
        # Charge the borrowed value's length before slicing/copying or parsing
        # its transaction. This fixes capacity-versus-corrupt precedence too.
        require(integer(remaining_raw, 0, 8388608))
        require(len(value)-8 <= min(262144, remaining_raw), "capacity")
        recorded = time_ms(value[:8])
        raw = value[8:]
        tx = parse_transaction(raw)
        self.raw_parsed += 1
        require(tx["txid"] == display(tx_hash))
        credits = []
        credit_bucket = "mc" if block is None else "c"
        expected_key_size = 36 if block is None else 72
        for key, row in self.indexed(credit_bucket, prefix, len(tx["outputs"])):
            require(len(key) == expected_key_size)
            index = number(key[-4:], 4)
            require(index < len(tx["outputs"]))
            amount, change = self.credit(row, unmined=block is None)
            require(amount == tx["outputs"][index]["atoms"])
            credits.append({"index": index, "atoms": amount, "change": change})
        debits = []
        if block is not None:
            for key, row in self.indexed("d", prefix, len(tx["inputs"])):
                require(len(key) == 72 and len(row) == 80)
                index = number(key[-4:], 4)
                require(index < len(tx["inputs"]))
                amount, previous_key = number(row[:8], 8), row[8:]
                previous = tx["inputs"][index]
                require(previous_key[:32] == previous["previous_hash"])
                require(number(previous_key[-4:], 4) == previous["previous_index"])
                previous_value = self.get("c", previous_key)
                actual, _ = self.credit(previous_value, must_spent=True)
                require(actual == amount and previous_value[9:] == key)
                debits.append({"index": index, "atoms": amount})
        else:
            for index, previous in enumerate(tx["inputs"]):
                key = previous["previous_hash"] + be32(previous["previous_index"])
                unspent = self.get("u", key)
                if unspent is not None:
                    require(len(unspent) == 36)
                    previous_key = previous["previous_hash"] + unspent + be32(previous["previous_index"])
                    value = self.get("c", previous_key)
                    amount, _ = self.credit(value, must_unspent=True)
                else:
                    value = self.get("mc", key)
                    if value is None:
                        continue
                    amount, _ = self.credit(value, unmined=True)
                debits.append({"index": index, "atoms": amount})
        return {"txid": display(tx_hash), "raw_hex": raw.hex(),
                "recorded_at_ms": recorded, "block": block,
                "credits": credits, "debits": debits}


def capture(encoded, height):
    store = Store(encoded)
    chosen, older = store.select(height)
    records, projected, raw_total = [], [], 0
    for tx_hash, block in chosen:
        record = store.record(tx_hash, block, 8388608-raw_total)
        raw_total += len(record["raw_hex"]) // 2
        require(raw_total <= 8388608, "capacity")
        projected.append(project_record(record, height)["item"])
        records.append(record)
    encoded_summaries = json.dumps(projected, separators=(",", ":"), allow_nan=False).encode()
    require(len(encoded_summaries) <= 524288, "capacity")
    require(store.mi_reads == 0)
    return {"has_older": older, "records": records, "items": projected,
            "metadata_visits": store.metadata_visits, "selected_raw_parsed": store.raw_parsed,
            "gets": store.gets, "index_positions": store.index_positions,
            "unmined_spender_map_reads": store.mi_reads}
