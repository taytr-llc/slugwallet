#!/usr/bin/env python3
"""Independently re-encode published upstream wallet fixtures for SLUG.

Inputs are canonical encodings from btcwallet v0.18.1
43f2950d2a065a7b3d4a4a1cf17ed1e84af6bcb4. Only network version/HRP and
checksum change; key, chain-code, witness-version and script payloads do not.
No SLUG/Go package is imported, executed, or used as an expected-value oracle.
All private encodings here are already-public upstream deterministic fixtures.
"""
import argparse
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def checksum(payload):
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]


def encode_base58(payload):
    value = int.from_bytes(payload, "big")
    digits = ""
    while value:
        value, remainder = divmod(value, 58)
        digits = BASE58[remainder] + digits
    return "1" * (len(payload) - len(payload.lstrip(b"\0"))) + digits


def decode_base58(encoded):
    value = 0
    for char in encoded:
        value = value * 58 + BASE58.index(char)
    decoded = b"\0" * (len(encoded) - len(encoded.lstrip("1")))
    decoded += value.to_bytes((value.bit_length() + 7) // 8, "big")
    if len(decoded) < 5 or checksum(decoded[:-4]) != decoded[-4:]:
        raise ValueError("invalid Base58Check checksum")
    if encode_base58(decoded) != encoded:
        raise ValueError("noncanonical Base58Check")
    return decoded[:-4]


def polymod(values):
    generators = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    value = 1
    for digit in values:
        high = value >> 25
        value = ((value & 0x1FFFFFF) << 5) ^ digit
        for bit, generator in enumerate(generators):
            if (high >> bit) & 1:
                value ^= generator
    return value


def expand_hrp(hrp):
    return [ord(char) >> 5 for char in hrp] + [0] + [ord(char) & 31 for char in hrp]


def decode_witness(encoded):
    if encoded != encoded.lower() or len(encoded) > 90:
        raise ValueError("noncanonical witness encoding")
    split = encoded.rfind("1")
    hrp, digits = encoded[:split], encoded[split + 1:]
    if split <= 0 or len(digits) < 7:
        raise ValueError("invalid witness encoding")
    values = [BECH32.index(char) for char in digits]
    data = values[:-6]
    if not 0 <= data[0] <= 16:
        raise ValueError("invalid witness version")
    constant = 1 if data[0] == 0 else 0x2BC830A3
    if polymod(expand_hrp(hrp) + values) != constant:
        raise ValueError("invalid witness checksum variant")
    # Verify canonical zero padding and consensus witness program lengths.
    bits, accumulator, program = 0, 0, bytearray()
    for digit in data[1:]:
        accumulator = (accumulator << 5) | digit
        bits += 5
        while bits >= 8:
            bits -= 8
            program.append((accumulator >> bits) & 255)
    if bits >= 5 or (accumulator & ((1 << bits) - 1)):
        raise ValueError("noncanonical witness padding")
    if not 2 <= len(program) <= 40 or (data[0] == 0 and len(program) not in (20, 32)):
        raise ValueError("invalid witness program length")
    return hrp, data, bytes(program)


def encode_witness(hrp, data):
    constant = 1 if data[0] == 0 else 0x2BC830A3
    value = polymod(expand_hrp(hrp) + data + [0] * 6) ^ constant
    tail = [(value >> (5 * (5 - index))) & 31 for index in range(6)]
    return hrp + "1" + "".join(BECH32[digit] for digit in data + tail)


def reencode(encoded, include_testnet=False):
    if encoded.startswith(("bc1", "tb1")):
        hrp, data, program = decode_witness(encoded)
        if hrp != "bc" and not (include_testnet and hrp == "tb"):
            raise ValueError("fixture is not an allowed source network")
        result = encode_witness("slug", data)
        target_hrp, target_data, target_program = decode_witness(result)
        assert target_hrp == "slug" and target_data == data and target_program == program
        return "witness", program.hex(), result
    payload = decode_base58(encoded)
    versions = {0x00: 0x53, 0x05: 0x47, 0x80: 0xD3}
    if include_testnet:
        versions.update({0x6F: 0x53, 0xC4: 0x47, 0xEF: 0xD3})
    hd_public = {0x0488B21E, 0x049D7CB2, 0x04B24746}
    hd_private = {0x0488ADE4, 0x049D7878, 0x04B2430C}
    if include_testnet:
        hd_public |= {0x043587CF, 0x044A5262, 0x045F1CF6}
        hd_private |= {0x04358394, 0x044A4E28, 0x045F18BC}
    if len(payload) == 78:
        version = int.from_bytes(payload[:4], "big")
        if version in hd_public:
            kind, prefix = "hd_public", bytes.fromhex("534c5547")
        elif version in hd_private:
            kind, prefix = "hd_private", bytes.fromhex("736c7567")
        else:
            raise ValueError("unsupported HD source version")
        unchanged = payload[4:]
    elif len(payload) in (21, 33, 34) and payload[0] in versions:
        kind, prefix, unchanged = "base58", bytes([versions[payload[0]]]), payload[1:]
        if len(payload) == 34 and payload[-1] != 1:
            raise ValueError("invalid compressed WIF suffix")
    else:
        raise ValueError("unsupported fixture payload")
    replaced = prefix + unchanged
    result = encode_base58(replaced + checksum(replaced))
    assert decode_base58(result) == replaced
    return kind, unchanged.hex(), result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="check committed vectors without editing")
    parser.add_argument("--update-tests", action="store_true", help="replace exact upstream fixture literals")
    args = parser.parse_args()
    inputs = json.loads((HERE / "bitcoin_encoding_inputs.json").read_text())
    results = []
    for entry in inputs:
        kind, payload, encoded = reencode(entry["bitcoin"], entry.get("testnet", False))
        results.append({**entry, "kind": kind, "payload": payload, "slug": encoded})
    output = json.dumps(results, indent=2) + "\n"
    destination = HERE / "slug_encoding_vectors.json"
    if args.check:
        if destination.read_text() != output:
            raise SystemExit("independent encoding vectors differ")
        print(f"Checked {len(results)} independent network re-encodings.")
    else:
        destination.write_text(output)
    if args.update_tests:
        # Only explicitly named test files are eligible; imports and runtime
        # package source are never read as an oracle or changed here.
        root = HERE.parents[1]
        for path in {row["file"] for row in results if not row.get("testnet")}:
            if path not in ("waddrmgr/common_test.go", "waddrmgr/manager_test.go", "wallet/createtx_test.go"):
                raise ValueError("unexpected fixture target")
            target = root / path
            text = target.read_text()
            import re
            expression = re.compile(r'"[^"\\\n]*"(?:\s*\+\s*"[^"\\\n]*")*')
            replacements = {row["bitcoin"]: row["slug"] for row in results if row["file"] == path}
            def replace(match):
                joined = "".join(re.findall(r'"([^"\\\n]*)"', match.group()))
                return json.dumps(replacements[joined]) if joined in replacements else match.group()
            target.write_text(expression.sub(replace, text))


if __name__ == "__main__":
    main()
