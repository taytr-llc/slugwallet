#!/usr/bin/env python3
"""Independent public TEST-ONLY SLUG gym authorization v1 fixtures.

The two private scalars are the deliberately public integers 1 and 2. They
are reproducible test inputs, NEVER real wallet or operator signing keys.
This script reads no private files and contacts no network or node.

Python's standard library implements secp256k1 point arithmetic, RFC6979
HMAC-SHA256 nonces, ECDSA and strict low-S DER. Protocol bytes and expected
DNA reuse only the independent Python references from sets 13 and 14. The
standalone production Argon2id oracle imports no project package. No output
from the Go gym authorization, proof verifier or DNA generator is consulted.

No arguments (or --check) verifies authorizations_v1.json. --generate prints
the reproducible array. These synthetic all-ones-target proofs are neither
accepted pool shares nor approved production target calibration.
"""

import argparse
import hashlib
import hmac
import json
from pathlib import Path
import runpy


FIELD = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GENERATOR = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
GYM_DOMAIN = b"SLUG gym identity\x00v1\x00"
AUTH_DOMAIN = b"SLUG prospect admission\x00v1\x00"


def sha256(value):
    return hashlib.sha256(value).digest()


def le32(value):
    return value.to_bytes(4, "little")


def add(left, right):
    """Affine secp256k1 group addition; None denotes the point at infinity."""
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % FIELD == 0:
        return None
    if left == right:
        slope = (3 * x1 * x1) * pow(2 * y1, -1, FIELD) % FIELD
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, FIELD) % FIELD
    x3 = (slope * slope - x1 - x2) % FIELD
    return x3, (slope * (x1 - x3) - y1) % FIELD


def multiply(scalar, point=GENERATOR):
    if scalar < 0:
        raise ValueError("negative scalar")
    result = None
    while scalar:
        if scalar & 1:
            result = add(result, point)
        point = add(point, point)
        scalar >>= 1
    return result


def public_key(private_scalar):
    if not 1 <= private_scalar < ORDER:
        raise ValueError("private scalar out of range")
    x, y = multiply(private_scalar)
    return bytes((2 | (y & 1),)) + x.to_bytes(32, "big")


def rfc6979_nonces(private_scalar, digest):
    """RFC6979 section 3.2, qlen=256, SHA-256 and bits2octets reduction."""
    if len(digest) != 32:
        raise ValueError("digest must contain 32 bytes")
    seed = private_scalar.to_bytes(32, "big") + (int.from_bytes(digest, "big") % ORDER).to_bytes(32, "big")
    key, value = bytes(32), b"\x01" * 32
    key = hmac.new(key, value + b"\x00" + seed, hashlib.sha256).digest()
    value = hmac.new(key, value, hashlib.sha256).digest()
    key = hmac.new(key, value + b"\x01" + seed, hashlib.sha256).digest()
    value = hmac.new(key, value, hashlib.sha256).digest()
    while True:
        value = hmac.new(key, value, hashlib.sha256).digest()
        candidate = int.from_bytes(value, "big")
        if 1 <= candidate < ORDER:
            yield candidate
        key = hmac.new(key, value + b"\x00", hashlib.sha256).digest()
        value = hmac.new(key, value, hashlib.sha256).digest()


def sign(private_scalar, digest):
    z = int.from_bytes(digest, "big")
    for nonce in rfc6979_nonces(private_scalar, digest):
        r = multiply(nonce)[0] % ORDER
        if not r:
            continue
        s = pow(nonce, -1, ORDER) * (z + r * private_scalar) % ORDER
        if not s:
            continue
        return r, min(s, ORDER - s)
    raise AssertionError("unreachable exhausted nonce sequence")


def verify(point, digest, r, s):
    if not 1 <= r < ORDER or not 1 <= s < ORDER:
        return False
    inverse = pow(s, -1, ORDER)
    candidate = add(multiply(int.from_bytes(digest, "big") * inverse % ORDER), multiply(r * inverse % ORDER, point))
    return candidate is not None and candidate[0] % ORDER == r


def der_signature(r, s):
    def integer(value):
        if value <= 0:
            raise ValueError("DER signature scalar must be positive")
        encoded = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if encoded[0] & 0x80:
            encoded = b"\x00" + encoded
        return b"\x02" + bytes((len(encoded),)) + encoded

    body = integer(r) + integer(s)
    return b"\x30" + bytes((len(body),)) + body


def gym_id(context, compressed_public_key):
    return sha256(GYM_DOMAIN + le32(context["network"]) + bytes.fromhex(context["genesis"]) + compressed_public_key).hex()


def admission_digest(context, proof, compressed_public_key, policy_id):
    header = bytes.fromhex(proof["header"])
    coinbase = bytes.fromhex(proof["coinbase"])
    return sha256(
        AUTH_DOMAIN
        + policy_id
        + bytes.fromhex(gym_id(context, compressed_public_key))
        + compressed_public_key
        + le32(proof["version"])
        + header
        + le32(len(coinbase))
        + coinbase
        + le32(len(proof["merkle_branch"]))
        + b"".join(bytes.fromhex(sibling) for sibling in proof["merkle_branch"])
    )


def self_check():
    if multiply(ORDER) is not None or multiply(ORDER + 1) != GENERATOR:
        raise AssertionError("secp256k1 order check failed")
    if public_key(1).hex() != "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798":
        raise AssertionError("public fixture key 1 differs from the generator")
    if public_key(2).hex() != "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5":
        raise AssertionError("public fixture key 2 differs from the doubled generator")
    digest = sha256(b"SLUG public deterministic authorization test")
    r, s = sign(1, digest)
    if s > ORDER // 2 or not verify(GENERATOR, digest, r, s):
        raise AssertionError("independent ECDSA signature verification failed")
    if verify(GENERATOR, sha256(digest), r, s):
        raise AssertionError("a changed digest retained a valid signature")
    if not verify(GENERATOR, digest, r, ORDER - s):
        raise AssertionError("high-S mathematical twin was not valid ECDSA")


def golden_records():
    repo = Path(__file__).resolve().parents[2]
    reference = runpy.run_path(str(repo / "prospect/testdata/reference_proofs.py"))
    dna = runpy.run_path(str(repo / "fighter/testdata/reference_dna.py"))
    dna["self_check"]()
    context = dict(reference["CONTEXT"])
    branches = (
        ("public-test-key-1-coinbase-only", 1, []),
        ("public-test-key-2-two-level", 2, [
            reference["sha256d"](b"SLUG gym authorization synthetic sibling 1"),
            reference["sha256d"](b"SLUG gym authorization synthetic sibling subtree 2"),
        ]),
    )
    proofs = [reference["make_proof"](context, gym_id(context, public_key(scalar)), siblings) for _, scalar, siblings in branches]
    work_hashes = reference["direct_argon_hashes"]([proof["header"] for proof in proofs])
    policy = reference["policy_id"](context)
    records = []
    for (name, scalar, _), proof, work_hash in zip(branches, proofs, work_hashes):
        pub = public_key(scalar)
        gym = gym_id(context, pub)
        digest = admission_digest(context, proof, pub, policy)
        r, s = sign(scalar, digest)
        if not verify(multiply(scalar), digest, r, s):
            raise AssertionError("fixture signature failed independent verification")
        if not 1 < int(work_hash, 16) <= int(context["prospect_target"], 16):
            raise AssertionError("fixture must pass prospect target and miss block target 1")
        records.append({
            "name": name,
            "test_only_private_key": scalar.to_bytes(32, "big").hex(),
            "context": dict(context),
            "proof": proof,
            "authorization": {"version": 1, "public_key": pub.hex(), "signature": der_signature(r, s).hex()},
            "expected_gym_id": gym,
            "expected_digest": digest.hex(),
            "invalid_high_s_signature": der_signature(r, ORDER - s).hex(),
            "commitment_script": reference["commitment_script"](context, gym).hex(),
            "expected_verified": {
                "version": 1,
                "verification": "supplied-context",
                "network": context["network"],
                "genesis": context["genesis"],
                "prospect_id": sha256(reference["ID_DOMAIN"] + le32(context["network"]) + bytes.fromhex(context["genesis"]) + bytes.fromhex(work_hash)).hex(),
                "policy_id": policy.hex(),
                "gym_id": gym,
                "work_hash": work_hash,
                "parent_hash": context["parent_hash"],
                "parent_height": context["parent_height"],
                "dna": dna["derive_dna"](work_hash),
            },
        })
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--check", action="store_true", help="regenerate and check adjacent fixtures (default)")
    actions.add_argument("--generate", action="store_true", help="print independently generated fixture array")
    args = parser.parse_args()
    self_check()
    records = golden_records()
    if args.generate:
        print(json.dumps(records, indent=2))
        return
    with Path(__file__).with_name("authorizations_v1.json").open(encoding="utf-8") as handle:
        if records != json.load(handle):
            raise SystemExit("authorizations_v1.json differs from the independent reference")
    print(f"verified {len(records)} independent gym authorizations with production Argon2id")


if __name__ == "__main__":
    main()
