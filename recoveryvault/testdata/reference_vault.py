#!/usr/bin/env python3
"""Independent, public-fixture-only AES256-GCM and vault binding oracle.

AES key expansion, block encryption, CTR, and GHASH use Python integer/byte
arithmetic, not Go or a cryptography library. NIST's published AES_GCM.pdf
examples 1-5 validate empty, full, and partial AAD/plaintext cases first.
Published wallet fixtures are rederived with the pre-existing independent
BIP39/BIP32 Python reference. No network, private inputs, or real keys are used.
This variable-time educational implementation must never protect real secrets.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "recovery/testdata/oracle"))
import reference as wallet_reference


NIST_SOURCE = "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_GCM.pdf"
CONTENT_DOMAIN = b"SLUG recovery vault content\x00v1\x00"
WRAP_DOMAIN = b"SLUG recovery vault wrap\x00v1\x00"
WRAPPER_ID = "public-fixture-wrapper-v1"
KEYS = {
    "fixture-recovery-v1": bytes(range(0, 32)),
    "fixture-recovery-v2": bytes(range(32, 64)),
    "fixture-gym-v1": bytes(range(64, 96)),
    "fixture-gym-v2": bytes(range(96, 128)),
}


def gf8(a, b):
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        a = ((a << 1) ^ (0x11b if a & 0x80 else 0)) & 0xff
        b >>= 1
    return result


def power8(a, n):
    result = 1
    while n:
        if n & 1:
            result = gf8(result, a)
        a = gf8(a, a)
        n >>= 1
    return result


def rotate8(a, n):
    return ((a << n) | (a >> (8-n))) & 0xff


def substitution(a):
    inverse = power8(a, 254) if a else 0
    return inverse ^ rotate8(inverse, 1) ^ rotate8(inverse, 2) ^ rotate8(inverse, 3) ^ rotate8(inverse, 4) ^ 0x63


SBOX = tuple(substitution(a) for a in range(256))


def aes256_schedule(key):
    assert len(key) == 32
    words = [list(key[i:i+4]) for i in range(0, 32, 4)]
    rcon = 1
    for i in range(8, 60):
        tmp = list(words[i-1])
        if i % 8 == 0:
            tmp = [SBOX[b] for b in tmp[1:] + tmp[:1]]
            tmp[0] ^= rcon
            rcon = gf8(rcon, 2)
        elif i % 8 == 4:
            tmp = [SBOX[b] for b in tmp]
        words.append([a ^ b for a, b in zip(words[i-8], tmp)])
    return [b for word in words for b in word]


def aes256_block(schedule, block):
    assert len(block) == 16
    state = [a ^ b for a, b in zip(block, schedule[:16])]
    for round_number in range(1, 15):
        old = [SBOX[b] for b in state]
        state = [old[4*((c+r) % 4)+r] for c in range(4) for r in range(4)]
        if round_number != 14:
            for c in range(4):
                a, b, d, e = state[4*c:4*c+4]
                state[4*c:4*c+4] = [
                    gf8(a, 2) ^ gf8(b, 3) ^ d ^ e,
                    a ^ gf8(b, 2) ^ gf8(d, 3) ^ e,
                    a ^ b ^ gf8(d, 2) ^ gf8(e, 3),
                    gf8(a, 3) ^ b ^ d ^ gf8(e, 2),
                ]
        state = [a ^ b for a, b in zip(state, schedule[16*round_number:16*(round_number+1)])]
    return bytes(state)


def multiply128(x, y):
    z = 0
    for bit in range(127, -1, -1):
        if (x >> bit) & 1:
            z ^= y
        y = (y >> 1) ^ (0xe1000000000000000000000000000000 if y & 1 else 0)
    return z


def pad16(data):
    return data + bytes((-len(data)) % 16)


def ghash(h, aad, ciphertext):
    data = pad16(aad) + pad16(ciphertext)
    data += (8*len(aad)).to_bytes(8, "big") + (8*len(ciphertext)).to_bytes(8, "big")
    value = 0
    for offset in range(0, len(data), 16):
        value = multiply128(value ^ int.from_bytes(data[offset:offset+16], "big"), h)
    return value.to_bytes(16, "big")


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def gcm(key, nonce, plaintext, aad):
    assert len(key) == 32 and len(nonce) == 12
    schedule = aes256_schedule(key)
    h = int.from_bytes(aes256_block(schedule, bytes(16)), "big")
    j0 = nonce + b"\x00\x00\x00\x01"
    ciphertext = b""
    for offset in range(0, len(plaintext), 16):
        counter = nonce + (2+offset//16).to_bytes(4, "big")
        ciphertext += xor(plaintext[offset:offset+16], aes256_block(schedule, counter))
    tag = xor(aes256_block(schedule, j0), ghash(h, aad, ciphertext))
    return ciphertext + tag


def nist_vectors():
    key = "feffe9928665731c6d6a8f9467308308" * 2
    nonce = "cafebabefacedbaddecaf888"
    p = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"
    a = "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4"
    c = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad"
    values = [
        (1, "", "", "", "fd2caa16a5832e76aa132c1453eeda7e"),
        (2, p, "", c, "b094dac5d93471bdec1a502270e3cc6c"),
        (3, "", a, "", "de34b6dcd4cee2fdbec3cea01af1ee44"),
        (4, p, a, c, "c06d76f31930fef37acae23ed465ae62"),
        (5, p[:-8], a[:40], c[:-8], "e097195f4532da895fb917a5a55c6aa0"),
    ]
    records = []
    for number, pt, aad, ct, tag in values:
        actual = gcm(bytes.fromhex(key), bytes.fromhex(nonce), bytes.fromhex(pt), bytes.fromhex(aad))
        assert actual.hex() == ct+tag, f"NIST GCM-AES256 Example#{number} mismatch"
        records.append({"name": f"nist-aes256-example-{number}", "key": key,
                        "nonce": nonce, "plaintext": pt, "aad": aad,
                        "ciphertext": ct, "tag": tag})
    return records


def sha256(raw):
    return hashlib.sha256(raw).digest()


def le32(n):
    return n.to_bytes(4, "little")


def le64(n):
    return n.to_bytes(8, "little")


def framed(text):
    raw = text.encode("ascii")
    return le32(len(raw)) + raw


def content_aad(binding, purpose, revision, manifest_hash):
    value = CONTENT_DOMAIN + le32(binding["version"])
    for field in ("authority_id", "account_id", "principal_id", "provision_id"):
        value += bytes.fromhex(binding[field])
    value += le32(binding["network"]) + bytes.fromhex(binding["genesis"])
    value += framed(binding["profile"]) + framed(binding["root_public_key"])
    value += bytes.fromhex(binding["gym_public_key"]) + bytes.fromhex(binding["gym_id"])
    return value + framed(purpose) + le64(revision) + bytes.fromhex(manifest_hash)


def wrapping_aad(envelope):
    content = content_aad(envelope["binding"], envelope["purpose"],
                          envelope["content_revision"], envelope["manifest_hash"])
    ciphertext = bytes.fromhex(envelope["nonce"] + envelope["ciphertext"])
    return (WRAP_DOMAIN + sha256(content) + sha256(ciphertext) +
            le64(envelope["wrap_revision"]) + framed(envelope["wrapper_id"]) +
            framed(envelope["key_ref"]))


def canonical_manifest(m):
    # Fixed v1 field order; independent encoding, no Go marshaling is invoked.
    ordered = {field: m[field] for field in (
        "version", "profile", "network", "genesis", "derivation", "scan_from_height",
        "root_public_key", "gym_path", "gym_public_key", "gym_id")}
    ordered["accounts"] = [{field: a[field] for field in (
        "purpose", "coin", "account", "external_type", "internal_type",
        "next_external", "next_internal")} for a in m["accounts"]]
    return json.dumps(ordered, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def generate():
    nist = nist_vectors()
    wallet_reference.verify_official_vectors()
    wallet_file = json.loads((ROOT / "recovery/testdata/recovery_v1.json").read_text())
    assert wallet_file["fixture_only"]
    cases = []
    for number, fixture in enumerate(wallet_file["cases"][:2]):
        assert fixture["name"] in ("zero256", "incrementing256")
        entropy = bytes.fromhex(fixture["entropy"])
        phrase = wallet_reference.mnemonic_from_entropy(entropy)
        assert phrase == fixture["export"]["mnemonic"]
        seed = wallet_reference.mnemonic_to_seed(phrase, "")
        manifest = fixture["export"]["manifest"]
        gym = wallet_reference.derive_path(seed, manifest["gym_path"])
        assert wallet_reference.public_key(gym.scalar).hex() == manifest["gym_public_key"]
        assert wallet_reference.ExtendedPrivate.master(seed).serialize(True, True) == manifest["root_public_key"]
        manifest_json = canonical_manifest(manifest)
        manifest_hash = sha256(manifest_json).hex()
        binding = {
            "version": 1, "authority_id": "10"*32,
            "account_id": bytes([0x20+number]).hex()*32,
            "principal_id": bytes([0x30+number]).hex()*32,
            "provision_id": bytes([0x40+number]).hex()*32,
            "network": manifest["network"], "genesis": manifest["genesis"],
            "profile": manifest["profile"], "root_public_key": manifest["root_public_key"],
            "gym_public_key": manifest["gym_public_key"], "gym_id": manifest["gym_id"],
        }
        for purpose in ("recovery", "gym-signing"):
            name = fixture["name"] + "-" + purpose
            label = ("public SLUG vault fixture " + name).encode("ascii")
            dek = sha256(label+b" DEK")
            nonce = sha256(label+b" content nonce")[:12]
            wrap_nonce = sha256(label+b" wrapping nonce v1")[:12]
            rewrap_nonce = sha256(label+b" wrapping nonce v2")[:12]
            role = "recovery" if purpose == "recovery" else "gym"
            keyref, nextref = f"fixture-{role}-v1", f"fixture-{role}-v2"
            plaintext = le32(1) + (entropy + le32(len(manifest_json)) + manifest_json
                                  if purpose == "recovery" else gym.scalar.to_bytes(32, "big"))
            aad = content_aad(binding, purpose, 1, manifest_hash)
            ciphertext = gcm(dek, nonce, plaintext, aad)
            envelope = {
                "version": 1, "binding": binding, "purpose": purpose,
                "content_revision": 1, "manifest_hash": manifest_hash,
                "nonce": nonce.hex(), "ciphertext": ciphertext.hex(),
                "wrapper_id": WRAPPER_ID, "key_ref": keyref,
                "wrap_revision": 1,
            }
            wrap_aad = wrapping_aad(envelope)
            envelope["wrapped_key"] = (wrap_nonce+gcm(KEYS[keyref], wrap_nonce, dek, wrap_aad)).hex()
            rotated = dict(envelope, key_ref=nextref, wrap_revision=2)
            next_aad = wrapping_aad(rotated)
            rotated["wrapped_key"] = (rewrap_nonce+gcm(KEYS[nextref], rewrap_nonce, dek, next_aad)).hex()
            cases.append({
                "name": name, "fixture_name": fixture["name"], "manifest": manifest,
                "canonical_manifest": manifest_json.decode("ascii"),
                "test_only_dek": dek.hex(), "test_only_wrap_nonce": wrap_nonce.hex(),
                "test_only_rewrap_nonce": rewrap_nonce.hex(),
                "expected_plaintext": plaintext.hex(), "expected_content_aad": aad.hex(),
                "expected_wrapping_aad": wrap_aad.hex(), "envelope": envelope,
                "expected_rewrapping_aad": next_aad.hex(), "rewrapped_envelope": rotated,
            })
    return {"fixture_only": True, "version": 1, "nist_source": NIST_SOURCE,
            "nist_vectors": nist, "public_test_keks": {k: v.hex() for k, v in KEYS.items()},
            "cases": cases}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--generate", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    encoded = json.dumps(generate(), indent=2) + "\n"
    if args.generate:
        print(encoded, end="")
    else:
        assert Path(__file__).with_name("vault_v1.json").read_text() == encoded, "vault vectors differ"
        print("Five NIST AES256-GCM examples and four independent vault envelopes match.")


if __name__ == "__main__":
    main()
