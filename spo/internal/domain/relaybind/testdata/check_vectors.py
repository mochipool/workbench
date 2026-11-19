#!/usr/bin/env python3
"""Independent check of vectors.json (ADR 0014 work package 1), with a
hand-written CBOR encoder and the standard library only. SOFTWARE test-key
vectors, provisional until the real-device check.

For every statement it rebuilds, from the fields, the payload text, the
protected header, the CIP-8 Sig_structure, the COSE_Sign1 and its canonical
hash (BLAKE2b-256), the COSE_Key and the key hash (BLAKE2b-224 of the public
key), and compares them with the file. The Ed25519 signatures are verified with
a hand-written implementation of RFC 8032 (section 6) using hashlib.sha512, so
no library is needed. For every device revoke it rebuilds the fingerprint and
the signed array. The near-miss payloads must not match the canonical grammar."""
import hashlib
import json
import os
import re
import sys

# --- CBOR (definite lengths, shortest heads, keys in the order given) -------


def head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    for info, w in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * w):
            return bytes([major << 5 | info]) + n.to_bytes(w, "big")
    raise ValueError(n)


def uint(n):
    return head(0, n)


def nint(n):  # n < 0
    return head(1, -1 - n)


def bstr(b):
    return head(2, len(b)) + b


def tstr(s):
    b = s.encode()
    return head(3, len(b)) + b


def array(items):
    return head(4, len(items)) + b"".join(items)


def cmap(pairs):
    return head(5, len(pairs)) + b"".join(k + v for k, v in pairs)


# --- RFC 8032 section 6, Ed25519 verification only --------------------------
p = 2**255 - 19
q = 2**252 + 27742317777372353535851937790883648493
d = -121665 * pow(121666, p - 2, p) % p
sqrt_m1 = pow(2, (p - 1) // 4, p)


def point_add(P, Q):
    A, B = (P[1] - P[0]) * (Q[1] - Q[0]) % p, (P[1] + P[0]) * (Q[1] + Q[0]) % p
    C, D = 2 * P[3] * Q[3] * d % p, 2 * P[2] * Q[2] % p
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % p, G * H % p, F * G % p, E * H % p)


def point_mul(s, P):
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            Q = point_add(Q, P)
        P = point_add(P, P)
        s >>= 1
    return Q


def point_equal(P, Q):
    if (P[0] * Q[2] - Q[0] * P[2]) % p != 0:
        return False
    return (P[1] * Q[2] - Q[1] * P[2]) % p == 0


def recover_x(y, sign):
    if y >= p:
        return None
    x2 = (y * y - 1) * pow(d * y * y + 1, p - 2, p) % p
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (p + 3) // 8, p)
    if (x * x - x2) % p != 0:
        x = x * sqrt_m1 % p
    if (x * x - x2) % p != 0:
        return None
    if (x & 1) != sign:
        x = p - x
    return x


def point_decompress(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % p)


g_y = 4 * pow(5, p - 2, p) % p
g_x = recover_x(g_y, 0)
G = (g_x, g_y, 1, g_x * g_y % p)


def ed25519_verify(public, msg, sig):
    if len(public) != 32 or len(sig) != 64:
        return False
    A = point_decompress(public)
    R = point_decompress(sig[:32])
    if A is None or R is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= q:
        return False
    h = int.from_bytes(hashlib.sha512(sig[:32] + public + msg).digest(), "little") % q
    return point_equal(point_mul(s, G), point_add(R, point_mul(h, A)))


def b2(data, n):
    return hashlib.blake2b(data, digest_size=n).digest()


BINDING = re.compile(r"^spo-relay-binding-v1 device [0-9a-f]{40} from (0|[1-9][0-9]{0,11}) until (0|[1-9][0-9]{0,11})$")
REVOKE = re.compile(r"^spo-relay-revoke-v1 device ([0-9a-f]{40}|all) not-before (0|[1-9][0-9]{0,11})$")

here = os.path.dirname(os.path.abspath(__file__))
vf = json.load(open(os.path.join(here, "vectors.json")))
bad = 0


def fail(*a):
    global bad
    print(*a)
    bad += 1


public = bytes.fromhex(vf["software_key_public"])
key_hash = b2(public, 28)
if key_hash.hex() != vf["software_key_hash"]:
    fail("key hash")

cose_key = cmap([(uint(1), uint(1)), (uint(3), nint(-8)), (nint(-1), uint(6)), (nint(-2), bstr(public))])


def refused_key_reason(enc):
    """Why a verification key must be refused, from point arithmetic alone:
    'non-canonical' (y >= p, or the sign bit set on x = 0) or 'small-order'
    (the point times the cofactor 8 is the identity). None if neither."""
    if len(enc) != 32:
        return "bad length"
    y = int.from_bytes(enc, "little") & ((1 << 255) - 1)
    if y >= p:
        return "non-canonical"
    point = point_decompress(enc)
    if point is None:
        return "non-canonical"
    if point_equal(point_mul(8, point), (0, 1, 1, 0)):
        return "small-order"
    return None


sigs = 0
for v in vf["statements"]:
    name = v["name"]
    if v["kind"] == "binding":
        text = "spo-relay-binding-v1 device %s from %d until %d" % (v["device"], v["from"], v["until"])
        if not BINDING.fullmatch(text) or not (3600 <= v["until"] - v["from"] <= 180 * 86400) or v["until"] > 253402300799:
            fail("binding grammar", name)
    else:
        text = "spo-relay-revoke-v1 device %s not-before %d" % ("all" if v.get("all") else v["device"], v["not_before"])
        if not REVOKE.fullmatch(text):
            fail("revoke grammar", name)
    if len(text) > 120:
        fail("payload too long", name)
    payload = text.encode("ascii")
    if v["payload"] != text or v["payload_hex"] != payload.hex():
        fail("payload", name)
    address = bytes.fromhex(v["address_hex"])
    if v["address_form"] == "key-hash":
        if address != key_hash:
            fail("address is not the key hash", name)
    else:  # a Shelley base address, key-hash payment credential (types 0 and 2), network 0 or 1
        if len(address) != 57 or address[1:29] != key_hash or address[0] >> 4 not in (0, 2) or address[0] & 15 > 1:
            fail("base address", name)
    protected = cmap([(uint(1), nint(-8)), (tstr("address"), bstr(address))])
    if protected.hex() != v["protected_hex"]:
        fail("protected", name)
    # CIP-8 Sig_structure: ["Signature1", protected, h'', payload]
    sig_structure = array([tstr("Signature1"), bstr(protected), bstr(b""), bstr(payload)])
    if sig_structure.hex() != v["sig_structure_hex"]:
        fail("sig_structure", name)
    signature = bytes.fromhex(v["signature_hex"])
    if ed25519_verify(public, sig_structure, signature):
        sigs += 1
    else:
        fail("signature does not verify", name)
    sign1 = array([bstr(protected), cmap([(tstr("hashed"), b"\xf4")]), bstr(payload), bstr(signature)])
    if sign1.hex() != v["sign1_hex"]:
        fail("sign1", name)
    # The full hash includes the signature (the value the auth bytes commit to).
    if b2(sign1, 32).hex() != v["canonical_hash_hex"]:
        fail("canonical hash", name)
    # The statement identity leaves the signature out: [label, K, payload].
    statement_id = b2(array([tstr("spo/relay-statement-id/v1"), bstr(key_hash), bstr(payload)]), 32)
    if statement_id.hex() != v["statement_id_hex"] or statement_id.hex() == v["canonical_hash_hex"]:
        fail("statement id", name)
    if cose_key.hex() != v["cose_key_hex"]:
        fail("cose key", name)

for v in vf["device_revokes"]:
    ed, x = bytes.fromhex(v["ed25519_public"]), bytes.fromhex(v["x25519_public"])
    fingerprint = b2(b"spo/party/v1" + ed + x, 32)[:20]
    if fingerprint.hex() != v["fingerprint"]:
        fail("fingerprint", v["name"])
    msg = array([tstr("spo/relay-revoke-device/v1"), bstr(fingerprint), uint(v["not_before"])])
    if msg.hex() != v["bytes_hex"]:
        fail("device revoke bytes", v["name"])
    if ed25519_verify(ed, msg, bytes.fromhex(v["signature_hex"])):
        sigs += 1
    else:
        fail("device revoke signature", v["name"])

for s in vf["near_miss_payloads"]:
    if BINDING.fullmatch(s) or REVOKE.fullmatch(s):
        fail("near miss matches the grammar", repr(s))

if refused_key_reason(public) is not None:
    fail("the software test key itself would be refused")
refused = 0
for k in vf["rejected_public_keys"]:
    if refused_key_reason(bytes.fromhex(k["public_key_hex"])) is None:
        fail("rejected key is neither small-order nor non-canonical", k["name"])
    else:
        refused += 1

print("ok" if not bad else "FAILED", len(vf["statements"]), "statements,",
      len(vf["device_revokes"]), "device revokes,", sigs, "signatures verified,",
      len(vf["near_miss_payloads"]), "near misses,", refused, "refused keys")
sys.exit(1 if bad else 0)
