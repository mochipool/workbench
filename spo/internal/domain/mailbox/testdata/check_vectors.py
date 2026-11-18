#!/usr/bin/env python3
"""Independent check of vectors.json, with a hand-written canonical CBOR
encoder and the standard library only: the envelope hash (hashlib's BLAKE2b
with a 32-byte digest); the signed auth array; and every frame, which is
encoded again from its `fields` (in the order of the message's shape) and
compared byte for byte with `cbor_hex`, with its length prefix and message type
checked. The Ed25519 signatures are not checked here (the standard library has
no Ed25519); the Go test verifies them."""
import hashlib
import json
import os
import struct
import sys


def head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    for info, w in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * w):
            return bytes([major << 5 | info]) + n.to_bytes(w, "big")
    raise ValueError(n)


def enc(v):
    if isinstance(v, bool):
        return b"\xf5" if v else b"\xf4"
    if isinstance(v, int):
        return head(0, v)
    if isinstance(v, bytes):
        return head(2, len(v)) + v
    if isinstance(v, str):
        b = v.encode()
        return head(3, len(b)) + b
    if isinstance(v, list):
        return head(4, len(v)) + b"".join(enc(x) for x in v)
    raise TypeError(v)


# The shape of each message type: (field name, kind) in wire order. Kinds: u an
# unsigned integer, b a byte string given as hex, bool, entries a list of
# [mid hex, size], mids a list of hex byte strings.
SHAPES = {
    0: [("min", "u"), ("max", "u"), ("nonce", "b"), ("relay_key", "b"), ("relay_time", "u")],
    1: [("version", "u"), ("fingerprint", "b"), ("signature", "b")],
    2: [("version", "u"), ("max_envelope", "u"), ("max_entries", "u"), ("max_bytes", "u"), ("retention_seconds", "u")],
    3: [("request_id", "u"), ("to", "b"), ("mid", "b"), ("size", "u")],
    4: [("request_id", "u"), ("status", "u")],
    5: [("request_id", "u"), ("after", "b"), ("max_items", "u"), ("wait_seconds", "u")],
    6: [("request_id", "u"), ("entries", "entries"), ("more", "bool")],
    7: [("request_id", "u"), ("mids", "mids")],
    8: [("request_id", "u"), ("deleted", "u")],
    9: [("code", "u")],
}


def field(kind, v):
    if kind == "u":
        assert isinstance(v, int) and not isinstance(v, bool), v
        return v
    if kind == "b":
        return bytes.fromhex(v)
    if kind == "bool":
        assert isinstance(v, bool), v
        return v
    if kind == "entries":
        return [[bytes.fromhex(m), n] for m, n in v]
    if kind == "mids":
        return [bytes.fromhex(m) for m in v]
    raise ValueError(kind)


here = os.path.dirname(os.path.abspath(__file__))
vf = json.load(open(os.path.join(here, "vectors.json")))
bad = 0
for v in vf["hash"]:
    got = hashlib.blake2b(bytes.fromhex(v["envelope_hex"]), digest_size=32).hexdigest()
    if got != v["mid"]:
        print("hash mismatch", v["envelope_hex"][:16]); bad += 1
for v in vf["auth"]:
    arr = ["spo/mailbox-auth/v1", v["version"], bytes.fromhex(v["relay_key"]),
           bytes.fromhex(v["client_node_key"]), bytes.fromhex(v["nonce"]),
           v["relay_time"], bytes.fromhex(v["fingerprint"])]
    if enc(arr).hex() != v["bytes_hex"]:
        print("auth bytes mismatch", v["name"]); bad += 1
for v in vf["frames"]:
    c, f = bytes.fromhex(v["cbor_hex"]), bytes.fromhex(v["frame_hex"])
    if struct.unpack(">I", f[:4])[0] != len(c) or f[4:] != c or c[0] >> 5 != 4:
        print("frame mismatch", v["name"]); bad += 1
    shape = SHAPES[v["type"]]
    if sorted(v["fields"]) != sorted(n for n, _ in shape):
        print("fields mismatch", v["name"]); bad += 1
        continue
    arr = [v["type"]] + [field(k, v["fields"][n]) for n, k in shape]
    if enc(arr) != c:
        print("cbor mismatch", v["name"], enc(arr).hex(), c.hex()); bad += 1
print("ok" if not bad else "FAILED", len(vf["hash"]), "hashes,", len(vf["auth"]), "auth,", len(vf["frames"]), "frames")
sys.exit(1 if bad else 0)
