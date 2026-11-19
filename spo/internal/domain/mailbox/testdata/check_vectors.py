#!/usr/bin/env python3
"""Independent check of vectors.json and vectors_v2.json, with a hand-written
canonical CBOR encoder and the standard library only: the envelope hash
(hashlib's BLAKE2b with a 32-byte digest); the signed auth arrays of both
versions; the hash of each expected-sender list (version 2); and every frame,
which is encoded again from its `fields` (in the order of the message's shape)
and compared byte for byte with `cbor_hex`, with its length prefix and message
type checked. The Ed25519 signatures are not checked here (the standard library
has no Ed25519); the Go test verifies them."""
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

# --- vectors_v2.json (ADR 0014 work package 2) -------------------------------
# The shape of each version 2 frame: (field name, kind) in wire order. The kinds
# are those above and blist, a list of byte strings given as hex. `binding` is
# [ed25519, x25519, sign1, cose key]. The Revoke frames are two shapes, told
# apart by the kind field, which is itself a field here.
SHAPES2 = {
    "challenge": (0, [("min", "u"), ("max", "u"), ("nonce", "b"), ("relay_key", "b"), ("relay_time", "u")]),
    "auth_v2": (1, [("version", "u"), ("fingerprint", "b"), ("signature", "b"), ("binding", "blist"), ("senders", "blist")]),
    "authok_v2": (2, [("version", "u"), ("max_envelope", "u"), ("max_entries", "u"), ("max_bytes", "u"), ("retention_seconds", "u"), ("until", "u")]),
    "put_v2": (3, [("request_id", "u"), ("wallet_key", "b"), ("to", "b"), ("mid", "b"), ("size", "u")]),
    "put_result": (4, [("request_id", "u"), ("status", "u")]),
    "error": (9, [("code", "u")]),
    "revoke_device": (10, [("request_id", "u"), ("kind", "u"), ("ed25519", "b"), ("x25519", "b"), ("not_before", "u"), ("signature", "b")]),
    "revoke_wallet": (10, [("request_id", "u"), ("kind", "u"), ("sign1", "b"), ("key", "b")]),
    "revoke_result": (11, [("request_id", "u"), ("status", "u")]),
}


def field2(kind, v):
    if kind == "blist":
        return [bytes.fromhex(m) for m in v]
    return field(kind, v)


def canonical_senders(keys):
    """A sender list is canonical: at most 64 keys of 28 bytes, strictly
    ascending (sorted, no repeat)."""
    return (len(keys) <= 64 and all(len(k) == 28 for k in keys)
            and all(a < b for a, b in zip(keys, keys[1:])))


def fingerprint(ed25519, x25519):
    """The device fingerprint, by the definition of domain/party: the first 20
    bytes of BLAKE2b-256 over the domain `spo/party/v1`, the Ed25519 public key
    and the X25519 public key."""
    return hashlib.blake2b(b"spo/party/v1" + ed25519 + x25519, digest_size=32).digest()[:20]


# The directory of vectors may be given, so that a corrupted copy can be checked.
data = sys.argv[1] if len(sys.argv) > 1 else here
vf2 = json.load(open(os.path.join(data, "vectors_v2.json")))
list_hash = {}
for v in vf2["senders"]:
    keys = [bytes.fromhex(k) for k in v["keys"]]
    if not canonical_senders(keys):
        print("senders not canonical", v["name"]); bad += 1
    got = hashlib.blake2b(enc(keys), digest_size=32).hexdigest()
    if got != v["hash_hex"]:
        print("senders hash mismatch", v["name"]); bad += 1
    list_hash[v["name"]] = v["hash_hex"]
for v in vf2["auth_v2"]:
    arr = ["spo/mailbox-auth/v2", 2, bytes.fromhex(v["relay_key"]),
           bytes.fromhex(v["client_node_key"]), bytes.fromhex(v["nonce"]),
           v["relay_time"], bytes.fromhex(v["fingerprint"]),
           bytes.fromhex(v["binding_hash"]), bytes.fromhex(v["senders_hash"])]
    got = enc(arr)
    if got.hex() != v["bytes_hex"] or got[0] != 0x89:
        print("auth v2 bytes mismatch", v["name"]); bad += 1
    # The senders hash is the hash of a sender-list vector, by name.
    if list_hash.get(v["senders_list"]) != v["senders_hash"]:
        print("auth v2 senders hash is not that of the list", v["name"], v["senders_list"]); bad += 1
for v in vf2["frames"]:
    c, f = bytes.fromhex(v["cbor_hex"]), bytes.fromhex(v["frame_hex"])
    if struct.unpack(">I", f[:4])[0] != len(c) or f[4:] != c or len(c) > 4096:
        print("frame v2 mismatch", v["name"]); bad += 1
    typ, shape = SHAPES2[v["shape"]]
    if typ != v["type"]:
        print("type mismatch", v["name"]); bad += 1
    if sorted(v["fields"]) != sorted(n for n, _ in shape):
        print("fields v2 mismatch", v["name"]); bad += 1
        continue
    arr = [typ] + [field2(k, v["fields"][n]) for n, k in shape]
    # The binding of an Auth is the nested array of its four byte strings, and
    # the senders list another: both are lists of byte strings, as encoded.
    if enc(arr) != c:
        print("cbor v2 mismatch", v["name"], enc(arr).hex(), c.hex()); bad += 1
    if v["shape"] == "auth_v2" and (v["fields"]["version"] != 2 or len(v["fields"]["binding"]) != 4
                                    or len(bytes.fromhex(v["fields"]["binding"][2])) > 512
                                    or len(bytes.fromhex(v["fields"]["binding"][3])) > 128):
        print("auth v2 bound mismatch", v["name"]); bad += 1
    if v["shape"] == "auth_v2":
        # The frame's own checks: the list is canonical, and the fingerprint is
        # that of the frame's device keys (the relay recomputes it from them).
        senders = [bytes.fromhex(k) for k in v["fields"]["senders"]]
        if not canonical_senders(senders):
            print("auth v2 frame senders not canonical", v["name"]); bad += 1
        binding = [bytes.fromhex(k) for k in v["fields"]["binding"]]
        if len(binding[0]) != 32 or len(binding[1]) != 32 or fingerprint(binding[0], binding[1]) != bytes.fromhex(v["fields"]["fingerprint"]):
            print("auth v2 frame fingerprint is not that of its device keys", v["name"]); bad += 1
        if not any(senders == [bytes.fromhex(k) for k in s["keys"]] for s in vf2["senders"]):
            print("auth v2 frame senders are in no sender-list vector", v["name"]); bad += 1
print("ok" if not bad else "FAILED", len(vf["hash"]), "hashes,", len(vf["auth"]), "auth,", len(vf["frames"]), "frames;",
      len(vf2["auth_v2"]), "auth v2,", len(vf2["senders"]), "sender lists,", len(vf2["frames"]), "v2 frames")
sys.exit(1 if bad else 0)
