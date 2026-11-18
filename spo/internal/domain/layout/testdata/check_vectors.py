#!/usr/bin/env python3
"""An independent check of the layout and envelope test vectors.

It uses only the Python standard library: hashlib (Blake2b-256, SHA-256), hmac
(HKDF-SHA256), and a from-scratch XChaCha20-Poly1305 (RFC 8439 with the
HChaCha20 subkey step of draft-irtf-cfrg-xchacha). It shares no code with the Go
implementation and reads only the committed JSON files:

    ../../../platform/seal/testdata/object_vectors.json   the sealed envelopes
    vectors.json                                          the layout's objects

Run from this directory:  python3 -I check_vectors.py   (a few seconds; pass
--fast to skip the 4 MiB vector).
Exit status 0 means every vector was reproduced byte for byte.
"""
import hashlib
import hmac
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OBJ = os.path.join(HERE, "..", "..", "..", "platform", "seal", "testdata", "object_vectors.json")
LAY = os.path.join(HERE, "vectors.json")
FAST = "--fast" in sys.argv

M32 = 0xFFFFFFFF


def rotl(x, n):
    return ((x << n) & M32) | (x >> (32 - n))


def qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & M32; s[d] = rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & M32; s[b] = rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & M32; s[d] = rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & M32; s[b] = rotl(s[b] ^ s[c], 7)


def rounds(s):
    for _ in range(10):
        qr(s, 0, 4, 8, 12); qr(s, 1, 5, 9, 13); qr(s, 2, 6, 10, 14); qr(s, 3, 7, 11, 15)
        qr(s, 0, 5, 10, 15); qr(s, 1, 6, 11, 12); qr(s, 2, 7, 8, 13); qr(s, 3, 4, 9, 14)


CONST = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]


def hchacha20(key, nonce16):
    s = CONST + list(struct.unpack("<8I", key)) + list(struct.unpack("<4I", nonce16))
    rounds(s)
    return struct.pack("<8I", *(s[0:4] + s[12:16]))


def chacha_block(key, counter, nonce12):
    init = CONST + list(struct.unpack("<8I", key)) + [counter] + list(struct.unpack("<3I", nonce12))
    s = list(init)
    rounds(s)
    return struct.pack("<16I", *[(a + b) & M32 for a, b in zip(s, init)])


def poly1305(key, msg):
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    p = (1 << 130) - 5
    acc = 0
    for i in range(0, len(msg), 16):
        blk = msg[i:i + 16]
        acc = ((acc + int.from_bytes(blk + b"\x01", "little")) * r) % p
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def pad16(b):
    return b + b"\x00" * (-len(b) % 16)


def xchacha_seal(key, nonce24, pt, ad):
    sub = hchacha20(key, nonce24[:16])
    n12 = b"\x00\x00\x00\x00" + nonce24[16:]
    otk = chacha_block(sub, 0, n12)[:32]
    ct = bytearray()
    for i in range(0, len(pt), 64):
        ks = chacha_block(sub, 1 + i // 64, n12)
        chunk = pt[i:i + 64]
        ct += bytes(a ^ b for a, b in zip(chunk, ks))
    ct = bytes(ct)
    mac = poly1305(otk, pad16(ad) + pad16(ct) + struct.pack("<QQ", len(ad), len(ct)))
    return ct + mac


def xchacha_open(key, nonce24, sealed, ad):
    ct, tag = sealed[:-16], sealed[-16:]
    sub = hchacha20(key, nonce24[:16])
    n12 = b"\x00\x00\x00\x00" + nonce24[16:]
    otk = chacha_block(sub, 0, n12)[:32]
    want = poly1305(otk, pad16(ad) + pad16(ct) + struct.pack("<QQ", len(ad), len(ct)))
    if not hmac.compare_digest(want, tag):
        raise ValueError("authentication failed")
    out = bytearray()
    for i in range(0, len(ct), 64):
        ks = chacha_block(sub, 1 + i // 64, n12)
        out += bytes(a ^ b for a, b in zip(ct[i:i + 64], ks))
    return bytes(out)


def hkdf_expand(prk, info, n=32):
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:n]


def hkdf_sha256(ikm, info, n=32):
    prk = hmac.new(b"\x00" * 32, ikm, hashlib.sha256).digest()  # no salt = a zero block
    return hkdf_expand(prk, info, n)


# ---- a minimal canonical CBOR (RFC 8949 4.2.1) for what the layout uses ----

def head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    for w, ai in ((1, 24), (2, 25), (4, 26), (8, 27)):
        if n < 1 << (8 * w):
            return bytes([major << 5 | ai]) + n.to_bytes(w, "big")
    raise ValueError("too large")


def enc(v):
    if v is None:
        return b"\xf6"
    if v is True:
        return b"\xf5"
    if v is False:
        return b"\xf4"
    if isinstance(v, int):
        return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, bytes):
        return head(2, len(v)) + v
    if isinstance(v, str):
        b = v.encode()
        return head(3, len(b)) + b
    if isinstance(v, list):
        return head(4, len(v)) + b"".join(enc(x) for x in v)
    raise TypeError(type(v))


def dec(b, i=0):
    ib = b[i]
    major, info = ib >> 5, ib & 31
    if major == 7:
        return {20: False, 21: True, 22: None}[info], i + 1
    if info < 24:
        n, i = info, i + 1
    else:
        w = 1 << (info - 24)
        n, i = int.from_bytes(b[i + 1:i + 1 + w], "big"), i + 1 + w
    if major == 0:
        return n, i
    if major == 1:
        return -1 - n, i
    if major == 2:
        return bytes(b[i:i + n]), i + n
    if major == 3:
        return b[i:i + n].decode(), i + n
    if major == 4:
        out = []
        for _ in range(n):
            x, i = dec(b, i)
            out.append(x)
        return out, i
    raise ValueError("unsupported major type %d" % major)


def canonical(b):
    v, i = dec(b)
    assert i == len(b), "trailing bytes"
    assert enc(v) == b, "not canonical"
    return v


# ---- known answers from the published documents ----
# Each value is written from the document named beside it. If this
# implementation did not reproduce one of them, it would be wrong or the value
# below would be: so a failure here means "do not trust the rest", and a match is
# a check of the implementation by someone else's numbers.

def known_answers():
    # RFC 5869 appendix A.1 (test case 1) and A.3 (test case 3), SHA-256.
    ikm = bytes([0x0B] * 22)
    salt = bytes(range(0x00, 0x0D))
    info = bytes(range(0xF0, 0xFA))
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    check(prk.hex() == "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5", "RFC 5869 A.1 PRK")
    okm = hkdf_expand(prk, info, 42)
    check(okm.hex() == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", "RFC 5869 A.1 OKM")
    prk3 = hmac.new(b"\x00" * 32, ikm, hashlib.sha256).digest()  # an empty salt is a block of zeros
    check(prk3.hex() == "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04", "RFC 5869 A.3 PRK")
    check(hkdf_expand(prk3, b"", 42).hex() == "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8", "RFC 5869 A.3 OKM")
    # draft-irtf-cfrg-xchacha, section 2.2.1: HChaCha20.
    sub = hchacha20(bytes(range(32)), bytes.fromhex("000000090000004a0000000031415927"))
    check(sub.hex() == "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc", "draft-irtf-cfrg-xchacha HChaCha20 example")
    # draft-irtf-cfrg-xchacha, appendix A.3.1: AEAD_XCHACHA20_POLY1305.
    pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    key = bytes(range(0x80, 0xA0))
    nonce = bytes(range(0x40, 0x58))
    want = ("bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e"
            "c0875924c1c7987947deafd8780acf49")
    check(xchacha_seal(key, nonce, pt, aad).hex() == want, "draft-irtf-cfrg-xchacha A.3.1 AEAD example")
    print("known answers checked")


# ---- the format ----

BUCKETS = [4096 << i for i in range(11)]
OVERHEAD = 17 + 24 + 16
LABEL = "spo/object-envelope/1"


def bucket_for(n):
    for b in BUCKETS:
        if n <= b:
            return b
    return None


def frame(cbor):
    need = 4 + len(cbor) + OVERHEAD
    b = bucket_for(need)
    if b is None:
        return None
    body = struct.pack(">I", len(cbor)) + cbor
    return body + b"\x00" * (b - OVERHEAD - len(body))


def bstr_pattern(c, start):
    hdr = 3 if c - 3 < 65536 else 5
    n = c - hdr
    data = bytes((start + i) & 255 for i in range(n))
    return head(2, n) + data


failures = []


def check(cond, what):
    if not cond:
        failures.append(what)
        print("FAIL:", what)


def check_objects():
    v = json.load(open(OBJ))
    master, ws, epoch = (bytes.fromhex(v[k]) for k in ("master_key", "workspace_id", "key_epoch"))
    check(v["object_key_label"] == LABEL, "the label is the pinned one")
    idx = hkdf_sha256(master, b"spo-workbench/seal/v1/index")
    wrap = hkdf_sha256(master, b"spo-workbench/seal/v1/record-wrap")
    key = hkdf_expand(idx, LABEL.encode())
    nkey = hkdf_expand(idx, b"spo/object-nonce/1")
    check(key.hex() == v["object_key"], "K_obj = HKDF-Expand(index key, info = spo/object-envelope/1)")
    check(nkey.hex() == v["nonce_key"], "K_nonce = HKDF-Expand(index key, info = spo/object-nonce/1)")
    check(len({key, nkey, idx, wrap}) == 4, "the four keys are distinct")
    ad = enc(["spo/object/1", 1, epoch, ws])
    for ov in v["vectors"]:
        name = ov["name"]
        if ov.get("refused"):
            check(frame(b"\x00" * ov["cbor_len"]) is None, name + ": refused (does not fit the largest bucket)")
            continue
        if FAST and ov["cbor_len"] > 1 << 20:
            print("skipped (--fast):", name)
            continue
        if "cbor" in ov:
            cbor = bytes.fromhex(ov["cbor"])
        else:
            cbor = bstr_pattern(ov["cbor_len"], ov["pattern_start"])
        check(len(cbor) == ov["cbor_len"], name + ": cbor length")
        body = frame(cbor)
        if "body" in ov:
            check(body.hex() == ov["body"], name + ": body")
        nonce = hmac.new(nkey, ad + body, hashlib.sha256).digest()[:24]
        check(nonce.hex() == ov["nonce"], name + ": synthetic nonce = HMAC-SHA256(K_nonce, AD || body)[:24]")
        stored = bytes([1]) + epoch + nonce + xchacha_seal(key, nonce, body, ad)
        check(len(stored) == ov["stored_len"] and len(stored) in BUCKETS, name + ": stored length is a bucket")
        check(stored[:17].hex() == ov["header"], name + ": header")
        if "stored" in ov:
            check(stored.hex() == ov["stored"], name + ": stored bytes")
        h = hashlib.blake2b(stored, digest_size=32).hexdigest()
        check(h == ov["object_name"], name + ": object name is Blake2b-256 of the stored bytes")
        check(ov["path"] == "objects/%s/%s" % (h[:2], h), name + ": path")
        # and open what the Go code stored, when it is in the file
        if "stored" in ov:
            pt = xchacha_open(key, bytes.fromhex(ov["stored"])[17:41], bytes.fromhex(ov["stored"])[41:], ad)
            check(pt == body, name + ": the Go bytes open to the body")
        # padding is zero and the length field is the CBOR length
        n = struct.unpack(">I", body[:4])[0]
        check(n == len(cbor) and set(body[4 + n:]) <= {0}, name + ": length and zero padding")
        print("ok:", name, ov["stored_len"])


def check_layout():
    v = json.load(open(LAY))
    for e in v["bucket_edges"]:
        if "refused" in e:
            check(frame(b"\x00" * e["cbor_len"]) is None, "edge %d refused" % e["cbor_len"])
        else:
            check(bucket_for(4 + e["cbor_len"] + OVERHEAD) == e["stored_len"], "edge %d -> %d" % (e["cbor_len"], e["stored_len"]))
    for o in v["objects"]:
        cbor = bytes.fromhex(o["cbor"])
        val = canonical(cbor)
        body = frame(cbor)
        check(len(body) == o["body_len"] and hashlib.sha256(body).hexdigest() == o["body_sha256"], o["name"] + ": framed body")
        check(len(body) + OVERHEAD == o["stored_len"], o["name"] + ": stored length")
        if o["name"].startswith("record-"):
            check(len(val) == 9 and len(val[8]) == 4 and len(val[8][1]) == 2 + 1536, o["name"] + ": record shape, wrapped-key field is W+2 bytes")
            n = int.from_bytes(val[8][1][:2], "big")
            check(1 <= n <= 1536 and set(val[8][1][2 + n:]) <= {0}, o["name"] + ": wrapped-key length and zero fill")
        print("ok:", o["name"])
    for s in v["slots_objects"]:
        st = bytes.fromhex(s["stored"])
        check(len(st) in BUCKETS and st[0] == 2, s["policy"] + ": slots object header and bucket")
        n = struct.unpack(">I", st[17:21])[0]
        val = canonical(st[21:21 + n])
        check(set(st[21 + n:]) <= {0} and bucket_for(21 + n) == len(st), s["policy"] + ": zero padding in the smallest bucket")
        check(val[0] == "spo/slots/1" and val[1][2] == s["policy"] and val[1][3] == st[1:17], s["policy"] + ": label, policy, epoch")
        h = hashlib.blake2b(st, digest_size=32).hexdigest()
        check(h == s["object_name"] and s["path"] == "objects/%s/%s" % (h[:2], h), s["policy"] + ": name and path")
        rows = [list(r) for r in val[2]]
        check(hashlib.sha256(enc(["spo/slotset/3", s["policy"], rows])).hexdigest() == s["slot_set_hash"], s["policy"] + ": slot-set hash")
        print("ok: slots object", s["policy"])
    hd = v["head"]
    note = hd["note"].encode()
    check(hashlib.blake2b(note, digest_size=32).hexdigest() == hd["hash"], "head hash is Blake2b-256 of the note")
    lines = hd["note"].split("\n")
    keys = [l.split(" ")[0] for l in lines[1:-1]]
    check(lines[0] == "spo/head-provisional/1" and lines[-1] == "" and keys == ["workspace", "sequence", "previous", "manifest", "slots", "audit-seq", "audit-mac", "recovery-key", "checkpoint-key", "epoch", "object-format", "time"], "head note lines")
    check("object-format spo/object/1" in lines and len(lines[10].split(" ")[1]) == 32, "head note epoch (16 bytes) and object format")
    seq = int(lines[2].split(" ")[1])
    check(hd["path"] == "heads/%020d" % seq, "head path")
    check(v["head_namespace"] == "spo/head-provisional/v1" and v["parent_format"] == "provisional-1", "namespace and parent format")
    print("ok: head note")


if __name__ == "__main__":
    known_answers()
    check_objects()
    check_layout()
    if failures:
        print("%d failure(s)" % len(failures))
        sys.exit(1)
    print("all vectors reproduced")
