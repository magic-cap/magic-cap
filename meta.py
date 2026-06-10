# decode the secret metadata from a raw cap file
#
# note, you need the raw "key_bytes" from a ImmutableReadCap to stuff into "key_bytes" below.
# that can be the raw output from a "dbg!(cap)" call
#
# this gives us slightly more confidence the Rust code is right if a
# different implementation can do it too

import sys
import struct
import msgpack

if len(sys.argv) != 2:
    print("give me a raw mcap file")
    sys.exit(-1)

with open(sys.argv[1], "rb") as f:
    data = f.read()

assert data[:4] == b"mcap"

# the "metadata offset" is the last 8 bytes of the file, as unsigned 8-byte integer
(offset, ) = struct.unpack(">Q", data[-8:])

print(f"offset: {offset}")

metadata = data[offset:-8]
print(f"{len(metadata)} bytes of metadata")

plain_meta = msgpack.loads(metadata)
size, blocks, blocksize, merkle_leaves, ciphertext_root, secret_meta = plain_meta
print(f"size: {size}")
print(f"blocks: {blocks}")
print(f"blocksize: {blocksize}")

assert len(merkle_leaves) == blocks, "inconsistent number merkle leaves vs. block count"

# TODO FIXME: it's weird that the secret_meta unpacked to a LIST of
# one bytes object -- can we make it serialize just "a bytes object"?
print(f"secret metadata: {secret_meta[0]}")

# decrypt the secret metadata .. we need a tagged-hash of the secret

# sha256 HKDF of the above with "magic-cap-metadata-0" as context / tag

secret_data = secret_meta[0]
key_bytes = bytes([
    188,
    176,
    34,
    171,
    196,
    45,
    66,
    44,
    5,
    253,
    154,
    49,
    123,
    164,
    110,
    73,
])

import hashlib
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
x = HKDF(algorithm=hashes.SHA256(), length=16, salt=None, info=b"magic-cap-metadata-0")
key = x.derive(key_bytes)
print(f"metadata key {key}")
assert len(key) == 16, "expected 16 bytes of key"

# ctr128be aes128
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
iv = b"\x00" * 16
cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
decryptor = cipher.decryptor()
msg = decryptor.update(secret_data) + decryptor.finalize()
print("decrypted", msg)

seekrit_meta = msgpack.loads(msg)
print("meta", seekrit_meta)
