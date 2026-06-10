#
# this is basically "minimum viable" Python to decode an on-disc capability alongside a Read Cap using Python
#
# this gives us slightly more confidence the Rust code is right if a
# different implementation can do it too
#
# for example:
#
#    python meta.py kitten.mcap mcap0r3LsgJf1LYZtRc_BGOzhx8j_FVDmFROmoBhDHGNTfXq8EAnU9NkykdwXfOg6VdQ7v
#

import sys
import struct
import msgpack
import base64
import hashlib
from dataclasses import dataclass
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


@dataclass
class ReadCapability:
    key: bytes
    metadata_hash: bytes


@dataclass
class ImmutableMetadata:
    size: int
    blocks: int
    blocksize: int
    leaves: list
    ciphertext_root: bytes
    secret: dict


def parse_capstr(capstr: str) -> ReadCapability:
    if capstr[:4] != "mcap":
        raise ValueError("not a capability string")
    if capstr[4] != "0":
        raise ValueError("capability string version is not 0")
    if capstr[5] != "r":
        raise ValueError("capability string is not a Read Cap")

    data = base64.urlsafe_b64decode(capstr[6:])
    if len(data) != 48:
        raise ValueError("capability data needs 48 bytes")
    metadata_hash = data[:32]
    key = data[32:48]
    return ReadCapability(key, metadata_hash)



def decode_readcap(data_fname, capstr):
    """
    Decode the Magic Cap data in 'data_fname' using the Read Cap
    in 'capstr'
    """
    with open(data_fname, "rb") as f:
        data = f.read()
    cap = parse_capstr(capstr)

    assert data[:4] == b"mcap"

    # the "metadata offset" is the last 8 bytes of the file, as unsigned 8-byte integer
    (offset, ) = struct.unpack(">Q", data[-8:])
    ## print(f"offset: {offset}")

    metadata = data[offset:-8]
    ## print(f"{len(metadata)} bytes of metadata")

    plain_meta = msgpack.loads(metadata)
    size, blocks, blocksize, merkle_leaves, ciphertext_root, secret_meta = plain_meta

    # we'll round up to a power of two for leaves
    if blocks > len(merkle_leaves):
        raise ValueError(f"{len(merkle_leaves)} merkle leaves vs. {blocks} block count")

    # compute the metadata hash .. then we can "trust" the metadata
    # as version 0 follows Tahoe, this is a 32 byte tagged-hash:
    # - netstring of the tag
    # - the value (all big-endian 64-bit integer)
    #   - size (u64)
    #   - total blocks (u64)
    #   - block size (u32)
    #   - 32 bytes of ciphertext / merkle root
    # - sha256 twice over the above
    tag = b"21:magic_cap_metadata_v1,"
    value = struct.pack(">QQL", size, blocks, blocksize)
    value += ciphertext_root
    hasher0 = hashlib.sha256()
    hasher1 = hashlib.sha256()
    hasher0.update(tag + value)
    hasher1.update(hasher0.digest())
    alleged_metadata_hash = hasher1.digest()

    if True:
        for x in alleged_metadata_hash:
            print(f" {x:02x}", end="")
        print()
        for x in cap.metadata_hash:
            print(f" {x:02x}", end="")
        print()

    if alleged_metadata_hash != cap.metadata_hash:
        raise ValueError("capability hash doesn't correspond to data hash")

    # TODO FIXME: it's weird that the secret_meta unpacked to a LIST of
    # one bytes object -- can we make it serialize just "a bytes object"?
    print(f"secret metadata: {secret_meta[0]}")

    # sha256 HKDF of the root key with "magic-cap-metadata-0" as
    # context / tag

    secret_data = secret_meta[0]
    hkdf = HKDF(algorithm=hashes.SHA256(), length=16, salt=None, info=b"magic-cap-metadata-0")
    key = hkdf.derive(cap.key)
    print(f"metadata key {key}")
    assert len(key) == 16, "expected 16 bytes of key"

    # ctr128be aes128, all-zero IV
    iv = b"\x00" * 16
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    decryptor = cipher.decryptor()
    msg = decryptor.update(secret_data) + decryptor.finalize()
    # print("decrypted", msg)
    seekrit_meta = msgpack.loads(msg)
    print("meta", seekrit_meta)

    return ImmutableMetadata(
        size,
        blocks,
        blocksize,
        merkle_leaves,
        ciphertext_root,
        seekrit_meta,
    )


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} file cap-string")
        sys.exit(1)
    meta = decode_readcap(sys.argv[1], sys.argv[2])
    hexroot = base64.b16encode(meta.ciphertext_root).decode('utf8')
    print("decoded")
    print(f"  size: {meta.size} bytes ({meta.blocks} x {meta.blocksize} blocks)")
    print(f"  root: {hexroot.lower()}")
    print("  encrypted metadata:")
    for k, v in meta.secret.items():
        print(f"    {k}: {v}")


