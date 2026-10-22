# Cryptographic Primitives

For better or for worse, we follow the cryptography from Tahoe-LAFS as closely as possible.
Although Tahoe-LAFS is an older project, it has at least received some attention from different cryptographers, and some light auditing.

Nevertheless, it is quite likely that better or more-modern primitives may be required.
As per the warning on the front cover, **no cryptographic audit has been performed** on Magic Cap as yet.

Internally in our code, we try to isolate these "Tahoe-LAFS inspired primitives" in the [tahoe.rs](https://github.com/magic-cap/magic-cap/blob/main/magic_cap/src/tahoe.rs) module.

All other Rust code uses [Rust Crypto](https://github.com/RustCrypto/) for cryptographic primitives and operations.

## Hashing

Many of the actual [Tahoe LAFS hashing implementations](https://github.com/tahoe-lafs/tahoe-lafs/blob/master/src/allmydata/util/hashutil.py) are available.
Yay free software!

In Magic Cap, "tagged hash" means "SHA256d" as the hashing algorithm, with a "Netstring"-encapsulated ASCII tag.
"SHA256d" means "SHA256 twice" (once on the tag prepended to the rest, and a second time on the result).
Although there's some talk of truncation in Tahoe we always use 32 bytes.

So, to take "the tagged hash" of the value `"No darkness lasts forever. And even there, there are stars."` with the tag `"example tag"` we do this:

- instantiate a SHA256 hasher
- update it with the 15 bytes: `11:example tag,`
- update it with the value (the 59 bytes ending `" stars."`).
- get the digest
- instantiate a second SHA256 hasher
- update it with the digest of the first
- get the digest
- return these 32 bytes

If you're following along at home, this should result in the bytes: `[170, 119, 221, 121, 208, 93, 0, 186, 155, 121, 80, 168, 102, 233, 219, 87, 111, 162, 128, 164, 48, 146, 149, 25, 106, 51, 96, 62, 0, 4, 34, 139]`.
See also the "hash.rs" example.


## Merkle Trees

Tahoe-LAFS makes use of a lot of different (Merkle trees)[https://en.wikipedia.org/wiki/Merkle_tree].

Magic Cap uses a Merkle tree over the ciphertext blocks, same as Tahoe LAFS does.
The leaves and interior nodes are hashed differently, as are any "empty" nodes.

- Leaf merkle nodes are tagged-hashed with tag `b"allmydata_crypttext_segment_v1"`.
- Interior merkle nodes are tagged-hashed with tag `b"Merkle tree internal node"`.
- Unused / empty leaf use value `"leaf:<num>"` and tag `b"Merkle tree empty leaf"`.
  (The `<num>` of a leaf is 1 for the first empty leaf, 2 for the second empty leaf, etc from left to right)


## Metadata Hash

Tahoe-LAFS has a hash over a bunch of the metadata called the "UEB Hash".
In Magic Cap we tagged-hash the Metadata block with tag `b"magic_cap_metadata_v1"`.

This is exposed publically in both a Magic Cap and a Magic Verifier as "the metadata hash", where it is based32 encoded as the first part of the string.
Since the Metadata includes the Merkle root of the ciphertext, this allows the software to verify that the Metadata corresponds to the Magic Cap string and subsequently that any block of the ciphertext also corresponds.


## Symmetric Encryption & Key Derivation

A Magic Cap's bulk data is encrypted using AES CTR.
The counter is the index of 16-byte chunks (and is thus not related to the block size)

FIXME TODO: does this mean our block size MUST be a multiple of 16??

Each Magic Cap has a primary secret, similar to Tahoe-LAFS.

FIXME TODO: the master secret is used directly for main encryption, same as tahoe: but should probably derive.

For any "other" keys required, a key-derivation from this master secret is used.
The key-derivation algorithm is as follows:

- decide on a unique "purpose" string
- use HKDF with SHA256 with the above string as "info"
- derive a 16-byte key from the above
