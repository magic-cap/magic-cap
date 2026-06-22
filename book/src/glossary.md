# Glossary

## Read Cap

A short base64-encoded string which can be used to decrypt Data.
For example, `mcap0r3LsgJf1LYZtRc_BGOzhx8j_FVDmFROmoBhDHGNTfXq8EAnU9NkykdwXfOg6VdQ7v`

In Rust, this is represented by the `ImmutableReadCap` type.

## Data

The metadata & ciphertext that can unlocked with a "Read Cap".
Note that some basic metadata (block-size, total size, ciphertext merkle root and the merkle leaves) is unencrypted; all other metadata, including all application-provided keys and values is encrypted.

## Verify Cap

A short base64-encoded string that can verify the validity of Data (but not decrypt it).
This is related to the Read Cap and can be derived (offline) from it in a deterministic way.

A "Read Cap" (or "Verify Cap") "corresponds to" a given Data if it may decrypt (or only verify) it.
In Rust, this is represented by the `ImmutableVerifyCap` type.


## Identifier or Locator

A 32-byte string (usually base32 encoded) derived from a "Read Cap" (or "Verify Cap") that uniquely identifies it (e.g. within a Catalog).
This is used by parts of the system to associate a Data to a Read Cap (without revealing the Read Cap or Verify Cap to the storage system).

## Catalog

A collection of Data organized by "Identifier" (at some root directory or URL, for example).

This allows a client holding a Read Cap to derive the Identifier and then ask the storage system if that Data is available.
For example, an on-disk storage system may simply ask if a particular file exists.
