# Locating and Retrieving Data

Applications require a method to associate a Data to a particular Read Cap.

Since the Read Cap itself gives access to the plaintext, we can't use that.
Therefore, we have a way to derive an **Immutable Identifier** from either a Read Cap or a Verify Cap.

This `Identifier` doesn't reveal which Read Cap it goes with -- that can only be done by a device holding the Read Cap (or Verify Cap).
Internally, we use the Identifier in the [Catalog](./catalog-anthology.md).

The `Identifier` is a 32-byte value derived via tagged-hash (with tag `"magic_cap_storage_index_v1"`).
This `Identifier` is essentially the same as the "storage index" used in Tahoe-LAFS.

When locating Data stored in files on disk, that Catalog implementation uses the `Identifier` to put the files in a structure very similar to a Git "`objects/`" subdirectory.

In the HTTP implementation of Catalog, the `Identifier` is used in the URL to ask for the ciphertext (and metadata) separately.
