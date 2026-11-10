# Locating and Retrieving Data

Applications require a method to associate a Data to a particular Read Cap.

Since the Read Cap itself gives access to the plaintext, we can't use that.
Therefore, we have a way to derive an **Immutable Identifier** from either a Read Cap or a Verify Cap.
This is known as an Identifier or Locator internally.

This `Identifier` doesn't reveal which Read Cap it goes with -- that can only be done by a device holding the Read Cap (or Verify Cap).
Internally, we use the Identifier in the [Catalog](./catalog-anthology.md).

The `Identifier` is a 32-byte value derived via tagged-hash (with tag `"magic_cap_storage_index_v1"`).
This `Identifier` is essentially the same as the "storage index" used in Tahoe-LAFS.

When locating Data stored in files on disk, that Catalog implementation uses the `Identifier` to put the files in a structure very similar to a Git "`objects/`" subdirectory.

In the HTTP implementation of Catalog, the `Identifier` is used in the URL to ask for the ciphertext (and metadata) separately.

> [!TIP]
> When developing your threat model, note that lots of network equipment leaks URLs.
> This, in turn, may leak the identity of Data that is of interest.
> While you do still need the Read Cap or Verify Cap to determine an `Identifier`, these leaks may still be of interest -- for example, an entity that logs every URL ever accessed could later associate these requests if they recovered a Read Cap or Verify Cap.
>
> For example if you encoded the Snowden leaks in a Magic Cap, an entity could confirm which IPs accessed these `Identifier` objects from a public Web service (if they had detailed request logs from that service and had recovered a Read Cap for the leaks).
>
> We are not *your* cryptographer...
