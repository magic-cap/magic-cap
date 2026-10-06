# Glossary

## Read Cap

A short base64-encoded string which can be used in a different time or place to decrypt Data.
For example, `mcap0r3LsgJf1LYZtRc_BGOzhx8j_FVDmFROmoBhDHGNTfXq8EAnU9NkykdwXfOg6VdQ7v`

In Rust, this is represented by the `ImmutableReadCap` type.

## Data

The metadata & ciphertext that can unlocked with a "Read Cap".
Note that some basic metadata (block-size, total size, ciphertext merkle root and the merkle leaves) is unencrypted; all other metadata, including all application-provided keys and values is encrypted.

FIXME: block-size and total-size should also be encrypted

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

This allows a client holding a Read Cap to derive the Identifier and
then ask the storage system if that Data is available (without
revealing details about the Read Cap).
For example, an on-disk storage system may simply check if a particular file exists.

## Anthology

A way to group multiple different Read Caps together ("like a Zip file").
For example, all the assets for a blog post.
This allows you to have a single "top-level" Read Cap that references other Read Caps of various kinds.

## Catalog vs. Anthology

The Anthology concept (think a book anthology) is meant to evoke a
related collection that is meaningful to the application (or author)
-- all the files that make up a blog post, or a bunch of photos for a
particular client.

A Catalog (think of a library card-catalog) is meant as a more generic
place to store all kinds of things (e.g. books, anthologies, etc).

Although the items in a Catalog may be related in some way, that's usually along "access" lines (e.g. *every current employee of MegaCorp* or "all comrades in good stating at the Tech Collective" or *anyone who has the right Onion Service URI*.
Someone providing Catalog services may have several different applications with different data-storage needs using it; any number of Anthologies (which are just Data) are used by applications with "collections" meaningful to them.

So: Anthologies are a way to structure related Data together
...and Catalogs are a way to provide a more generalized collection of Data (located only by Identifier) with any stucture decided by users.
A Catalog-provider could attempt to infer relationships through traffic monitoring or access patterns, but it cannot tell if any particular Data is a single thing or an Anthology or part of other Anthologies.

**Analogy time!**.
That is: books are just books to the library.
They are found on the shelves by obscure numbers on their spine (you look these up in a catalog).
Every book is filled with gibberish (but you can see how many pages there are).
Anyone who signs out a book needs the corresponding Read Cap to translate the gibberish.
("Signing out" a book in this magic library makes a clone of it, so any number of people can do this).
Someone with just a Verify Cap may locate a book as well, but cannot translate the gibberish (they can, however, tell if any pages are missing or altered).
