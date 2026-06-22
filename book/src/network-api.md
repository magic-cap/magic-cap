# Retrieving via HTTP

On the filesystem, seeking inside a file is fairly inexpensive.
We'd like to avoid doing range-request and other less-standard HTTP behavior (although this works too).

The HTTP API is rooted at some base URI.
(On the command-line, this is the `--catalog-url` option).
Following this, we have some additional valid sub-URLs:

`/magic-cap-catalog`
  : JSON describing this Catalog. Currently contains simply `{"version": 0}`

`/<identifier>/metadata`
  : the encoded metadata (including the encrypted portion) for the given [Identifier](./locations.md).

`/<identifier>/ciphertext`
  : the ciphertext blocks, one after the other. A client that wishes to do random-access to particular blocks could use HTTP Range Requests to do so. The block size is encoded in the metadata.
