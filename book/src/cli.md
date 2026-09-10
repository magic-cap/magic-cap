# Command Line Interface

To allow rapid experimentation with this library, many aspects of it are exported via the `mcap` CLI tool.

This is a sub-command based tool.
There are a few top-level options and several sub commands (even some "sub-sub commands").

## Practical Uses

There are some practical use-cases that the CLI and/or Rust libraries make available to tinkerers and experts right now.
These include:

**Publish immutables to a Web server** that you control.
If you can `rsync` or `scp` to a Web server then you can keep a [Catalog](./catalog-anthology.md) published.
Use `mcap encrypt --catalog ./local/catalog` when creating Immutables.
To syncrhonize / publish to your Web site, use `mcap ./local/catalog ~/public_html/published_catalog` along with an `rsync` or `scp` command to move all of `~/public_html/published_catalog` to your Web server.

This would then allow other computers to use `mcap decrypt --url-catalog https://meejah.ca/published_catalog` (of course insert your own URL) to retrieve and decrypt an Immutable.
(You need to share the Read Cap with them somehow).
You can use Anthologies to group many distinct files together.

**Use Immutables locally** with Rust-based software.
Although our exact public API is still very early and in flux, we'd appreciate hearing of any success (or failure!) using these primitives inside Rust programs.
By providing both "push"-style and "pull"-style reading and writing (via `Read`, `Seek` and `Write` traits) our intent is to make it easy to plug in "but private!" use-cases for tools.
Additional tools for exchanging bytes over the network are coming too!


**Immediate release of digital artifacts** can be prototyped with the existing tools.
Create your ciphertext with `mcap encrypt` and put the resulting `.mcap` file on a public Web server.
Fans may then download this `.mcap` file at their leisure.
In order to **do the release later** you simply make the short Read Cap string available to users.
They can then use `mcap decrypt` to reveal the digital artifact.
(Of course, a polished end-user tool would likely do this internally via the Rust APIs).

*Please get in touch* if you try any of the above (e.g. file a ticket, find us on IRC or Mastodon) whether it was successful or not!


## Common Top-Level Options

These options apply to every command.

`--loglevel`, `-l`
  : Specify the logging level, one of `ERROR`, `WARN`, `INFO`, `DEBUG`, `TRACE`.


## Core Functionality

The main thing this library does is encrypt and later decrypt data.

`mcap encrypt`
  : Turn plaintext into the ciphertext Data and a Read Cap. We need somewhere to write the Data; the Read Cap is printed to `stderr` (in case you chose to write the Data to `stdout` instead of a file or [Catalog](./catalog-anthology.md)).

`mcap decrypt`
  : Turn a ciphertext Data and associated Read Cap back into the plaintext.
  
These two commands know how to use data inside a Catalog, which can live on disk or behind an HTTP interface.
These are controlled with the `--catalog` and `--catalog-url` options.
Currently, we can only write to an on-disk catalog.

`mcap verify`
  : Confirm that a given Data exists and correctly corresponds to the Read Cap that the specified Verify Cap is derived from.
    Basically this computes the merkle root of the ciphertext blocks and confirms it matches the root in the Cap.
	This needs access to the ciphertext, so uses options for at Catalog similar to the prior two commands.

`mcap reduce`
  : Turn a Read Cap into its associated Verify Cap.


## Sharing Data

`mcap publish`
  : Turn a local on-disk Catalog into a format suitable for static-hosting.
    This "static hosted" data corresponds to the read-only ReST API.
	An example workflow could be to `mcap publish` your Catalog periodically, and `rsync` it to a static Web host.


## Anthologies

Highly related collections of data are called an "Anthology" in Magic Cap.
This is somewhat like a Zip archive.

The result is a single Read Cap that itself points to other Read Caps.
Local directories are used by these commands: you can turn (recursively!) a directory into an Anthology.
Usually you'd use this to encode a bunch of things into a particular Catalog.

When decrypting, you can decrypt everything in the Anthology to a local directory, or use `mcap anthology list` to choose particular items of interest.

`mcap anthology create`
  : Turn a local directory (and all its descendants) into a collection of Read Caps, culminating in a top-level Anthology Read Cap that is printed out.
    Anyone with access to the appropriate Catalog and the Anthology Read Cap can access all the data inside it.
	You may also choose to share just the Read Cap for an item in an Anthology (e.g. a sub-directory or single file) -- the receiver of such a Read Cap cannot determine if this is part of any Anthologies (unless they also have the Anthology Read Cap).

`mcap anthology list`
  : Itemize everything in a given Anthology.
    Does not access or decrypt any of these items.
