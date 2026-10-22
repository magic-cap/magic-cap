# Catalogs and Anthologies

Using book-adjacent naming, we have several actors in our system:

- **Author**: computer controlled by a human who creates **Data** to share with other humans
- **Data**: encrypted digital information, rendered accessible with a Read Cap
- **Reader**: computer controlled by a human to find, download and decrypt Data (for use by particular apps)
- **Catalog**: a collection of (encrypted) Data in a particular place accessible to **Readers** somehow (e.g. a GitHub repository, a Web site, an S3 bucket, a BackblazeB2 folder, a thumb drive, etc)
- **Anthology**: a group of Data deemed related by some Author (e.g. all the 3D printer files for a project; or the html, css and images making up a Web page; or anything you might group in a Zip file)
- **Publisher**: a computer which has the correct credentials to put new Data into a **Catalog**.

<!-- todo: consider "Zine" instead of "Catalog"? (Less boring) -->

There is only one way to create a Read Cap: have the write credentials to a Catalog.
This can be as simple as a directory that you have write permission to on a local drive.
We have support for the following sorts of Catalogs:

- local, directory-based Catalogs (in Rust, that's `ImmutableDirectoryCatalog`.
- HTTP ReST-style API (in Rust, it's `ImmutableWebCatalog`).
- [planned](https://github.com/magic-cap/magic-cap/issues/43): S3 compatible API

Any Publisher necessarily also has some way to do read access; that is, a Publisher has an associated Catalog.
We have support for the following sorts of Publishers:

- local, directory-based Publisher
- GitHub API via token
- via example: rsync, scp

When thinking about how to organize things, "Catalog" is the top level (for Readers).
An "Anthology" must live inside a Catalog.

Let us consider the distinction between the two categories.

## Catalogs

A Catalog is like a library: a whole bunch of different titles, some perhaps related and others less so.
Before the Internet, real-world libraries often used a "card catalog" to index the collection.
So, for this sort of collection in Magic Cap, we name it a "Catalog".

In this analogy, the "title" corresponds to the [Identifier](./locations.md) and the result is the ciphertext and associated metadata for the Read Cap (or Verify Cap) the Identifier is derived from.

Remember that only holders of the Read Cap can see the plaintext.
That is, the books contain gibberish.
If you have a Read Cap you can make the gibberish recognizable.
You can't even look things up in the Catalog without a Read Cap (or Verify Cap), since you need an Identifier.

Using the CLI, the top-level `--catalog` option configures Catalogs to use.

You can ask the CLI to output the `Identifier` for a Read Cap you have with `mcap debug locator` which will output the hex-string of the Identifier on stdout.


## Anthologies

Another kind of collection is when we have two or more tightly-related items.
For example, a collection of pictures about some event to share with friends.
Or a group of HTML, CSS and images that comprise a Web site or blog post.
Anything that one might typically use a Zip file for.

We name this sort of collection an "Anthology" to stay with the book analogy: several related books or stories or poems are collected together in a single anthology.

An Anthology in Magic Cap is essentially just a list of names and their associated Read Caps.
That is, an "Anthology Read Cap" is just a normal Read Cap with its contents being in a particular format which refers to other Read Caps.
All the Data for a single Anthology should usually be located in a single Catalog.

The CLI has a `mcap anthology` sub-command group to create and list Anthologies.


## Concrete Examples

Prerequisite: a local copy of (the Magic Cap repository)[https://github.com/magic-cap/magic-cap] where ``cargo run`` works.

Let us consider the example Catalog, located in `./kitten-catalog`.

Inside `./kitten-catalog` are a bunch of two-character subdirectories.
Within each of these are some number of Data files.
This is all very similar to a ".git" object storage directory.

The hex-looking files are the hex-encoded Identifier strings for all the Data in this Catalog.
Condier one of the "kitten" examples from the README.org: `mcap0rAGkuRf82Cy5AYsS_1Xh8ngZoxa2Ra31dv4SOWQ-7UTbOEuu2iGL-GFRJ_hJTnVuP`.

We can use the CLI to find the Identifier for this Read Cap:

```bash,ignore
$ cargo run -- debug locator mcap0rAGkuRf82Cy5AYsS_1Xh8ngZoxa2Ra31dv4SOWQ-7UTbOEuu2iGL-GFRJ_hJTnVuP
98d8a2491e1ff0d4191a6829a572b0b6b29530b0223535420f1a90683033c172
```

So if we look in the kitten-catalog we can find this Data, which starts with the four bytes "mcap" and then the current version as a 32-byte unsigned integer:

```bash,ignore
$ hexdump -C -n 8 kitten-catalog/98/98d8a2491e1ff0d4191a6829a572b0b6b29530b0223535420f1a90683033c172 
00000000  6d 63 61 70 00 00 00 01                           |mcap....|
00000008
```

The ReST API is somewhat similar, but it splits out the "metadata" and "ciphertext" blocks as separate URI endpoints.
This enables the HTTP API to minimize seeking or demand range-requests.
(The on-disk format puts the metadata offset in the last 8 bytes to facilitate no-seek streaming during encryption).

We have an example of an Anthology as well.
Here are all the kitten pictures from the README:

```bash,ignore
$ cargo run -- --catalog kitten-catalog/ decrypt mcap0r_eX0bI_Nmm2kdwuFPqEHrVbjdbVo4_i9H_hVL13G2NWACUaXowpM6rXRR7iwFnED
mcap0rlnzyN_KuH9bRBUHP3QkXBlkWipQ6JMw50NbNBpt6aj15q2pSnh85eKib9Ac-2m51 bruennhilde.jpeg
mcap0rAGkuRf82Cy5AYsS_1Xh8ngZoxa2Ra31dv4SOWQ-7UTbOEuu2iGL-GFRJ_hJTnVuP cat-on-shoulder.jpeg
mcap0rWoPqhovsj1gNIWosnS4BeB0yCt8JCTCiFuCiMoVwKFax8e0XiiUHk-Le96ImU8eT kittens-in-basket.jpeg
mcap0rQJ08bwA8dj4NFCMCTyzp5YaGq2JXZHB7kj3wUmTWXO7G_0PIs2hqi5SHc3QUPsRs the-cook.jpeg
mcap0r-A3km_Op0GEpxQO3vNDH0wyEaaBcBtfOHAqp47Y8ukfiCdhLipNVjJlatMtmT3le three-jolly-kittens.jpeg
```

This first version of Anthology just includes a space-separated Read Cap string and (suggested) name encoded as a text file.
