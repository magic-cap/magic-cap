# Catalogs and Anthologies

When considering a group or collection of related items, we see two main possibilities.

## Catalogs

One way is sort of like a library: a whole bunch of different titles, some perhaps related and other less so.
Before the Internet, real-world libraries often used a "card catalog" to index the collection.
So, for this sort of collection in Magic Cap, we name it a "Catalog".

In this analogy, the "title" corresponds to the [Identifier](./locations.md) and the result is the ciphertext and associated metadata for the Read Cap (or Verify Cap) the Identifier is derived from.

Using the CLI, the top-level `--catalog` option configurs Catalogs to use.

## Anthologies

Another kind of collection is when we have two or more tightly-related items.
For example, a collection of pictures to share with friends.
Or a group of HTML, CSS and images that comprise a Web site or blog post.
The sort of thing one might typically use a Zip file for.

We name this sort of collection an "Anthology" to stay with the book analogy: several related books or stories or poems are collected together in a single anthology.

An Anthology in Magic Cap is essentially just a list of names and an associated Read Cap.
That is, a "Anthology Read Cap" is just a normal Read Cap with its contents being in a particular format which refers to other Read Caps.
All the Data for a single Anthology should usually be located in a single Catalog.

The CLI has a `mcap anthology` sub-command group to create and list Anthologies.
