# Hands-On Examples

Once you have the software installed and working, it can be useful to explore the CLI directly.

All the examples below assume you've:

- used ``git clone`` (or [Jujutsu](https://docs.jj-vcs.dev/latest/) as we do) to obtain the source;
- used ``cargo build`` to compile it;
- and thus ``cargo run`` to operate the "mcap" command-line tool.

Run all examples from the root of the above directory, using example Data and other things from the repository.

If all the above works, you should be able to run the help:

```bash
$ cargo run -- --help
        ┏┳┓┏━┓┏━╸╻┏━╸        ┏━╸┏━┓┏━┓
O------ ┃┃┃┣━┫┃╺┓┃┃    ---   ┃  ┣━┫┣━┛ ------O
        ╹ ╹╹ ╹┗━┛╹┗━╸        ┗━╸╹ ╹╹

Create, read and verify Magic Cap strings and encrypted data.

Data is a file containing encrypted data and associated metadata.

A Read Cap is a string containing secret information to decrypt a corresponding Data.

A Verify Cap has only the power to confirm that the data is correct.
Any Read Cap may be turned into a Verify Cap offline.

Anyone with both the Data and corresponding Read Cap may re-create the plaintext.


Usage: mcap [OPTIONS] [COMMAND]

Commands:
  encrypt    turn plaintext into a Read Cap + ciphertext
  decrypt    turn a Read Cap + ciphertext into plaintext
  verify     Confirm a ciphertext is valid
  reduce     Turn a Read Cap into a less-powerful Verify Cap
  publish    Turn a disc Catalog into one suitable for static hosting (as the REST API).
  debug      Debugging tools. Be careful copy-pasting any of these from untrusted sources
  anthology  Tools to create and manipulate Anthologies
  help       Print this message or the help of the given subcommand(s)

Options:
  -l, --loglevel <LOGLEVEL>  ERROR, WARN, INFO, DEBUG, TRACE in that order [default: INFO]
  -h, --help                 Print help
  -V, --version              Print version

```


## Basic Decryption

Most of the commands read from a Catalog and there is an example in the root at `kitten-catalog/`.
Thus you'll want to include `--catalog ./kitten-catalog` for most commands.
(You can find a list of Read Caps encoded in this Catalog in the top-level README.org)

```bash
$ cargo run -- --catalog ./kitten-catalog decrypt mcap0rwedkkhZUU4LIEBS9VypVCYO6YQrVpkYhazyNtg16Kzhqt4pKhRGjXNLLEhdYG-vZ > brunnhilde.jpeg
$ display brunnhilde.jpeg
```

What is happening here is that the software is fetching the Data from a "Directory Catalog" source (``./kitten-catalog/``) and then using the Magic Cap to (attempt) decryption.
If this Data doesn't correspond to the Magic Cap, no decryption takes place.

> [!TIP]
> Explore the `kitten-catalog/` subdirectory: items are named according to their Identifier or Locator.
> Find the Locator for a Read Cap like so: ``cargo run -- debug locator mcap0rwedkkhZUU4LIEBS9VypVCYO6YQrVpkYhazyNtg16Kzhqt4pKhRGjXNLLEhdYG-vZ``
> Then see the Data with ``hexdump -C ./kitten-catalog/88/884ef78b37fd33ac3fa8f8e939ed68e8d4b35710908fddd411f4d2314cba66af``.


## Verification

We can turn the above Magic Cap into a less-powerful Verify Cap:

```bash
$ cargo run -- reduce mcap0r3LsgJf1LYZtRc_BGOzhx8j_FVDmFROmoBhDHGNTfXq8EAnU9NkykdwXfOg6VdQ7v
mcap0v3LsgJf1LYZtRc_BGOzhx8j_FVDmFROmoBhDHGNTfXq8
```

This Verify Cap (``mcap0v3LsgJf1LYZtRc_BGOzhx8j_FVDmFROmoBhDHGNTfXq8``) cannot decrypt ``kitten.mcap`` but can verify that all the ciphertext is there, and valid.
We can ask the software to do this:

```base
$ cargo run -- verify --ciphertext kitten.mcap mcap0v3LsgJf1LYZtRc_BGOzhx8j_FVDmFROmoBhDHGNTfXq8
$ echo $?
0
```

Notice that there's no output by default; the exit-code indicates success or failure.

**Exercise**: try changing some of the file and see if it still verifies correctly.


## Encryption on Publishers

The ``--catalog`` option is just for reading things.
When writing data, we use a Publisher.
Commands that require one have a required ``--publisher`` option.

When encoding Data, it will be written into the Catalog according to its "[Identifier](./locations.md)".
Similarly, Data is found by searching for the correct "[Identifier](./locations.md)".
The Identifier is deterministically derived from a Read Cap or a Verify Cap.

We encode the ``README.org`` file into a local Catalog at ``./data/root`` like this:

```bash
$ mkdir data/root
$ cargo run -- encrypt --publisher ./data/root README.org
mcap0rtKJjQeHHgPPzj5vFAX0-BqaZYAdMuvZtTHgLUyi6W2Ud8hzN7utr_1-8uVVt6M1d
```

Note that the Read Cap printed when you run this will be different because a random key is used.
Regardless, you should then be able to immediately decrypt this like this (substitute your own Read Cap of course):

```bash
$ cargo run -- decrypt --catalog ./data/root mcap0rtKJjQeHHgPPzj5vFAX0-BqaZYAdMuvZtTHgLUyi6W2Ud8hzN7utr_1-8uVVt6M1d
...
```

The original ``README.org`` contents should be printed.
If instead you see an error, check that you copy-pasted _your_ Magic Cap (which will be different from the example above).

**Exercise**: try encoding and decrypting other files. Try using ``mcap reduce`` to create Verify Caps from your Read Caps (and use ``mcap verify`` to confirm the Data can be found).

**Exercise**: use ``mcap debug id <magic-cap>`` to find the Identifier for your Magic Cap.
The find the file that corresponds to your Magic Cap inside ``./data/root``.
Hint: the first two characters are the directory.


## Remote / Hosted Catalogs

To facilitate network interactions, we've made some rudimentrary tools so you can export a local Catalog and host it (on any static Web host).

This is the ``mcap export`` tool, which transforms a local Catalog into a directory suitable for publishing.

```bash
$ cargo run -- export ./data/root data/published
export "./data/root" to "data/published"
  ./data/root/fc/fc8319d66125b6eaffbacb4ddcfe7d491844cb89e6ea38e0d8f8f6b3625801db: 12740 bytes, 00004 blocks.
```

Your output may differ; this shows that we had just a single Magic Cap in the Catalog when the above was run.
Looking at ``./data/published``:

```bash
$ find data/published
data/published/
data/published/fc8319d66125b6eaffbacb4ddcfe7d491844cb89e6ea38e0d8f8f6b3625801db
data/published/fc8319d66125b6eaffbacb4ddcfe7d491844cb89e6ea38e0d8f8f6b3625801db/metadata
data/published/fc8319d66125b6eaffbacb4ddcfe7d491844cb89e6ea38e0d8f8f6b3625801db/ciphertext
data/published/README
data/published/magic-cap-catalog
```

This intends to simulate the [ReST-Style Network API](./network-api.md) we've mocked up.
If you put the above Catalog at a static Web host, you can then pass that URL to ``--catalog``.

The ``fc9319...801db`` is an Identifier; we can't tell which Read Cap that derived from unless we also have that Read Cap (or its corresponding Verify Cap).
You may fetch the ``.../metadata`` or ciphertext blocks (``.../ciphertext``) for an Identifier.

The root-level ``README`` and ``magic-cap-catalog`` JSON explain what this directory contains.


> [!TIP]
> You should turn off directory-listing when hosting this.
> Failing to do so allows someone without any Magic Caps to determine how many items (and of what size) Data you are hosting in the Catalog

