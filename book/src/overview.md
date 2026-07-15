# Magic Cap Overview

**Storage is *boring*** &mdash; and we aim to **keep it that way**.

Magic Cap keeps private information encrypted and gives you simple tools to control access.

No accounts, no identities, safely store user data on untrusted providers.

Written in Rust, we provide libraries to read and write data from various sources and a command-line tool for experimentation.

> [!CAUTION]
> This is a release-early library that has **not yet received cryptographic (or other) audits**.
> We do appreciate feedback, but you own both pieces if you deploy to production :)

We can ignore most details and look at the high-level view of this tool as two diagrams.
Encrypting:

![overview diagram of magic-cap turning plaintext into encrypted data + a read-capability](./diagrams/mcap-encrypt.svg)

Decrypting:

![overview diagram of magic-cap turning Data + Read Cap back into plaintext](./diagrams/mcap-decrypt.svg)

There is a less-powerful "Verify Cap" that cannot see the plaintext but can confirm all the ciphertext is available and correct:

![diagram of magic-cap Verify Cap confirming the validity of ciphertext](./diagrams/mcap-verify.svg)

Note that the Verify Cap cannot decrypt anything.


## Capabilities <i style="font-size: 75%">Without Accounts</i>

Plaintext is transformed into an encrypted Data and a corresponding Read Cap.
A Read Cap may be transformed (offline) into a Verify Cap.
The size of the Data is a few percent larger than the plaintext.
Read and Verify Caps look like this:

```
mcap0r3LsgJf1LYZtRc_BGOzhx8j_FVDmFROmoBhDHGNTfXq8EAnU9NkykdwXfOg6VdQ7v
mcap0v3LsgJf1LYZtRc_BGOzhx8j_FVDmFROmoBhDHGNTfXq8
```

Anyone with both a Read Cap and the corresponding Data can turn it back into the plaintext.

Anyone with both a Verify Cap and the corresponding Data can confirm the ciphertext is correct and well-formed (but cannot see the plaintext)

This allows many use-cases, facilitating direct peer interactions since no server interaction is needed to create, transform or share Read Caps (or Verify Caps).

Magic Cap is inspired by the core ideas of "capability theory" embedded in Tahoe-LAFS.

Magic Cap currently implements two kinds of "data capabilities" (or "Caps" for short).

Immutable Read Cap
  : can be exchanged for the plaintext (alongside a corresponding Data)

Immutable Verify Cap
  : used to check whether a corresponding Data is valid (but not see the plaintext)

Plaintext is transformed into two pieces: encrypted Data and an associated Read Cap.
Re-combining these two pieces later allows the software to recover the plaintext.
The Read Cap is a short string (approximately 73 bytes).
The size of the encrypted Data is the same as the plaintext (plus a little overhead)

Where and how the Data is stored, moved or transmitted is up to the application.
Similarly, where and how the Read Cap is kept is up to the application -- its small size allows for storage in TPM or other secure storage or even printed out or transcribed hard-copy.

This gives users of this library a lot of choice, while keeping the core concepts straightforware to reason about.


## Networking

Although we have a couple ideas embedded in the command-line application currently, how to store and fetch Data is very open-ended (on purpose).
This allows many different uses and experimentation.

It is also possible to layer additional access controls on top, if your threat-model or use-case demands that.
For example, Data may be on an SSH-accessible server accessed via keys or passwords.
One may use S3 to store data, taking advantage of additional IAM services -- or not!

The current methods built-in to the command-line tool are:

Local Files
   : Data is stored on the file-system, with familiar permissions-based read/write access-controls

HTTP ReST-like API
   : The ``mcap publish`` subcommand can export local filesystem data into a format suitable for direct access via HTTP, simulating a proof-of-concept ReST-style API that can be statically-hosted.

See the "[Hands-On Examples](./hands-on.md)" section for more.


## Use Case Examples

Note that these are ideas about how this technology might be used.

We haven't built these applications, and highly recommend developing your own security model.


### Traditional App

Lots of application need to store user data.
A common pattern is to host the data on servers the application operators or developers control (e.g. Amazon S3).

Traditionally, these same developers have access to all of this data.

Using Magic Caps allows this user data to be truly private to the user -- the "Data" piece is stored on the servers, while the Read Cap is stored on user-controlled secure storage (e.g. the TPM of a smartphone or an encrypted hard-drive of a laptop).

(Read about "Verify Caps" that allow the service to confirm data integrity without having access to the plaintext).


### Timed Release of Large Digital Artifact (game, movie)

You have a multi-gigabyte digital artifact to release at a particular time.

Using Magic Caps, you can do this:

1. Encrypt the artifact, producing the large Data file and small Immutable Read Cap string
1. Upload the large Data file to any storage system you like (Web server, Torrent)
1. Instruct fans or users to download the Data

Then, when the actual release time arrives, you distribute the Read Cap string (via email, text, SMS, Signal, a Web site update).

This separates the distribution from the actual "release", reducing server bandwidth requirements, etc.


### Shared Organizational Data

An organazation often has lots of data, often with different visibility requirements.

A system centered around Magic Caps (along with the Catalog and Anthology concepts) could allow members of the organization to carry offline copies of all the data while only allowing access to particular pieces of it.

While Magic Cap itself has no concept of identity or users, application developers may layer this on top.

So, members of an organzation could all have a complete copy of all organization Data items (and keep in sync periodically via rsync or similar).

Since all these Data items are encrypted, members need a Read Cap to actually decrypt any of them.
Thus, particular members could be given Read Caps as they require them.
(Using the Anthology concept makes it easier to share many items with one Read Cap instead of many).


## Next Steps

This tool can be used via the available CLI, which exposes **most** of the Rust library functionality.

In the next sections, we explore more of the details and how to access them via the CLI.
