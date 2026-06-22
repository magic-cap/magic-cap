# Command Line Interface

To allow rapid experimentation with this library, many aspects of it are exported via the `mcap` CLI tool.

This is a sub-command based tool.
There are a few top-level options and several sub commands (even some "sub-sub commands").

## Common Top-Level Options

These options apply to every command.


## Core Functionality

The main thing this library does is encrypt and later decrypt data.

`mcap encrypt`
  : Turn plaintext into the ciphertext Data and a Read Cap. We need somewhere to write the Data; the Read Cap is printed to `stderr` (in case you chose to write the Data to `stdout` instead of a file or [Catalog](./catalog-anthology.md)).
