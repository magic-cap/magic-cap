//! # Magic Cap
//!
//! Provides low-level primitives for working with a "magic cap",
//! which is a small string (~70 bytes) that can be turned back into
//! the corresponding plaintext when presented alongside the correct
//! ciphertext.
//!
//! The repository README has diagrams <https://github.com/magic-cap/magic-cap>
//!
//! <div class="warning">
//! This is a release-early library that has <b>not yet received cryptographic (or other) audits</b>.
//! We do appreciate feedback, but you own both pieces if you deploy to production :)
//! </div>
//!
//! ## Overview
//!
//! Magic Cap turns the problem of having a lot of secret data
//! (e.g. Sintel.mp4) into a tiny problem of only a little (fixed)
//! amount of data ("the cap").
//!
//! The resulting (fixed, tiny) Magic Cap string can combined with the
//! data file for the secret data; either part by itself cannot learn
//! the secret data.
//!
//! The "Magic Cap" string is short (70 bytes) and can fit in TPMs or
//! other secure storage.  Any interesting uses come when thinking
//! about separating the Data (ciphertext + metadata) from the Magic
//! Cap in time or space or both.
//!
//! ## Using the Crate
//!
//! This crate contains a CLI. For the Rust library, see:
//! <https://docs.rs/magic_cap/latest/magic_cap/>
//!
//! Once built, you should have a binary called `mcap`, which
//! will display help by default. It has several subcommands.
//!
//! ### `mcap encrypt`
//!
//! General usage is `mcap encrypt --plaintext <filename> <ciphertext-filename>`.
//! For example:
//!
//! ```bash
//!    $ mcap encrypt --plaintext kitten.jpeg kitten.mcap
//!    mcap0r-Gshm9tyvjXDnfWpLWKMgjcK0AOdC-O12vvLW5rxeV7752pj2a2uogG4RpvMFS0g
//! ```
//!
//! The string it spits out to stdout is the "Read Cap". The encrypted Data will
//! be written to `kitten.mcap`. Later, you may decrypt them when presented together
//!
//! ### `mcap decrypt`
//!
//! Turn a Read Cap and Data back into plaintext. For example:
//!
//! ```bash
//!    $ mcap decrypt --cap mcap0r-Gshm9tyvjXDnfWpLWKMgjcK0AOdC-O12vvLW5rxeV7752pj2a2uogG4RpvMFS0g --ciphertext kitten.mcap --plaintext kitten.jpeg
//!    Wrote 306199 bytes of plaintext to "kitten.jpeg".
//! ```
//!
//! You may get an error if the Read Cap does not correspond to the given ciphertext and exit-code 2.
//!
//! ```bash
//!    $ mcap decrypt --cap mcap0rBX50S5FpIJQdu6cRr-bgGyxCzE9KHe46um1QcCfxn8PYZwX-X09Jv5I7vT1apgS6 --ciphertext kitten.mcap --plaintext kitten.jpeg
//!    Error: Magic Cap does not correspond to Metadata hash
//! ```
//!
//! ### `mcap reduce`
//!
//! Turn a Read Cap into a Verify Cap. A Verify Cap can confirm that a
//! Data file is not corrupt and contains the correct ciphertext, but
//! may not decrypt it. This could be used by a service provider or
//! other third party to monitor or confirm availability of data
//! without knowing what that data is.
//!
//! ```bash
//!    $ mcap reduce mcap0r-Gshm9tyvjXDnfWpLWKMgjcK0AOdC-O12vvLW5rxeV7752pj2a2uogG4RpvMFS0g
//!    mcap0v-Gshm7tyvjXDnfWpLWKMgjcK0AOdC-O12vvLW5rxeV4
//! ```
//!
//! ### `mcap verify`
//!
//! Uses a Verify Cap to confirm that a Data file corresponds to it
//! (and thus could be correctly decrypted by whomever has the Read
//! Cap).
//!
//! ```bash
//!    $ mcap verify --cap mcap0v-Gshm9tyvjXDnfWpLWKMgjcK0AOdC-O12vvLW5rxeV4 --ciphertext kitten.mcap
//! ```
//!
//! (No output is good). An error may be printed (with exit code 2) if
//! the Verify Cap does not correspond.
//!
//! ```bash
//!    $ mcap verify --cap mcap0vBX50S5FpIJQdu6cRr-bgGyxCzE9KHe46um1QcCfxn8M --ciphertext kitten.mcap
//!    Error: Magic Cap does not correspond to Metadata hash
//! ```
//!

use magic_cap::err::MagicCapError;
/// Functions that implement the core CLI commands
use magic_cap::{
    Immutable, ImmutableBuilder, ImmutableReadCap, ImmutableVerifier, ImmutableVerifyCap, ReadCap,
};
use std::fs::File;
use std::io::prelude::*;
use std::path::{Path, PathBuf};

/// Implementation of "mcap encrypt"
/// This is the top level function for easy use of this crate by applications or other libraries.
/// This function does not consider memory use, but instead just does the thing using all the memory.
pub fn main_encrypt(
    output: &mut impl Write,
    plain_text: &Path,
    output_fname: &Path,
) -> Result<(), MagicCapError> {
    let mut input_file = std::fs::File::open(plain_text)?;

    // "write as one file"
    // write "mcap"
    // write 4-byte version number (1?)
    // write all the ciphertext blocks
    // write the metadata
    // write 8-byte offset to metadata
    // done

    // file format version 1 is:
    // 4 bytes: "mcap"
    // 4 bytes: 0x01  (the version number, big-endian)
    // <all the ciphertext blocks>
    // <meta_offset>: <metadata>
    // 8 bytes: u64 meta_offset to start of metadata

    let output_file = File::create(output_fname)?;
    let mut bufw = std::io::BufWriter::new(output_file);

    let mut plaintext: Vec<u8> = vec![0u8; 4096];
    let mut cryptor = ImmutableBuilder::new(4096, &mut bufw)?;

    let mut r = input_file.read(&mut plaintext)?;
    while r != 0 {
        plaintext.resize(r, 0);
        let _ = cryptor.write(&plaintext)?;
        r = input_file.read(&mut plaintext)?;
    }
    let (cap, _) = cryptor.done()?;

    let capstr = format!("{}", cap);
    writeln!(output, "{}", capstr)?;
    Ok(())
}

/// "mcap decrypt"
pub fn main_decrypt(
    //    input: &mut impl Read,
    output: &mut impl Write,
    cap: &str,
    input_fname: &PathBuf,
    outfile: &Path,
) -> Result<(), MagicCapError> {
    let cap = ImmutableReadCap::try_from(cap)?;
    let f = std::fs::File::open(input_fname)?;
    let imm = Immutable::read(&mut std::io::BufReader::new(f))?;

    match cap.decrypt(&imm) {
        Ok(plain) => {
            let mut out = std::fs::File::create(outfile)?;
            out.write_all(plain.as_slice())?;
            match outfile.to_str() {
                Some(of) => {
                    writeln!(
                        output,
                        "Wrote {} bytes of plaintext to \"{}\".",
                        plain.len(),
                        of,
                    )?;
                    Ok(())
                }
                None => Ok(()),
            }
        }
        Err(e) => match &e {
            MagicCapError::McapMetadataDiscordant() => Err(e),
            _ => {
                writeln!(output, "Error decrypting: {}", e)?;
                Ok(())
            }
        },
    }
}

/// "mcap verify"
pub fn main_verify(cap: &str, input_fname: &Path) -> Result<(), MagicCapError> {
    let cap = ImmutableVerifyCap::try_from(cap)?;
    let f = std::fs::File::open(input_fname)?;
    let imm = Immutable::read(&mut std::io::BufReader::new(f))?;

    cap.verify(&imm)?;
    Ok(())
}

/// "mcap reduce"
pub fn main_reduce(output: &mut impl Write, cap: &str) -> Result<(), MagicCapError> {
    if let Ok(readcap) = ImmutableReadCap::try_from(cap) {
        let verifycap = ImmutableVerifyCap::from(readcap);
        writeln!(output, "{}", verifycap)?;
    } else if let Ok(verifycap) = ImmutableVerifyCap::try_from(cap) {
        writeln!(output, "{}", verifycap)?;
    } else {
        writeln!(output, "Unknown kind of cap.")?;
        return Err(MagicCapError::InvalidCap(cap.to_string()));
    }
    Ok(())
}

#[cfg(test)]
pub mod test {
    use super::*;
    use proptest::prelude::*;
    use tempfile::tempdir;

    proptest! {
        #[test]
        fn round_trip_main(s in "\\PC+") {
            // write to a file so we can exercise via paths
            let outd = tempdir()?;
            let plain = outd.path().join("plain");
            {
                let mut tmp = File::create(&plain)?;
                tmp.write(s.as_bytes())?;
            }  // close tmp
            let cipher = outd.path().join("cipher");
            let mut output = vec!();
            main_encrypt(&mut output, &plain, &cipher).unwrap();

            let capstr: &str = std::str::from_utf8(&output)?.trim_end();
            let round = outd.path().join("decrypted");

            // turn this into a Verify Cap and confirm the ciphertext
            let mut output = vec!();
            main_reduce(&mut output, capstr)?;
            let verifycap = std::str::from_utf8(&output)?.trim_end();
            main_verify(verifycap, &cipher).unwrap();

            // confirm that "decrypt" can turn back into plaintext
            let mut output = vec!();
            main_decrypt(&mut output, capstr, &cipher, &round).unwrap();

            let mut og = String::new();
            let mut other = String::new();
            File::open(plain)?.read_to_string(&mut og)?;
            File::open(round)?.read_to_string(&mut other)?;

            assert_eq!(og, other);
        }
    }
}
