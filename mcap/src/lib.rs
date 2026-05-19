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
    Immutable, ImmutableBuilder, ImmutableCatalog, ImmutableDirectoryCatalog, ImmutableIdentifier,
    ImmutableMetadata, ImmutableReadCap, ImmutableVerifier, ImmutableVerifyCap,
    ImmutableWebCatalog, ReadCap,
};
use reqwest::header::HeaderMap;
use std::fs::File;
use std::io::BufWriter;
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use url::Url;

use walkdir::WalkDir;

pub mod tests;

/// Implementation of "mcap encrypt"
/// This is the top level function for easy use of this crate by applications or other libraries.
/// This function does not consider memory use, but instead just does the thing using all the memory.
pub fn main_encrypt(
    output: &mut impl Write,
    plain_text: &Path,
    output_fname: &Option<PathBuf>,
    catalog: &Option<PathBuf>,
    blocksize: usize,
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

    let mut cryptor: ImmutableBuilder<BufWriter<File>> = if let Some(output_fname) = output_fname {
        let output_file = File::create(output_fname)?;
        ImmutableBuilder::new(blocksize, BufWriter::new(output_file), None)?
    } else if let Some(catalog) = catalog {
        let mut catalog = ImmutableDirectoryCatalog::create(catalog.clone())?;
        catalog.insert(blocksize)?
    } else {
        // no output file AND no catalog, so user wants ciphertext on stdout
        let stdio = std::io::stdout(); //.lock();
        let mut cryptor: ImmutableBuilder<std::io::Stdout> =
            ImmutableBuilder::new(blocksize, stdio, None)?;

        // FIXME: TODO: this "cryptor" is a different type than the
        // other "cryptor", because ImmutableBuilder has its "writer"
        // type as a generic -- so it's part of the type, and we can't
        // have one variable that points at ImmutableBuilder<File> OR
        // ImmutableBuilder<Stdio> .. using Box<dyn Write> gets rid of
        // the generic, but then the "consume / un-consume" pattern on
        // done() doesn't work .. see the "stream.rs" example for why

        let mut plaintext: Vec<u8> = vec![0u8; blocksize];

        let mut r = input_file.read(&mut plaintext)?;
        while r != 0 {
            // resize is here to remove bytes in case we don't read a block's worth of bytes
            // XXX wait, isn't this the *first* read? I don't think we need this here!
            plaintext.resize(r, 0);
            let _ = cryptor.write(&plaintext)?;
            r = input_file.read(&mut plaintext)?;
        }
        let (cap, _) = cryptor.done()?;

        let capstr = format!("{}", cap);
        writeln!(output, "{}", capstr)?;
        return Ok(());
    };

    //let mut bufw = BufWriter::new(output_file);

    let mut plaintext: Vec<u8> = vec![0u8; blocksize];

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

//static default_catalog: PathBuf = PathBuf::from("~/.magicap");

/// "mcap decrypt"
pub fn main_decrypt(
    //    input: &mut impl Read,
    output: &mut impl Write,
    cap: &str,
    catalog: &Option<PathBuf>,
    catalog_url: &Option<Url>,
    input_fname: &Option<PathBuf>,
    input_url: &Option<Url>,
    outfile: &Option<PathBuf>,
) -> Result<(), MagicCapError> {
    if input_fname.is_some() && input_url.is_some() {
        todo!();
        // similar to below, use type system to say "either PathBuf OR Url"
    }
    if catalog.is_some() && input_fname.is_some() {
        // could be error, could say "if filename doesn't exist then use catalog"
        //
        // take a Enum in here that is a Catalog OR a input_fname OR catalog-url
        // so we can only do one
        todo!();
    }
    let cap = ImmutableReadCap::try_from(cap)?;

    if let Some(url) = input_url {
        let mut headers = HeaderMap::new();
        // read the last 8 bytes to get the metadata offset
        headers.insert("Range", "bytes=-8".parse().unwrap());
        let result = reqwest::blocking::Client::new()
            .get(url.clone())
            .headers(headers)
            .send();

        if let Ok(result) = result {
            //println!("{:?}", result);
            let offset = result.bytes()?;
            let offraw: Vec<u8> = offset.into();
            let offslice: [u8; 8] = offraw.try_into().unwrap();
            let off: u64 = u64::from_be_bytes(offslice);
            //println!("bytes {:?} {:?}", offslice, off);

            // request the metadata bytes (note that we're also
            // reading the last-8-bytes but serde ignores that
            // successfully)
            headers = HeaderMap::new();
            headers.insert("Range", format!("bytes={}-", off).parse().unwrap());

            let result = reqwest::blocking::Client::new()
                .get(url.clone())
                .headers(headers)
                .send()?;
            //println!("{:?}", result);
            let metadata_raw: Vec<u8> = result.bytes()?.into();
            //println!("{} bytes", metadata_raw.len());
            let mut mdbytes = metadata_raw.as_slice();
            let metadata: ImmutableMetadata = rmp_serde::decode::from_read(&mut mdbytes)?;
            //println!("size={} blocks={} block_size={}", metadata.size, metadata.blocks, metadata.block_size);

            // now we request 'all the rest of the bytes' and stream
            // them into the decryptor (which will write to the output
            // Write-able)
            let mut output = std::io::stdout().lock();
            let mut decryptor = cap.decrypt_stream(metadata, &mut output)?;

            // skip the first 8 bytes, which are "mcap" + 32-byte version
            // TODO: check those (version == 1 is the only one)
            headers = HeaderMap::new();
            headers.insert("Range", format!("bytes=8-{}", off).parse().unwrap());
            let mut result = reqwest::blocking::Client::new()
                .get(url.clone())
                .headers(headers)
                .send()
                .unwrap();
            // streams the incoming data to the decryptor object
            result.copy_to(&mut decryptor)?;
            return Ok(());
        }
    }

    // TODO FIXME early return
    if let Some(root_url) = catalog_url {
        let collect = ImmutableWebCatalog::create(root_url.clone())?;
        let locid: ImmutableIdentifier = (&cap).into();
        let mut output = std::io::stdout().lock();
        let metadata = collect.fetch_metadata(&locid)?;
        let key = cap.create_tahoe_key();
        let mut pusher = collect.stream_push(key, metadata, &mut output)?;
        collect.copy_ciphertext_to(&locid, &mut pusher)?;
        return Ok(());
    }

    let immutable = if let Some(input_fname) = input_fname {
        let f = std::fs::File::open(input_fname)?;
        Immutable::read(&mut std::io::BufReader::new(f))
    } else if let Some(root) = catalog {
        let collect = ImmutableDirectoryCatalog::create(root.clone())?;
        let locid: ImmutableIdentifier = (&cap).into();
        tracing::info!("Loading location {}", locid);
        collect.load(&locid)
    } else {
        Err(MagicCapError::GenericError(
            "Must provide either --ciphertext or --catalog or --catalog-url".to_string(),
        ))
    };

    match cap.decrypt(&mut immutable?) {
        Ok(plain) => {
            if let Some(outfile) = outfile {
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
            } else {
                let mut out = std::io::stdout();
                out.write_all(plain.as_slice())?;
                Ok(())
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
    let mut imm = Immutable::read(&mut std::io::BufReader::new(f))?;

    cap.verify(&mut imm)?;
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

/// "mcap publish"
pub fn main_publish(
    stdout: &mut impl Write,
    catalog: &PathBuf,
    output: &PathBuf,
) -> Result<(), MagicCapError> {
    writeln!(stdout, "publish {:?} to {:?}", catalog, output)?;
    if output.exists() {
        return Err(MagicCapError::GenericError(format!(
            "\"{}\" already exists",
            output.display()
        )));
    }

    std::fs::create_dir(output.as_path())?;
    {
        // tell passers-by what this directory is for
        let mut readme = output.clone();
        readme.push("README");
        let mut readme = std::fs::File::create(readme.as_path())?;
        readme.write_all(b"This is a Catalog published by Magic Cap\n")?;
    }
    {
        // tell programs what this basedir is for
        let mut catalogmeta = output.clone();
        catalogmeta.push("magic-cap-catalog");
        let mut catalogmeta = std::fs::File::create(catalogmeta.as_path())?;
        catalogmeta.write_all(b"{\"version\": 0}")?;
    }

    let walker = WalkDir::new(catalog);
    for entry in walker.into_iter().filter_map(|e| e.ok()) {
        if entry.metadata().unwrap().is_file() {
            let mut r = std::io::BufReader::new(std::fs::File::open(entry.path())?);
            let mut imm = Immutable::stream(&mut r)?;
            let mut published = output.clone();
            let id: ImmutableIdentifier = (&imm).into();
            let id: String = id.into();
            published.push(id);
            //let published = magic_cap::add_identifier(&published, &id);
            write!(
                stdout,
                "  {}: {} bytes",
                entry.path().display(),
                imm.metadata.size,
            )?;
            std::fs::create_dir_all(published.clone())?;
            // just assume version == 0 for now .. could put a "version" file with 0u32 in it?
            // (add ".version" to ImmutableMetadata?

            // write the metadata to "/metadata"
            {
                let mut meta = published.clone();
                meta.push("metadata");
                let mut meta = std::fs::File::create(meta.as_path())?;
                imm.metadata.write(&mut meta)?;
                write!(stdout, ", ")?;
            }

            stdout.write_all(b"      blocks")?;
            // write the blocks to "/ciphertext"
            {
                let mut blocks = published.clone();
                blocks.push("ciphertext");
                let mut blocks = std::fs::File::create(blocks.as_path())?;
                let mut block = vec![0u8; imm.data_provider.block_size() as usize];
                for block_num in 0..imm.data_provider.total_blocks() {
                    imm.data_provider
                        .get_block(block_num, block.as_mut_slice())?;
                    blocks.write_all(block.as_slice())?;
                    // \x08 is backspace "BS" raw character
                    stdout.write_all(
                        format!(
                            "\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08{:05} blocks",
                            block_num + 1
                        )
                        .to_string()
                        .as_bytes(),
                    )?;
                }
            }
            stdout.write_all(b".\n")?;
        }
    }
    Ok(())
}

/// "mcap debug locator"
pub fn main_debug_locator(capstr: &str) -> Result<(), MagicCapError> {
    if let Ok::<ImmutableReadCap, _>(cap) = capstr.try_into() {
        let id: ImmutableIdentifier = cap.into();
        println!("{}", id);
    }
    Ok(())
}
