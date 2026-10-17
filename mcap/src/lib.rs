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

use tracing::debug;

use magic_cap::err::MagicCapError;
/// Functions that implement the core CLI commands
use magic_cap::{
    Immutable, ImmutableBuilder, ImmutableCatalog, ImmutableDirectoryCatalog, ImmutableIdentifier,
    ImmutableMetadata, ImmutableReadCap, ImmutableVerifier, ImmutableVerifyCap,
    ImmutableWebCatalog, ReadCap,
};
use reqwest::header::HeaderMap;
use std::error::Error;
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
    output: &mut impl Write, // where we write the Magic Cap string
    plain_text: &Path,       // input data
    catalogs: &mut Vec<Box<dyn ImmutableCatalog<'_>>>,
    blocksize: usize,
) -> Result<(), MagicCapError> {
    let mut input_file = std::fs::File::open(plain_text)?;

    // file format version 1 is:
    // 4 bytes: "mcap"
    // 4 bytes: 0x01  (the version number, big-endian)
    // <all the ciphertext blocks>
    // <meta_offset>: <metadata>
    // 8 bytes: u64 meta_offset to start of metadata

    // XXX FIXME how do we choose _which_ catalog to use??
    if catalogs.len() != 1 {
        return Err(MagicCapError::GenericError(
            "We need exactly one Catalog".to_string(),
        ));
    }
    let mut cryptor: ImmutableBuilder<BufWriter<File>> = catalogs[0].insert(blocksize)?;

    // todo: do we we want a way to do stdout (or maybe arbitrary
    // file) output..?
    //
    // (having _just_ stdout would solve this, if you redirect to a
    // file .. and then we write the cap-string to stderr??)
    /*
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

        let capstr = format!("{cap}");
        writeln!(output, "{capstr}")?;
        return Ok(());
    };
     */

    let mut plaintext: Vec<u8> = vec![0u8; blocksize];

    let mut r = input_file.read(&mut plaintext)?;
    while r != 0 {
        plaintext.resize(r, 0);
        let _ = cryptor.write(&plaintext)?;
        r = input_file.read(&mut plaintext)?;
    }
    let (cap, _) = cryptor.done()?;

    let capstr = format!("{cap}");
    writeln!(output, "{capstr}")?;
    Ok(())
}

//static default_catalog: PathBuf = PathBuf::from("~/.magicap");

/// "mcap decrypt"
/// accepts one readcap 'decryption key', four vectors of sources for encrypted data, and an outfile Option.
/// if outfile is None, write to standard output.
/// if the vectors are not empty, search each of them in order for matching encrypted data.
pub fn main_decrypt(
    readcap: &ImmutableReadCap,
    catalogs: &Vec<Box<dyn ImmutableCatalog>>,
    outfile: &Option<PathBuf>,
) -> Result<(), MagicCapError> {
    // decrypt to a file or stdout?
    let mut output: Box<dyn Write> = if let Some(output_file) = outfile {
        debug!("creating output_file {:?}", output_file);
        Box::new(std::fs::File::create(output_file).unwrap()) as Box<dyn Write>
    } else {
        debug!("output to stdout");
        Box::new(std::io::stdout()) as Box<dyn Write>
    };

    let id: ImmutableIdentifier = readcap.into();

    for catalog in catalogs {
        if let Ok(mut imm) = catalog.stream(&id) {
            let mut block: Vec<u8> = vec![0u8; imm.metadata.block_size as usize];
            let mut decryptor = readcap.decrypt_stream(&imm.metadata, &mut output)?;
            for i in 0..imm.metadata.blocks as usize {
                imm.data_provider.get_block(i, &mut block)?;
                decryptor.write_all(&block)?;
            }
            return Ok(())
        }
    }

    Err(MagicCapError::GenericError(
        format!(
            "Failed to find corresponding Data in {} Catalogs",
            catalogs.len(),
        )
    ))
}

fn cap_match(
    output: &mut impl Write,
    cap: &ImmutableReadCap,
    immutable: Result<Immutable<'_>, MagicCapError>,
) -> Result<(), MagicCapError> {
    match cap.decrypt(&mut immutable?) {
        Ok(plain) => Ok(output.write_all(plain.as_slice())?),
        Err(e) => match &e {
            MagicCapError::McapMetadataDiscordant() => Err(e),
            _ => {
                writeln!(output, "Error decrypting: {e}")?;
                Ok(())
            }
        },
    }
}

/// "mcap verify"
pub fn main_verify(capstr: &str, catalogs: &mut Vec<Box<dyn ImmutableCatalog<'_>>>) -> Result<(), MagicCapError> {
    // if we are given a "Read Cap" then we can still convert it to a
    // Verify Cap for the user, so lets do that .. but if this string
    // is neither a Read Cap _nor_ a Verify Cap then we error out via
    // the "?" inside the match
    let cap: ImmutableVerifyCap = match ImmutableVerifyCap::try_from(capstr) {
        Err(_) => ImmutableReadCap::try_from(capstr)?.into(),
        Ok(cap) => cap,
    };

    // we have a verify-cap, load all the data and verify
    // todo: should be able to stream this instead
    // todo: support "--catalog" for finding the ciphertext
    let id: ImmutableIdentifier = cap.clone().into();
    for catalog in catalogs {
        if let Ok(mut imm) = catalog.stream(&id) {
            return cap.verify(&mut imm);
        }
    }
    Err(MagicCapError::GenericError("Could not find corresponding Data".to_string()))
}

/// "mcap reduce"
pub fn main_reduce(output: &mut impl Write, cap: &str) -> Result<(), MagicCapError> {
    if let Ok(readcap) = ImmutableReadCap::try_from(cap) {
        let verifycap = ImmutableVerifyCap::from(readcap);
        writeln!(output, "{verifycap}")?;
    } else if let Ok(verifycap) = ImmutableVerifyCap::try_from(cap) {
        writeln!(output, "{verifycap}")?;
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
    writeln!(stdout, "publish {catalog:?} to {output:?}")?;
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
    for entry in walker.into_iter().filter_map(Result::ok) {
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
pub fn main_debug_locator(readcap: &ImmutableReadCap) -> Result<(), MagicCapError> {
    let id: ImmutableIdentifier = readcap.into();
    println!("{id}");
    Ok(())
}

/// "mcap debug info"
pub fn main_debug_info(
    readcap: &ImmutableReadCap,
    catalog: &Option<PathBuf>,
) -> Result<(), MagicCapError> {
    if !catalog.is_some() {
        return Err(MagicCapError::GenericError(
            "Need a catalog to find readcap metadata".to_string(),
        ));
    }
    let catalog = ImmutableDirectoryCatalog::create(catalog.clone().unwrap())?;

    let id: ImmutableIdentifier = (readcap).into();
    let imm = catalog.load(&id)?;
    let meta = imm.metadata;
    println!("location-id: {id}");
    println!(" block-size: {}", meta.block_size);
    println!("      bytes: {}", meta.size);
    println!("     blocks: {}", meta.blocks);
    println!("encrypted metadata:");
    let secret_meta = meta.secret_metadata(readcap);
    for (k, v) in secret_meta.data {
        println!("  {k:>20}: {v}");
    }
    Ok(())
}

pub struct AnthologyEntry {
    name: String,
    cap: ImmutableReadCap,
}

//todo: something like?
//pub fn create_anthology(entries: Vec<AnthologyEntry>) -> Result<dyn Read>;

/// "mcap anthology create"
pub fn main_anthology_create(directory: &Path) -> Result<(), MagicCapError> {
    // need a catalog -- waiting for shapr's PR to "promote" it to top-level
    let mut catalog = ImmutableDirectoryCatalog::create(PathBuf::from("data/root"))?;

    if !directory.is_dir() {
        return Err(MagicCapError::GenericError(
            "Anthology is not a directory".to_string(),
        ));
    }

    // refactor into own function
    let mut anthology: Vec<AnthologyEntry> = vec![];

    for p in directory
        .read_dir()
        .expect("Cannot list directory")
        .flatten()
    {
        let t = p.file_type().expect("Cannot stat file");
        if t.is_file() {
            debug!("Encoding file {:?}", p.file_name());
            let mut builder = catalog.insert(4096).expect("Creating catalog entry");
            let mut path: std::path::PathBuf = directory.to_path_buf();
            path.push(p.file_name());
            let mut plaintext = std::io::BufReader::new(std::fs::File::open(path.clone()).unwrap());
            let written = std::io::copy(&mut plaintext, &mut builder).expect("Copy failed");
            let (cap, _) = builder.done().expect("Failed to finalize Immutable");
            eprintln!("{}: {} bytes", path.display(), written);
            anthology.push(AnthologyEntry {
                name: format!("{}", p.file_name().display()),
                cap,
            });
        }
    }

    if anthology.is_empty() {
        return Err(MagicCapError::GenericError("Empty Anthology".to_string()));
    }

    // refactor into its own function, probably
    let mut builder = catalog
        .insert(4096)
        .expect("Create catalog anthology entry");
    for entry in anthology {
        writeln!(builder, "{} {}", entry.cap, entry.name).expect("Writing anthology entry");
    }
    let (cap, _) = builder.done().expect("Failed to finalize Immutable");
    println!("{cap}");

    Ok(())
}

pub fn main_anthology_list(readcap: &ImmutableReadCap) -> Result<(), MagicCapError> {
    // need a catalog -- waiting for shapr's PR to "promote" it to top-level
    let catalog = ImmutableDirectoryCatalog::create(PathBuf::from("data/root"))?;

    let id: ImmutableIdentifier = readcap.clone().into();
    let mut anthology = catalog.load(&id)?;
    let plaintext = readcap.decrypt(&mut anthology)?;

    debug!("{:?}", anthology.metadata);
    for line in plaintext.lines().map_while(Result::ok) {
        debug!("{:?}", line);
        let two: Vec<&str> = line.split(' ').collect();
        if two.len() != 2 {
            return Err(MagicCapError::GenericError(
                "illegal line in Anthology".to_string(),
            ));
        }
        let name = two[1];
        println!("{name}");
    }

    Ok(())
}

// okay, thinking about this all in terms of Catalogs
//
// static config?
// - each catalog has petname
// - can be read-only or writable (e.g. no-creds HTTP is read-only)
// - probably countless other metadatas (ideally only in support of features)
//
// for the "read" / decrypt side it's easy: keep looking until you
// find the right Data. Tahoe-style. User might want:
// - priority order (first filesystems, then remote)
// - "no network"?
// - w/ named config: "--catalog foo" or "--catalog-ignore bar" for filtering (from the whole config'd list)
//
// for "write" / encrypt side it's a little more complex:
// - write to ALL configured Catalogs?
// - only to named-on-the-command-line ones?
// - (w/ named config that can be "--catalog foo")
// - default is the set ("default", )
// - if no catalog in static config named "default", the default is "one that makes sense on your system"
// - default-default is like "~/.config/magic-cap/default-catalog" or something?
// - (what's the crate that does platform-specific defaults for Rust?)

struct FileUrl {
    url: Url,
}
struct CatalogUrl {
    catalog_url: Url,
}
struct FileLocal {
    file_local: PathBuf,
}
struct CatalogLocal {
    catalog_local: PathBuf,
}

pub trait Locator {
    fn extract(
        &self,
        readcap: &ImmutableReadCap,
        output: &mut impl Write,
    ) -> Result<(), MagicCapError>;
}

impl Locator for FileUrl {
    fn extract(
        &self,
        readcap: &ImmutableReadCap,
        mut output: &mut impl Write,
    ) -> Result<(), MagicCapError> {
        let mut headers = HeaderMap::new();
        // read the last 8 bytes to get the metadata offset
        headers.insert("Range", "bytes=-8".parse().unwrap());
        let result = reqwest::blocking::Client::new()
            .get(self.url.clone())
            .headers(headers)
            .send()?;

        debug!("{:?}", result);
        let offset = result.bytes()?;
        let offraw: Vec<u8> = offset.into();
        let offslice: [u8; 8] = offraw.try_into().unwrap();
        let off: u64 = u64::from_be_bytes(offslice);
        debug!("bytes {:?} {:?}", offslice, off);

        // request the metadata bytes (note that we're also
        // reading the last-8-bytes but serde ignores that
        // successfully)
        headers = HeaderMap::new();
        headers.insert("Range", format!("bytes={off}-").parse().unwrap());

        let result = reqwest::blocking::Client::new()
            .get(self.url.clone())
            .headers(headers)
            .send()?
            .error_for_status()?;
        debug!("{:?}", result);
        let metadata_raw: Vec<u8> = result.bytes()?.into();
        debug!("{} bytes", metadata_raw.len());
        let mut mdbytes = metadata_raw.as_slice();
        let metadata: ImmutableMetadata = rmp_serde::decode::from_read(&mut mdbytes)?;
        debug!(
            "size={} blocks={} block_size={}",
            metadata.size, metadata.blocks, metadata.block_size
        );
        // does this readcap match this immutable?
        if !readcap.verify.corresponds_to(&metadata) {
            return Err(MagicCapError::McapMetadataDiscordant());
        }
        let mut decryptor = readcap.decrypt_stream(&metadata, &mut output)?;

        // skip the first 8 bytes, which are "mcap" + 32-byte version
        // TODO: check those (version == 1 is the only one)
        headers = HeaderMap::new();
        headers.insert("Range", format!("bytes=8-{off}").parse().unwrap());
        let mut result = reqwest::blocking::Client::new()
            .get(self.url.clone())
            .headers(headers)
            .send()
            .unwrap();
        // streams the incoming data to the decryptor object
        let res = result.copy_to(&mut decryptor);

        // if the _output_ stream closes, then copy_to() will return a
        // BrokenPipe error .. but piping "mcap" output through "head
        // -n 10" will cause stdout to close, so we ignore this error
        let res = match res {
            Ok(x) => Ok(x),
            Err(e) => {
                if let Some(src) = &e.source()
                    && let Some(ee) = src.downcast_ref::<std::io::Error>()
                    && ee.kind() == std::io::ErrorKind::BrokenPipe
                {
                    debug!("ignoring BrokenPipe error");
                    return Ok(());
                }
                Err(e)
            }
        };
        res.unwrap();
        Ok(())
    }
}

impl Locator for CatalogUrl {
    fn extract(
        &self,
        readcap: &ImmutableReadCap,
        output: &mut impl Write,
    ) -> Result<(), MagicCapError> {
        debug!("before catalog create {}", self.catalog_url);
        let collect = ImmutableWebCatalog::create(self.catalog_url.clone())?;
        let tahoe_cap = readcap.clone();
        debug!("before readcap.into");
        let locid: ImmutableIdentifier = readcap.into();
        debug!("before fetch_metadata");
        let metadata = collect.fetch_metadata(&locid)?;
        let key = tahoe_cap.create_tahoe_key();
        debug!("before stream_push");
        let mut pusher = collect.stream_push(key, &metadata, output)?;
        collect.copy_ciphertext_to(&locid, &mut pusher)?;
        Ok(())
    }
}

impl Locator for FileLocal {
    fn extract(
        &self,
        readcap: &ImmutableReadCap,
        output: &mut impl Write,
    ) -> Result<(), MagicCapError> {
        let f = std::fs::File::open(self.file_local.clone())?;
        let immutable = Immutable::read(&mut std::io::BufReader::new(f));

        cap_match(output, readcap, immutable)
    }
}
impl Locator for CatalogLocal {
    fn extract(
        &self,
        readcap: &ImmutableReadCap,
        output: &mut impl Write,
    ) -> Result<(), MagicCapError> {
        let collect = ImmutableDirectoryCatalog::create(self.catalog_local.clone())?;
        let locid: ImmutableIdentifier = readcap.into();
        debug!("Loading location {}", locid);
        let immutable = collect.load(&locid);
        cap_match(output, readcap, immutable)
    }
}
