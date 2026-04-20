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
//! A "Magic Cap" is represented by the struct [`ImmutableReadCap`]
//! in Rust code.  This implements [`Display`] and [`From`] for
//! converting to the human-usable strings, which are UTF8 characters
//! with URL-safe Base64 encoded data which looks like this:
//!
//!    `mcap0r1EmWRHtNLvG4J2xkLZ2Qd3GFcwRXJfxJ2X40xj8nJac5U7RTaKClMp1YsJXPMw47w`
//!
//! Breaking this down, we have:
//!
//! - `mcap` -- all Magic Caps start with this
//! - `0` -- a version identifier (only "0" exists, and is **not yet stable**)
//! - `r` -- the kind of Cap this is ("r" for Read and "v" for Verify are valid for version 0)
//! - rest is url-safe base64 encoded binary data, dependant on the version
//!
//! The entire Magic Cap should be treated as a secret -- because it is!
//! It is an identifier you can later use to retrieve the original
//! plaintext (and share offline, etc -- more on those features later)
//!
//! There is a reduced-power string called a Verify Cap which can be
//! directly derived from the Read Cap (offline, with no server
//! interaction). This Verify Cap can confirm that the ciphertext is
//! valid, and could be decrypted by the Read Cap but cannot itself
//! see any of the data. These look like:
//!
//!    ``mcap0v-Gshm9tyvjXDnfWpLWKMgjcK0AOdC-O12vvLW5rxeV4``
//!
//! Notice the ``v`` instead of ``r`` at the start of the string.
//!
//! ## Examples
//!
//! One way to create an [`ImmutableReadCap`] is to stream plaintext
//! to it using the [`Write`] trait to an [`ImmutableBuilder`]. For
//! example:
//!
//! ```rust
#![doc = include_doc::source_file!("examples/stream.rs")]
//! ```
//!
//! Another way is to create a completely in-memory [`Immutable`] and
//! corresponding [`ImmutableCap::Read`]. This example also
//! demonstrates using the [`ImmutableVerifyCap`] to verify the
//! ciphertext.
//!
//! ```rust
#![doc = include_doc::source_file!("examples/in-memory.rs")]
//! ```
//!

mod catalog;
pub mod err;

#[cfg(test)] // can we put this "inside" test.rs instead somehow?
mod test;

// todo: re-export some stuff from catalog
pub use catalog::ImmutableCatalog;
pub use catalog::ImmutableDirectoryCatalog;
pub use catalog::ImmutableIdentifier;

// why can't we use KeyInit ?!
use aes::cipher::{KeyIvInit, StreamCipher}; // we'll need StreamCipherSeek for random access decryption
use data_encoding::BASE64URL_NOPAD;
use rs_merkle::{Hasher, MerkleTree};
use serde::ser::Serialize;
use sha2::{Digest, Sha256};

use std::convert::Into;
use std::convert::TryInto;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::BufWriter;
use std::io::prelude::*;

use err::MagicCapError;

/// Produce a "tagged hash" by concatenating a netstring of the tag
/// with the value, and applying SHA256d to the result. [^tahoe]
///
/// [^tahoe]: This is the same way Tahoe-LAFS does it.
fn tagged_hash<const TAGSIZE: usize>(tag: &[u8], val: &[u8]) -> [u8; TAGSIZE] {
    // todo: Chris' code had "truncate_to" as an arg ... and then we
    // wnated to do that as const-generics ... but "sha256d" _is_ just
    // always 32 bytes so what does the truncate_to even do?
    // tagged_hash<16>
    const {
        assert!(TAGSIZE <= 32, "illegal tag size");
    }
    let mut hasher = Sha256::new();
    hasher.update(netstring(tag));
    hasher.update(val);
    let hash = hasher.finalize();
    let hash2 = Sha256::digest(hash);
    let mut rtn: [u8; TAGSIZE] = [0u8; TAGSIZE];
    rtn.copy_from_slice(&hash2[0..TAGSIZE]);
    rtn
}

/// Produce a "netstring" from the provided slice, which prepends a
/// length and appends a comma. That is, the "netstring" version of
/// ``"foo"`` is ``"3:foo,"`` [^djb97]
///
/// [^djb97]: <https://cr.yp.to/proto/netstrings.txt>
fn netstring(s: &[u8]) -> Vec<u8> {
    //format!("{}:{},", s.len(), std::str::from_utf8(s).unwrap()).into_bytes()

    // what Python does is output BYTES here, where we have some
    // number of ASCII-numeral bytes that represent the length, then a
    // ':' byte, and then 32 arbitrary bytes of key
    let tag = format!("{}:", s.len());
    // stuff two byte-sequences together; better way?
    [tag.as_bytes(), s, b","].concat()
}

// from binrw-tahoe experiments -- mirroring the Tahoe way of
// using tagged hashes for merkel nodes, with different tags for
// leaves vs. interior vs. empty nodes.
#[derive(Clone)]
/// Marker struct for Merkle Tree nodes that are leaves
struct TahoeLeaf {}

#[derive(Clone)]
/// Marker struct interior Merkle Tree nodes
struct TahoeInside {}

impl Hasher for TahoeLeaf {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> [u8; 32] {
        //why not "Hash" as return type?
        //let mut engine = sha256d::Hash::engine();
        //engine.input(data);
        //sha256d::Hash::from_engine(engine).to_byte_array()
        let hash = tagged_hash::<32>(b"allmydata_crypttext_segment_v1", data);
        let mut ret = [0; 32];
        ret.copy_from_slice(hash.as_slice());
        ret
    }

    /*
    fn concat_and_hash(left: &Self::Hash, right: Option<&Self::Hash>) -> Self::Hash {
    match right {
    //Some(r) => Hasher::concat_and_hash::<[u8; 32]>(left, right),
    Some(r) => Hasher::concat_and_hash(left, right),
    None => panic!("Tahoe can't have an un-full tree")
    }
    }
     */
}

impl Hasher for TahoeInside {
    type Hash = [u8; 32];
    // we don't really want "generics, of u32 or str" etc we can just
    // add those as "things your Trait needs ot have"? is that the pattern?
    // a tahoe inside node in python is "tagged_pair_hash(constant, left_hash, right_hash)"
    // but the left and right hashes both get wrapped in a netstring()

    fn hash(data: &[u8]) -> [u8; 32] {
        //why not "Hash" as return type?
        // tahoe does netstring() of _each_ node's hash
        /*
        let net0: Vec<u8> = netstring(&data[0..32]);
        let net1: Vec<u8> = netstring(&data[32..64]);
        let netfinal = vec![net0, net1].concat();
         */
        let hash = tagged_hash::<32>(b"Merkle tree internal node", data);
        let mut ret = [0; 32];
        ret.copy_from_slice(hash.as_slice());
        ret
    }
}

type TahoeAesCtr = ctr::Ctr128BE<aes::Aes128>;

// ImmutableVerifyCap and ImmutableReadCap are morally-equivalent to
// the "capability-string" from Tahoe. e.g.
//     "URI:CHK:<key>:<ueb-hash>:<needed-shares>:<total-shares>:<size>"
// But we:
// - don't need needed-shares, we have 1
// - don't need total shares, we have 1
// - don't trust size (it leaks information and is redundant)

#[derive(Debug)]
pub enum ImmutableCap {
    Verify(ImmutableVerifyCap),
    Read(ImmutableReadCap),
}

pub trait ImmutableVerifier {
    fn verify(&self, immutable: &mut Immutable) -> Result<(), MagicCapError>;
}

pub trait ReadCap: ImmutableVerifier {
    fn decrypt(&self, immutable: &mut Immutable) -> Result<Vec<u8>, MagicCapError>;
    fn encrypt(
        plaintext: Vec<u8>,
        writer: BufWriter<File>,
        blocksize: usize,
    ) -> Result<ImmutableReadCap, MagicCapError>;
}

#[derive(Debug, PartialEq, PartialOrd, Clone)]
/// A Cap that is able to confirm the ciphertext is valid, but cannot
/// decrypt any of it.
///
/// You obtain one from a `ImmutableReadCap` or by parsing a valid
/// Verify Cap string.
///
/// For example:
///
/// ```rust
///    use magic_cap::{ImmutableReadCap, ImmutableVerifyCap};
///
///    let cap_string = "mcap0r-Gshm9tyvjXDnfWpLWKMgjcK0AOdC-O12vvLW5rxeV7752pj2a2uogG4RpvMFS0g";
///    let readcap: ImmutableReadCap = cap_string.try_into().unwrap();
///    let verifycap: ImmutableVerifyCap = readcap.into();
///    let verifycap_string = format!("{}", verifycap);
///    assert_eq!(
///        verifycap_string,
///        "mcap0v-Gshm9tyvjXDnfWpLWKMgjcK0AOdC-O12vvLW5rxeV4"
///    );
/// ```
///
pub struct ImmutableVerifyCap {
    metadata_hash: [u8; 32],
}

impl ImmutableVerifyCap {
    /// returns true IFF the hash of the passed metadata matches that
    /// in this VerifyCap
    pub fn corresponds_to(&self, immutable: &Immutable) -> bool {
        let h = ImmutableVerifyCap::from(&immutable.metadata);
        h.metadata_hash == self.metadata_hash
    }
}

impl ImmutableVerifier for ImmutableVerifyCap {
    /// returns true IFF the given ciphertext is valid (that is, the
    /// merkle tree of hashes of each block matches the root in the
    /// metadata). This traverses all the bytes of ciphertext (to hash
    /// them).
    fn verify(&self, immutable: &mut Immutable) -> Result<(), MagicCapError> {
        // before anything else, we check that the capability
        // corresponds to this Immutable ... by hashing the Metadata,
        // and confirming it matches the Cap's hash
        if !self.corresponds_to(immutable) {
            return Err(MagicCapError::McapMetadataDiscordant());
        }

        // can we use iterators more directly here instead of for loop? e.g.:
        let mut leaves: Vec<[u8; 32]> = vec![];
        for i in 0..immutable.data_provider.total_blocks() {
            let mut leaf = vec![0u8; immutable.data_provider.block_size() as usize];
            immutable.data_provider.get_block(i, &mut leaf)?;
            let lh = TahoeLeaf::hash(&mut leaf);
            leaves.push(lh);
        }
        fill_empty_merkle_leaves(&mut leaves);

        let merkle_tree = MerkleTree::<TahoeInside>::from_leaves(&leaves);
        let merkle_root = merkle_tree.root().ok_or(MagicCapError::MerkleError())?;

        // this checks that the _metadata_ from our metadata file
        // actually matches the ciphertext from our 'data' file (we
        // checked above that the user-supplied capability-string has
        // a matching root)
        if merkle_root != immutable.metadata.ciphertext_root {
            let incorrect_hash = BASE64URL_NOPAD.encode(&merkle_root);
            return Err(MagicCapError::CipherTextDiscordant(incorrect_hash));
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, PartialOrd, Clone)]
/// A Cap that is able to both verify the ciphertext and decrypt it
///
/// Use `Display` and `TryFrom` to convert to and from human-usable
/// rendintions of this data.
///
/// For example:
///
/// ```rust
///    use magic_cap::ImmutableReadCap;
///
///    let cap_string = "mcap0r-Gshm9tyvjXDnfWpLWKMgjcK0AOdC-O12vvLW5rxeV7752pj2a2uogG4RpvMFS0g";
///    let cap: ImmutableReadCap = cap_string.try_into().unwrap();
///    println!("The cap is: {}", cap);
/// ```
pub struct ImmutableReadCap {
    // "Read" adds on top of Verify: we always need to verify
    verify: ImmutableVerifyCap,

    // AES in CTR / Counter mode, with IV == 0 to start (for first
    // block) with 16-byte key and 16-byte IV + blocks.  ...we
    // actually want a ctr::Ctr128BE<aes::Aes128> here, but it
    // doesn't give us access to the key material -- so we save
    // JUST the key here, and create the AES-CTR on-demend for
    // encryption / decryption. Yes, keys are 16-bytes in Tahoe.
    key: [u8; 16], // used by: ctr::Ctr128BE<aes::Aes128>
}

// without Seek on the output, we require it on the input

type BuilderDoneCb = Box<dyn FnOnce(&ImmutableReadCap)>;

/// Manage context to incrementally encrypt to an underlying [`Write`]
///
/// Instances of this are used to build up an [`Immutable`] by writing
/// plaintext data to it, which is then encrypted and written out to
/// the underlying [`Write`] instance in ``writer``.
///
/// To retrieve the ``Immutable`` you must call ``done`` which
/// consumes the ``ImmutableBuilder`` and finalizes the metadata and
/// offsets in the output.
pub struct ImmutableBuilder<W>
where
    W: Write,
{
    context: EncryptionContext,
    output: W,
    this_block: Vec<u8>,
    ciphertext_bytes: usize,
    completed: Option<BuilderDoneCb>,
}

// feb 3: see the history: we have a version that takes a "&mut Write"
// reference, with a lifetime. It also works where we "consume" the
// Write on ::new(), and "un-consume" it when we're "done()" (like
// below). This gets rid of a lifetime, but we don't know which way is
// "idiomatic Rust".

impl<W> ImmutableBuilder<W>
where
    W: Write,
{
    // pub fn encrypt_stream(blocksize: usize, encrypted: Write) -> Result<ImmutableBuilder, MagicCapError> {
    // 1. write header to "encrypted"

    /// Create a new ``ImmutableBuilder`` which will write ciphertext
    /// to ``writer`` in chunks of size ``blocksize``.
    pub fn new(
        blocksize: usize,
        mut writer: W,
        completed: Option<BuilderDoneCb>,
    ) -> Result<Self, MagicCapError> {
        writer.write_all(b"mcap")?; // tag
        writer.write_all(&1u32.to_be_bytes())?; // version == 1

        let result = Self {
            context: EncryptionContext::new(blocksize)?,
            output: writer,
            this_block: Vec::with_capacity(blocksize),
            ciphertext_bytes: 0,
            completed,
        };
        Ok(result)
    }

    /// Finalize the metadata and return the resulting ``ImmutableReadCap``.
    ///
    /// No more data may be written after this (as the instance is
    /// consumed).
    pub fn done(mut self) -> Result<(ImmutableReadCap, W), MagicCapError> {
        // 1. if remaining buffered data, pad it + write final block
        // 2. write metadata
        // 3. ... profit?
        if !self.this_block.is_empty() {
            // make sure we "fill up" the final block and write it
            let leftover = self.context.blocksize - self.this_block.len();
            assert!(
                leftover > 0,
                "should never have more than one blocksize left"
            );
            // todo: faster way to do this?
            let pad: Vec<u8> = vec![0u8; leftover];
            let _written_amount = self.write(&pad)?;
            self.context.datasize -= leftover;
        }
        let offset = self.ciphertext_bytes + 8;

        assert!(self.this_block.is_empty());

        let (cap, meta) = self.context.done()?;
        // "current_location" is now the offset of the metadata .. so
        // we write that out at the very end of the file
        meta.write(&mut self.output)?;

        self.output.write_all(&offset.to_be_bytes())?;
        if let Some(completion_cb) = self.completed {
            completion_cb(&cap);
        }
        Ok((cap, self.output))
    }
}

impl<W> Write for ImmutableBuilder<W>
where
    W: Write,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        // 1. do we have >= 1 "blocksize" plaintext?
        // 2. yes? -> encrypt it
        // 3. where do we put the ciphertext? need a writer
        // boring way
        self.this_block.write(buf)?;
        let mut local_written = 0;
        while self.this_block.len() >= self.context.blocksize {
            // cut off a block's worth at the front
            let this_block_bytes: Vec<u8> =
                self.this_block.drain(0..self.context.blocksize).collect();
            // encrypt it
            let encrypted_block = match self.context.encrypt_block(&this_block_bytes) {
                Ok(it) => it,
                Err(err) => return Err(std::io::Error::other(err)),
            };
            // write out a block
            self.output.write_all(&encrypted_block)?;
            local_written += encrypted_block.len();
            self.ciphertext_bytes += encrypted_block.len();
        }
        Ok(local_written)
        // todo: we're basically "just hosed" if anything errors in
        // here, right? should we mark ourselves as failed then?
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // 1. can we honour this by writing "part of a block"
        // immediately (and then writing the rest when it comes in?)
        todo!()
    }
    // think: can "done()" be like "close()"??
}

//TODO: below is the stuff we want to re-do as an iterator, right?
// and then also as a "plaintext -> ciphertext" function?

impl ReadCap for ImmutableReadCap {
    /// encode the provided plaintext into a version 1 file written to
    /// BufWriter, also yielding an ImmutableReadCap that corresponds
    /// to the encoded data.
    fn encrypt(
        plaintext: Vec<u8>,
        mut writer: std::io::BufWriter<File>,
        blocksize: usize,
    ) -> Result<ImmutableReadCap, MagicCapError> {
        writer.write_all(b"mcap")?; // tag
        writer.write_all(&1u32.to_be_bytes())?; // version == 1

        let plaintext_chunks = plaintext.as_slice().chunks(blocksize);

        // todo: this should be created inside ReadCapability trait
        // can use "default" trait implementation of a method to "use" the
        // streaming version to do "in place" / whole-file
        // decryption/encryption
        let mut ptc = EncryptionContext::new(blocksize)?;
        for plain in plaintext_chunks {
            let ciphertext = ptc.encrypt_block(plain)?;
            writer.write_all(ciphertext.as_slice())?;
        }

        // "done()" consumes the EncryptionContext, which is the
        // correct semantics here because we can't usefully do
        // anything else with a EncryptionContext once we've produced
        // the ReadCap + ImmutableMetadata
        let (cap, meta) = ptc.done()?;

        let offset: u64 = writer.stream_position()?;

        // write the metadata. It's at the end, but we already
        // included an offset so readers can deserialize the metadata
        // first.
        meta.write(&mut writer)?;

        // offset goes at the end
        writer.write_all(&offset.to_be_bytes())?;

        Ok(cap)
    }

    ////XXX want a like 'decrypt_stream' or something? what does a "rust stream of chunks" look like?
    //// push vs. pull iterators? (e.g. File wants pull, network streams want "push" probably?)

    /// turn an existing ReadCap plus associated Immutable back into
    /// the original plaintext (double-checks that this Immutable
    /// corresponds to the ReadCap first).
    fn decrypt(&self, immutable: &mut Immutable) -> Result<Vec<u8>, MagicCapError> {
        let mut plaintext: Vec<u8> = Vec::with_capacity(immutable.metadata.size as usize);
        let iv = [0u8; 16]; // 16 bytes of 0's
        // before anything else, we check that the capability
        // corresponds to this Immutable ... by hashing the Metadata,
        // and confirming it matches the Cap's hash
        if !self.verify.corresponds_to(immutable) {
            return Err(MagicCapError::McapMetadataDiscordant());
        }

        // todo: streaming decryption also goes into the ReadCapability, somehow
        // -> EncryptionContext equiv gets created by some fn in the trait
        // todo: the actual decrypt code should be moved into "impl Read for ReadCapabilty"
        let mut key = TahoeAesCtr::new(&self.key.into(), &iv.into());

        // can we use iterators more directly here instead of for loop? e.g.:
        // let mut leaves: Vec<[u8; 32]> = cipher.iter().map(|x| TahoeLeaf::hash(x)).collect();
        let mut leaves: Vec<[u8; 32]> = vec![];
        for i in 0..immutable.data_provider.total_blocks() {
            let mut leaf = vec![0u8; immutable.data_provider.block_size() as usize];
            immutable.data_provider.get_block(i, &mut leaf)?;
            let lh = TahoeLeaf::hash(&leaf);
            leaves.push(lh);
        }
        fill_empty_merkle_leaves(&mut leaves);

        let merkle_tree = MerkleTree::<TahoeInside>::from_leaves(&leaves);
        let merkle_root = merkle_tree.root().ok_or(MagicCapError::MerkleError())?;

        // this checks that the _metadata_ from our metadata file
        // actually matches the ciphertext from our 'data' file (we
        // checked above that the user-supplied capability-string has
        // a matching root)
        if merkle_root != immutable.metadata.ciphertext_root {
            let incorrect_hash = BASE64URL_NOPAD.encode(&merkle_root);
            return Err(MagicCapError::CipherTextDiscordant(incorrect_hash));
        }

        for block_idx in 0..immutable.data_provider.total_blocks() {
            let mut block: Vec<u8> = vec![0u8; immutable.data_provider.block_size() as usize];
            immutable.data_provider.get_block(block_idx, &mut block)?;
            key.apply_keystream(&mut block);
            plaintext.append(&mut block);
        }
        // we probably "decrypted" more of the block than is valid (on
        // the last block) so throw that data away
        plaintext.truncate(immutable.metadata.size as usize);
        Ok(plaintext)
    }
}

impl ImmutableVerifier for ImmutableReadCap {
    fn verify(&self, immutable: &mut Immutable) -> Result<(), MagicCapError> {
        self.verify.verify(immutable)
    }
}

impl std::convert::From<ImmutableReadCap> for ImmutableVerifyCap {
    fn from(readcap: ImmutableReadCap) -> ImmutableVerifyCap {
        // do we just readcap.verify.clone() here instead?
        ImmutableVerifyCap {
            metadata_hash: readcap.verify.metadata_hash,
        }
    }
}

impl Display for ImmutableVerifyCap {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        let metahash: String = BASE64URL_NOPAD.encode(&self.metadata_hash);
        write!(f, "mcap0v{}", metahash)?;
        Ok(())
    }
}

impl std::convert::TryFrom<&str> for ImmutableVerifyCap {
    type Error = MagicCapError;

    fn try_from(uri: &str) -> Result<ImmutableVerifyCap, Self::Error> {
        if !uri.starts_with("mcap0v") {
            return Err(MagicCapError::InvalidCap(uri.to_string()));
        }

        let metahash = BASE64URL_NOPAD.decode(&uri.as_bytes()[6..])?;
        Ok(ImmutableVerifyCap {
            metadata_hash: vec_to_array(metahash)?,
        })
    }
}

impl Display for ImmutableReadCap {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        let mut metakey: Vec<u8> = self.verify.metadata_hash.to_vec();
        metakey.append(&mut self.key.to_vec());
        let mk: String = BASE64URL_NOPAD.encode(&metakey);
        write!(f, "mcap0r{}", mk)?;
        Ok(())
    }
}

impl std::convert::TryFrom<&str> for ImmutableReadCap {
    type Error = MagicCapError;

    fn try_from(uri: &str) -> Result<ImmutableReadCap, Self::Error> {
        if !uri.starts_with("mcap0r") {
            return Err(MagicCapError::InvalidCap(uri.to_string()));
        }

        let keymeta = BASE64URL_NOPAD.decode(&uri.as_bytes()[6..])?;

        let key = vec_to_array(keymeta[32..48].to_vec())?;
        Ok(ImmutableReadCap {
            key,
            verify: ImmutableVerifyCap {
                metadata_hash: vec_to_array(keymeta[0..32].to_vec())?,
            },
        })
    }
}

fn vec_to_array<T, const BLOCKSIZE: usize>(v: Vec<T>) -> Result<[T; BLOCKSIZE], MagicCapError> {
    // todo: surely we can type this shorter, but we so far failed
    let result = v.try_into();
    match result {
        Ok(r) => Ok(r),
        Err(x) => Err(MagicCapError::VecToArray(format!(
            "Expected Vec of length {} but got {}",
            BLOCKSIZE,
            x.len()
        ))),
    }
}

/// Specification of how to access all ciphertext, which are stored in blocks.
pub trait EncryptedImmutable {
    // naive API:
    fn total_blocks(&self) -> usize;
    fn block_size(&self) -> u32;

    /// get all the ciphertext for a particular block. it is an error
    /// if the size of "buf" is not equal to the block-size. returns
    /// the number of bytes read.
    fn get_block(&mut self, index: usize, buf: &mut [u8]) -> std::io::Result<usize>;
}

#[derive(Debug, PartialEq)]
/// Store all of the ciphertext on the heap
pub struct EncryptedImmutableMemory {
    // morally-equivalent to "all the blocks / segments"
    // todo: _can_ we make this a Vec<&[u8]> or do we just not know Rust and "this is the way"?
    pub blocks: Vec<Vec<u8>>,
    _block_size: u32,
}

impl EncryptedImmutable for EncryptedImmutableMemory {
    fn total_blocks(&self) -> usize {
        self.blocks.len()
    }

    fn block_size(&self) -> u32 {
        self._block_size
    }

    fn get_block(&mut self, index: usize, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.len() != self.blocks[0].len() {
            Err(
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("buf is {} but blocksize is {}", buf.len(), self._block_size),
                )
            )
        } else {
            buf.copy_from_slice(&self.blocks[index]);
            Ok(self.blocks[index].len())
        }
    }
}

#[derive(Debug, PartialEq)]
/// Access all ciphertext via a [`Read`] provider
pub struct EncryptedImmutableReader<'a, R>
where
    R: Read + Seek + 'a,
{
    provider: &'a mut R,
    blocks: u64,
    offset: u64,
    blocksize: u32,
}

impl<'a, R> EncryptedImmutable for EncryptedImmutableReader<'a, R>
where
    R: Read + Seek + 'a,
{
    fn total_blocks(&self) -> usize {
        self.blocks as usize
    }

    // can we just demand a "block_size: u32" _attribute_ in the Trait?
    fn block_size(&self) -> u32 {
        self.blocksize
    }

    fn get_block(&mut self, index: usize, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.len() != self.blocksize as usize {
            Err(
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("buf is {} but blocksize is {}", buf.len(), self.blocksize),
                )
            )
        } else {
            let offset = self.offset + (index as u64 * self.blocksize as u64);
            self.provider.seek(std::io::SeekFrom::Start(offset))?;
            Ok(self.blocksize as usize)
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
/// A struct representing (unencrypted!) metadata about the data.
pub struct ImmutableMetadata {
    // morally-equivalent to Tahoe's UEB
    pub size: u64,
    pub blocks: u64,
    pub block_size: u32,
    // todo: actually we want the WHOLE merkle tree (for random / streaming access, in the future)
    pub merkle_leaves: Vec<[u8; 32]>,
    pub ciphertext_root: [u8; 32], // merkle root of the ciphertext blocks

                                   // todo: could we encrypt this? it would have to be in such a way
                                   // that a Verify Cap can also decrypt it. Also, what about servers
                                   // that e.g. might want a "get_block()" API or similar (they need
                                   // to know the block-size, at least)
}

impl ImmutableMetadata {
    /// used to get "the bytes to hash" because Tahoe's identifiers
    /// are based on "the hash of the metadata" (aka "UEB")
    // todo: should this be From/Into? or even just implement Hasher?
    pub fn extract_bytes(&self, b: &mut Vec<u8>) {
        b.extend_from_slice(&self.size.to_be_bytes());
        b.extend_from_slice(&self.blocks.to_be_bytes());
        b.extend_from_slice(&self.block_size.to_be_bytes());
        b.extend_from_slice(&self.ciphertext_root);
    }

    pub fn write<T>(&self, writer: &mut T) -> Result<(), MagicCapError>
    where
        T: Write,
    {
        // "with_bytes" ensures we encode Vec<u8>'s as byte-slices,
        // and not lists of arbitrary-sized numbers
        let mut serializer =
            rmp_serde::Serializer::new(writer).with_bytes(rmp_serde::config::BytesMode::ForceAll);
        Ok(self.serialize(&mut serializer)?)
    }
}

/// Represents everything to do with an [`Immutable`] except the
/// [`ImmutableCap`] itself. That is, this represents the [`Immutable`]'s
/// metadata and a way to access the ciphertext.
pub struct Immutable<'a> {
    //    pub cap: Option<ImmutableCap>,
    pub metadata: ImmutableMetadata,
    // todo: do we want Arc() here too? So we can implement Clone nicely?
    pub data_provider: Box<dyn EncryptedImmutable + 'a>, // Box<dyn ..> here so we're Sized
}

impl<'a> Immutable<'a> {
    /// Deserialize an Immutable from the given input stream.
    ///
    /// The serialized format stores the metadata near the end of the
    /// data so this will read some bytes from the beginning then seek
    /// to the end before returning to near the start to read
    /// encrypted blocks of data.
    ///
    /// All of the ciphertext is read into memory. For larger files it
    /// may be better to use the ``stream`` function instead.
    ///
    pub fn read<'b, R>(mut reader: R) -> Result<Immutable<'b>, MagicCapError>
    where
        R: Read + std::io::Seek,
    {
        // read the tag and verify this is an mcap file
        let mut tag = [0u8; 4];
        reader.read_exact(&mut tag)?;
        if tag != *b"mcap" {
            return Err(MagicCapError::InvalidCapTag(tag));
        }

        // read the version number, we only understand 0x01
        let mut version = [0u8; 4];
        reader.read_exact(&mut version)?;
        let version: u32 = u32::from_be_bytes(version);
        if version != 1 {
            return Err(MagicCapError::InvalidCapVersion(version));
        }
        // the offset to the metadata is at the end of the file, the last 8 bytes
        reader.seek(std::io::SeekFrom::End(-8))?;
        // find the offset to metadata
        let mut metadata = [0u8; 8];
        reader.read_exact(&mut metadata)?;
        let metadata_offset: u64 = u64::from_be_bytes(metadata);

        // read the metadata first so we know blocksize etc
        reader.seek(std::io::SeekFrom::Start(metadata_offset))?;
        let metadata: ImmutableMetadata = rmp_serde::decode::from_read(&mut reader)?;
        let bs = metadata.block_size;

        // we have our metadata, now read the ciphertext
        reader.seek(std::io::SeekFrom::Start(4 + 4))?;
        let mut chunks =
            Vec::with_capacity(metadata.blocks as usize * metadata.block_size as usize);
        for _ in 0..metadata.blocks {
            let mut chunk = vec![0u8; metadata.block_size as usize];
            reader.read_exact(chunk.as_mut_slice())?;
            chunks.push(chunk);
        }

        // todo: ImmutableVerifyCap.decrypt checks the merkle root but maybe we want to do it here (too)?
        // (yes, we read through all the ciphertext above so perhaps ONLY check here?)
        Ok(Immutable {
            metadata,
            data_provider: Box::new(
                EncryptedImmutableMemory {
                    blocks: chunks,
                    _block_size: bs,  // how does 'metadata' get moved? where?
                }
            ),
        })
    }

    /// Similar to ``read`` but doesn't read all the ciphertext blocks
    /// into memory at once, instead accessing the provided reader
    /// as-needed to access the ciphertext on-demand.

    // so .. we still return an "Immutable", but it's backend thing is
    // set up to read "on demand" (and we've changed the Immtuable API
    // to support both)
    pub fn stream<'b, R>(reader: &'b mut R) -> Result<Immutable<'b>, MagicCapError>
    where
        R: Read + std::io::Seek,
    {
        // read the tag and verify this is an mcap file
        let mut tag = [0u8; 4];
        reader.read_exact(&mut tag)?;
        if tag != *b"mcap" {
            return Err(MagicCapError::InvalidCapTag(tag));
        }

        // read the version number, we only understand 0x01
        let mut version = [0u8; 4];
        reader.read_exact(&mut version)?;
        let version: u32 = u32::from_be_bytes(version);
        if version != 1 {
            return Err(MagicCapError::InvalidCapVersion(version));
        }
        // the offset to the metadata is at the end of the file, the last 8 bytes
        reader.seek(std::io::SeekFrom::End(-8))?;
        // find the offset to metadata
        let mut metadata = [0u8; 8];
        reader.read_exact(&mut metadata)?;
        let metadata_offset: u64 = u64::from_be_bytes(metadata);

        // read the metadata first so we know blocksize etc
        reader.seek(std::io::SeekFrom::Start(metadata_offset))?;
        let metadata: ImmutableMetadata = rmp_serde::decode::from_read(&mut *reader)?;

        // we have our metadata, now set up an on-demand reader to our
        // underlying data source
        let ondemand = Box::new(
            EncryptedImmutableReader {
                provider: reader,
                blocks: metadata.blocks,
                offset: 4 + 4,
                blocksize: metadata.block_size,
            }
        );

        // todo: have we checked that the merkle root matches each block?
        Ok(Immutable {
            metadata,
            data_provider: ondemand,
        })
    }

    pub fn encrypt<R>(
        source: R,
        blocksize: usize, // just make this u32 to match metadata?
    ) -> Result<(ImmutableCap, Immutable<'a>), MagicCapError>
    where
        R: Read,
    {
        let mut buf = vec![];
        let bytes = std::io::BufReader::new(source).read_to_end(&mut buf)?;

        let plaintext_chunks = buf.as_slice().chunks(blocksize);
        let mut ciphertext_blocks = vec![];
        let mut ptc = EncryptionContext::new(blocksize)?;
        // let meta = plaintext_chunks.fold(...)
        for plain in plaintext_chunks {
            let ciphertext = ptc.encrypt_block(plain)?;
            ciphertext_blocks.push(ciphertext);
        }

        let (cap, metadata) = ptc.done()?;
        assert_eq!(bytes, metadata.size as usize);

        // two-tuple of (cap, immutable)
        Ok((
            ImmutableCap::Read(cap),
            Immutable {
                metadata,
                data_provider: Box::new(EncryptedImmutableMemory {
                    blocks: ciphertext_blocks,
                    _block_size: blocksize as u32,
                }),
            },
        ))
    }
}

// todo: probably want something like "Into" for "plaintext" of an Immutable to convert to str, or BufReader, or ....
//
// "something like": let reader: BufReader = catalog.get_immutable(ImmutableReadCap).unwrap().into();
// "something like": let data: Vec<u8> = catalog.get_immutable(ImmutableReadCap).unwrap().into();
// "something like": let datastr: String = catalog.get_immutable(ImmutableReadCap).unwrap().into();

pub struct ImmutableCiphertextStream<R>
where
    R: Read,
{
    blocksize: usize,
    encryptor: TahoeAesCtr,
    source: R,
    // metadata: ImmutableMetadata, // incrementally accumulated
    // offset: usize, // for IV and merkle tree use
}

impl<R> Iterator for ImmutableCiphertextStream<R>
where
    R: Read,
{
    type Item = Vec<u8>;
    fn next(&mut self) -> Option<Self::Item> {
        // encrypt call has to know our offset
        let mut buf = Vec::with_capacity(self.blocksize);
        self.source.read_exact(&mut buf).ok()?;
        self.encryptor.apply_keystream(&mut buf);
        Some(buf)
    }
}

/// Method to track details about an in-progress encryption of some plaintext.
/// Used by [`Immutable::encrypt`].
struct EncryptionContext {
    pub key: TahoeAesCtr,
    pub key_bytes: [u8; 16],
    pub datasize: usize,
    pub blocksize: usize, // todo: must match plaintext-block size, can we do that with types? Yes, you can with const generics
    pub leaves: Vec<[u8; 32]>,
}

impl EncryptionContext {
    /// Create a new encryptor with a fresh, random key
    pub fn new(blocksize: usize) -> Result<Self, MagicCapError> {
        let mut key_bytes = [0u8; 16];
        getrandom::fill(&mut key_bytes)?;
        let iv = [0u8; 16]; // 16 bytes of 0's
        let key = TahoeAesCtr::new(&key_bytes.into(), &iv.into());
        Ok(EncryptionContext {
            key,
            key_bytes,
            datasize: 0,
            blocksize,
            leaves: Vec::new(),
        })
    }

    // todo: actually we can accept any slice size and just pad?
    // (or, take "a small-sized block" to mean "we are done"?)
    //
    // TODO: replace error value with an enum with a descriptive message, like, EncryptionError::BlockSize(String)
    pub fn encrypt_block(&mut self, block: &[u8]) -> Result<Vec<u8>, MagicCapError> {
        if block.len() > self.blocksize {
            return Err(MagicCapError::WrongDataSize(block.len(), self.blocksize));
        }
        // TODO: reuse the incoming block!
        let mut buf = vec![0u8; self.blocksize];
        buf[0..block.len()].copy_from_slice(block);
        self.key.apply_keystream(&mut buf);

        // update metadata
        self.datasize += block.len();
        self.leaves.push(TahoeLeaf::hash(buf.as_slice()));
        Ok(buf)
    }

    // todo: double-check we did "all the blocks", or error?
    // todo: once you call "done", are you disallowed from calling encrypt_blocks() anymore?
    //       (do we "just get" this from the fact done() consumes self?) shae says YES! ("i think so")
    pub fn done(self) -> Result<(ImmutableReadCap, ImmutableMetadata), MagicCapError> {
        let mut melf = self;
        fill_empty_merkle_leaves(&mut melf.leaves);
        let merkle_tree = MerkleTree::<TahoeInside>::from_leaves(&melf.leaves);
        let merkle_root = merkle_tree.root().ok_or(MagicCapError::MerkleError())?;
        let merkle_leaves = merkle_tree.leaves().ok_or(MagicCapError::MerkleError())?;

        let metadata = ImmutableMetadata {
            size: melf.datasize as u64,
            blocks: melf.datasize.div_ceil(melf.blocksize) as u64,
            block_size: melf.blocksize as u32,
            merkle_leaves, // todo: store all merkle leaf nodes in here
            ciphertext_root: merkle_root,
        };

        // todo: 2-tuple of cap, metadata ... but want to unify with "Immutable" maybe?
        Ok((
            ImmutableReadCap {
                key: melf.key_bytes,
                verify: ImmutableVerifyCap::from(&metadata),
            },
            metadata,
        ))
    }
}

/// Produce a VerifyCap corresponding to a particular Metadata
impl std::convert::From<&ImmutableMetadata> for ImmutableVerifyCap {
    fn from(meta: &ImmutableMetadata) -> ImmutableVerifyCap {
        let mut ueb_bytes: Vec<u8> = vec![];
        meta.extract_bytes(&mut ueb_bytes);
        let ueb_hash = tagged_hash::<32>(b"magic_cap_metadata_v1", ueb_bytes.as_slice());
        let mut thehash = [0u8; 32];
        thehash.copy_from_slice(ueb_hash.as_slice());
        ImmutableVerifyCap {
            metadata_hash: thehash,
        }
    }
}

/// This is what Tahoe does with empty Merkle leaves.
/// why? is there good reason to do that, or is rs_merkle default good?
fn fill_empty_merkle_leaves(leaves: &mut Vec<[u8; 32]>) {
    let next_pow = leaves.len().next_power_of_two();
    let mut leaf = leaves.len();
    while leaves.len() < next_pow {
        leaf += 1;
        let leaf_num = format!("{:?}", leaf);
        let empty_leaf = tagged_hash::<32>(b"Merkle tree empty leaf", leaf_num.as_bytes());
        let mut temp = [0u8; 32];
        temp.copy_from_slice(empty_leaf.as_slice());
        leaves.push(temp);
    }
}
