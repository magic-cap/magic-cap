use crate::err::MagicCapError;
use crate::tahoe::tagged_hash;
use crate::{Immutable, ImmutableBuilder, ImmutableReadCap, ImmutableVerifyCap};
use data_encoding::HEXLOWER;
use std::fmt;
use std::fs::File;
use std::io::BufWriter;
use std::path::{Path, PathBuf};

// todo: might want a more fine-grained API so we do "get_metadata"
// vs. "get_ciphertext" so that a network / storage-server can be
// smarter about the seeks? (speculative)!
pub trait ImmutableCatalog<'a> {
    // todo: probably want "load" vs. "stream" API here
    // todo: and stream() vs stream_async() probably
    fn open(&self, locator: &ImmutableIdentifier) -> Result<Immutable<'a>, MagicCapError>;

    fn insert(
        &mut self,
        blocksize: usize,
    ) -> Result<ImmutableBuilder<BufWriter<File>>, MagicCapError>;
}

#[derive(Debug, PartialEq)]
pub struct ImmutableIdentifier {
    storage_index: [u8; 32], // tagged-hash
}

impl fmt::Display for ImmutableIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", HEXLOWER.encode(&self.storage_index))
    }
}

impl std::convert::From<&ImmutableVerifyCap> for ImmutableIdentifier {
    fn from(cap: &ImmutableVerifyCap) -> ImmutableIdentifier {
        ImmutableIdentifier {
            storage_index: tagged_hash::<32>(b"magic_cap_storage_index_v1", &cap.metadata_hash),
        }
    }
}

// todo: make a Base32 / Base64 marker-type? That contains a String?
impl std::convert::From<ImmutableIdentifier> for String {
    fn from(val: ImmutableIdentifier) -> String {
        Self::from(&val)
    }
}

impl std::convert::From<&ImmutableIdentifier> for String {
    fn from(val: &ImmutableIdentifier) -> String {
        HEXLOWER.encode(&val.storage_index)
    }
}

impl std::convert::From<ImmutableVerifyCap> for ImmutableIdentifier {
    fn from(cap: ImmutableVerifyCap) -> ImmutableIdentifier {
        ImmutableIdentifier::from(&cap)
    }
}

impl std::convert::From<&ImmutableReadCap> for ImmutableIdentifier {
    fn from(cap: &ImmutableReadCap) -> ImmutableIdentifier {
        ImmutableIdentifier::from(&cap.verify)
    }
}

impl std::convert::From<ImmutableReadCap> for ImmutableIdentifier {
    fn from(cap: ImmutableReadCap) -> ImmutableIdentifier {
        ImmutableIdentifier::from(&cap)
    }
}

// TODO: could have a Default implementation that always says no and
// is and error to insert?
//
// OR: could create a new one in a "well known place" and uses that
// (this is nice because then it actually works)

/// a file-system implementation of [`ImmutableCatalog`] which
/// stores magic-caps in a struture similar to Git
/// (...should it just BE a Git object-store? Put the .cap files in Blobs...?)
#[derive(Debug)]
pub struct ImmutableDirectoryCatalog {
    root: PathBuf,
}

impl ImmutableDirectoryCatalog {
    pub fn create(root: PathBuf) -> Result<ImmutableDirectoryCatalog, MagicCapError> {
        if !root.is_dir() {
            return Err(MagicCapError::NotDirectory());
        }
        // todo: consider putting a README or similar in here that
        // both more-accurately marks this as an
        // ImmutableDirectoryCatalog and also explains to a human
        // what this is.
        Ok(ImmutableDirectoryCatalog { root })
    }
}

impl<'a> ImmutableCatalog<'a> for ImmutableDirectoryCatalog {
    fn open(&self, locator: &ImmutableIdentifier) -> Result<Immutable<'a>, MagicCapError> {
        // 1. convert identifier to &str (base64? base32?)
        // 2. strip first 2 (more?) chars off
        // 3. look in root/<2 chars>/<entire id>
        let name: String = locator.into();
        let dir = &name[0..2];
        let fname = Path::join(&Path::join(self.root.as_path(), dir), name);
        let f = std::fs::File::open(fname.clone())?;
        let imm = Immutable::read(f)?;
        Ok(imm)
    }

    fn insert(
        &mut self,
        blocksize: usize,
    ) -> Result<ImmutableBuilder<BufWriter<File>>, MagicCapError> {
        // 1. (use collection-builder thing we just built)
        // 2. open an ephemeral file in <root>/INCOMING/<rnd>.mcap
        // 3. return the builder with Write to our ephemeral file
        // 4. when done() called, our Write will be close()'d (right?)
        // 5. ...and so we can then move it to the right spot.
        //   (but how do we get the Immutable / identifier then??)
        //  -> do we have to wrap the BUILDER? (probably)
        let incoming = Path::join(self.root.as_path(), "foo"); // fixme, random ephemeral name
        let uploaded = incoming.clone();
        let writer = File::create(incoming)?;
        let bufwriter = BufWriter::new(writer);
        let mut dir = self.root.clone();
        let completed = Box::new(move |cap: &ImmutableReadCap| {
            let id: ImmutableIdentifier = cap.into();
            let idstr: String = id.into();
            dir.push(&idstr[0..2]);
            let mut fname = dir.clone();
            fname.push(&idstr);

            // maybe create subdir for this hash
            let _ = std::fs::create_dir(dir);

            // move into correct place
            std::fs::rename(uploaded, fname).unwrap();
        });

        let builder = ImmutableBuilder::<BufWriter<File>>::new(
            blocksize,
            bufwriter,
            Some(Box::new(completed)),
        )?;
        Ok(builder)
    }
}
