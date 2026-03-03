use crate::err::MagicCapError;
use crate::{Immutable, ImmutableBuilder, ImmutableReadCap, ImmutableVerifyCap, tagged_hash};
use std::fs::File;
use std::io::BufWriter;
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use data_encoding::HEXLOWER;

pub trait ImmutableCollection {
    // todo: probably want "load" vs. "stream" API here
    fn open(&self, locator: &ImmutableIdentifier) -> Result<Immutable, MagicCapError>;

    fn insert(
        &mut self,
        blocksize: usize,
    ) -> Result<ImmutableDirectoryCollectionBuilder<BufWriter<File>>, MagicCapError>;
}

#[derive(Debug, PartialEq)]
pub struct ImmutableIdentifier {
    storage_index: [u8; 32], // tagged-hash
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

/// a file-system implementation of [`ImmutableCollection`] which
/// stores magic-caps in a struture similar to Git
/// (...should it just BE a Git object-store? Put the .cap files in Blobs...?)
pub struct ImmutableDirectoryCollection {
    root: PathBuf,
}

impl ImmutableDirectoryCollection {
    pub fn create(root: PathBuf) -> Result<ImmutableDirectoryCollection, MagicCapError> {
        if !root.is_dir() {
            return Err(MagicCapError::NotDirectory());
        }
        // todo: consider putting a README or similar in here that
        // both more-accurately marks this as an
        // ImmutableDirectoryCollection and also explains to a human
        // what this is.
        Ok(ImmutableDirectoryCollection { root })
    }
}

pub struct ImmutableDirectoryCollectionBuilder<W>
where
    W: Write,
{
    builder: ImmutableBuilder<W>,
    completed: Box<dyn FnOnce(&ImmutableReadCap)>,
}

impl<W> ImmutableDirectoryCollectionBuilder<W>
where
    W: Write,
{
    pub fn done(self) -> Result<(ImmutableReadCap, W), MagicCapError> {
        let (cap, w) = self.builder.done()?;
        // 1. tell collection we're done inserting
        (self.completed)(&cap);
        // 2. return to parent
        Ok((cap, w))
    }
}

impl<W> Write for ImmutableDirectoryCollectionBuilder<W>
where
    W: Write,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        self.builder.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.builder.flush()
    }
}

impl ImmutableCollection for ImmutableDirectoryCollection {
    fn open(&self, locator: &ImmutableIdentifier) -> Result<Immutable, MagicCapError> {
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
    ) -> Result<ImmutableDirectoryCollectionBuilder<BufWriter<File>>, MagicCapError> {
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

        let builder = ImmutableBuilder::<BufWriter<File>>::new(blocksize, bufwriter)?;
        Ok(ImmutableDirectoryCollectionBuilder::<BufWriter<File>> { builder, completed })
    }
}
