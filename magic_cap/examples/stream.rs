use magic_cap::{Immutable, ImmutableBuilder, ReadCap, err::MagicCapError};
use std::io::{Cursor, Write};
use std::any::Any;
use std::boxed::Box;

// NB: using ImmutableBuilder directly is fairly low-level and most
// users will be happier to use Publisher

fn main() -> Result<(), MagicCapError>{
    let plaintext: Vec<u8> = "To light a candle is to cast a shadow...".into();
    let ciphertext = Box::<Vec<u8>>::new(vec![]);

    // Create an encrypted immutable + associated ReadCap.
    // We're using "Vec<u8>" as a Write implementation here, but it
    // could be a File or Stdout).
    let mut cryptor = ImmutableBuilder::new(4096, ciphertext, None)?;
    let _written_amount = cryptor.write(&plaintext)?;
    // .write() may be called any number of times with any size data
    let (cap, ciphertext) = cryptor.done()?;

    // note that we get the Box'd ciphertext back above .. but it's
    // now a Box<dyn Write> so we have to downcast() it back to the
    // type we made initially. Often, we never need this returned
    // object at all -- e.g. for a File or similar -- so can ignore
    // these gymnastics

    let ciphertext = (ciphertext as Box<dyn Any>).downcast::<Vec<u8>>().unwrap();
    println!("ciphertext size: {} bytes", ciphertext.len());

    // Using the encrypted immutable data and ReadCap, get back the
    // plaintext (note that Immutable::read() loads all the ciphertext
    // into memory -- see stream_read.rs for an example that streams
    // the ciphertext in.
    let mut immutable = Immutable::read(Cursor::new(ciphertext.as_slice()))?;
    let decrypted: Vec<u8> = cap.decrypt(&mut immutable)?;
    assert_eq!(plaintext, decrypted);
    Ok(())
}
