use magic_cap::{Immutable, ImmutableBuilder, ReadCap};
use std::io::{Cursor, Write};
use std::any::Any;

// NB: using ImmutableBuilder directly is fairly low-level and most
// users will be happier to use Publisher

fn main() {
    let plaintext: Vec<u8> = "To light a candle is to cast a shadow...".into();
    let ciphertext = Box::<Vec<u8>>::new(vec![]);

    // Create an encrypted immutable + associated ReadCap.
    // We're using "Vec<u8>" as a Write implementation here, but it
    // could be a File or Stdout).
    let mut cryptor = ImmutableBuilder::new(4096, ciphertext, None).unwrap();
    let _written_amount = cryptor.write(&plaintext).unwrap();
    // .write() may be called any number of times with any size data
    let (cap, ciphertext) = cryptor.done().unwrap();

    let ciphertext = (ciphertext as Box<dyn Any>).downcast::<Vec<u8>>().unwrap();
    println!("ciphertext size: {} bytes", ciphertext.len());

    // Using the encrypted immutable data and ReadCap, get back the
    // plaintext (note that Immutable::read() loads all the ciphertext
    // into memory -- see stream_read.rs for an example that streams
    // the ciphertext in.
    let ctext = ciphertext.as_slice();
    let mut data = Cursor::new(ctext);
    let mut immutable = Immutable::stream(&mut data).unwrap();
    let decrypted: Vec<u8> = cap.decrypt(&mut immutable).unwrap();
    assert_eq!(plaintext, decrypted);
}
