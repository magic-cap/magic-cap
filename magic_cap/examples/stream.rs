use magic_cap::{Immutable, ImmutableBuilder, ReadCap};
use std::io::{Cursor, Write};

fn main() {
    let plaintext: Vec<u8> = "attack at dawn".into();
    let mut ciphertext: Vec<u8> = vec![];

    // create an encrypted immutable + associated ReadCap
    let mut cryptor = ImmutableBuilder::new(4096, &mut ciphertext).unwrap();
    cryptor.write(&plaintext).unwrap();
    // .write() may be called any number of times with any size data
    let (cap, ciphertext) = cryptor.done().unwrap();
    println!("ciphertext: {} bytes", ciphertext.len());

    // using the encrypted immutable and ReadCap, get back the ciperhtext
    let ctext = ciphertext.as_slice();
    let immutable = Immutable::read(Cursor::new(ctext)).unwrap();
    let decrypted: Vec<u8> = cap.decrypt(&immutable).unwrap();
    assert_eq!(plaintext, decrypted);
}
