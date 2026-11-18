use magic_cap::{Immutable, ImmutableReadCap, ReadCap};

fn main() {
    // "cargo test --doc" will run this in "<git-root>/magic_cap"
    let mut root = std::path::PathBuf::from("../kitten-catalog");
    if !root.exists() {
        // ..but users probably run from the git checkout root
        root = std::path::PathBuf::from("kitten-catalog");
    }

    // the readcap for "bruennhilde.jpeg"
    let readcap = ImmutableReadCap::try_from(
        "mcap0rwedkkhZUU4LIEBS9VypVCYO6YQrVpkYhazyNtg16Kzhqt4pKhRGjXNLLEhdYG-vZ",
    )
    .expect("valid readcap");

    // we can find corresponding Data files inside on-disk Catalogs by
    // using the "Identifier", which we can find with "mcap debug id"
    // on the command-line
    root.push("88");
    root.push("884ef78b37fd33ac3fa8f8e939ed68e8d4b35710908fddd411f4d2314cba66af");
    let data = std::io::BufReader::new(std::fs::File::open(root).expect("find Bruennhilde"));

    // now we can decrypt the data into memory
    let mut imm = Immutable::read(data).expect("deserialize Data");
    let plaintext: Vec<u8> = readcap.decrypt(&mut imm).expect("decrypt");

    // 'plaintext' contains JPEG data, so we should see that in the 3
    // "magic bytes" at the start; see https://en.wikipedia.org/wiki/JPEG
    assert_eq!(b"\xff\xd8\xff", &plaintext.as_slice()[0..3],);
    println!("Loaded {} bytes of JPEG properly.", plaintext.len());
}
