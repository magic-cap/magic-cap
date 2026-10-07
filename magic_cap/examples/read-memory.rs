use magic_cap::{Immutable, ImmutableReadCap, ReadCap};

fn main() {
    // "cargo test --doc" will run this in "<git-root>/magic_cap"
    let mut root = std::path::PathBuf::from("../kitten-catalog");
    if !root.exists() {
        // ..but users probably run from the git checkout root
        root = std::path::PathBuf::from("kitten-catalog");
    }

    // this is the path to bruennhilde.jpeg's encoding in the
    // kitten-catalog at the root of this repository
    root.push("03");
    root.push("03f18f02af384c0c798d1e77ad57cda4e917b5ec5fa778fdcbbc62824b484dce");
    let data = std::io::BufReader::new(std::fs::File::open(root).expect("find Bruennhilde"));
    // ...so we'll need the corresponding Magic Cap to read it (see
    // README.org for more of these)
    let readcap = ImmutableReadCap::try_from(
        "mcap0rp2UZFy-aCyUD0lMwajQn9r9FKXMg8b1oC9A9x_Cj_f6SzNBaSzS0bbQ4U2IL5GNB",
    )
    .expect("valid readcap");

    // now we can decrypt the data into memory
    let mut imm = Immutable::read(data).expect("deserialize Data");
    let plaintext: Vec<u8> = readcap.decrypt(&mut imm).expect("decrypt");

    // 'plaintext' contains JPEG data, so we should see that in the 3
    // "magic bytes" at the start; see https://en.wikipedia.org/wiki/JPEG
    assert_eq!(b"\xff\xd8\xff", &plaintext.as_slice()[0..3],);
    println!("Loaded {} bytes of JPEG properly.", plaintext.len());
}
