use magic_cap::{Immutable, ImmutableReadCap, ReadCap};

fn main() {
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(std::io::stderr)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    // "cargo test --doc" will run this in "<git-root>/magic_cap"
    let mut root = std::path::PathBuf::from("../kitten-catalog");
    if !root.exists() {
        // ..but users probably run from the git checkout root
        root = std::path::PathBuf::from("kitten-catalog");
    }

    // this is the path to bruennhilde.jpeg's encoding in the
    // kitten-catalog at the root of this repository
    /*
    root.push("1c");
    root.push("1c4dad38c5f147f6518784ccae913a395d6ceabbbc210d3f78e084f93ce0af5c");
    let data = std::io::BufReader::new(std::fs::File::open(root).expect("find Bruennhilde"));
     */
    let data = std::io::BufReader::new(std::fs::File::open("foo").expect("find Bruennhilde"));
    // ...so we'll need the corresponding Magic Cap to read it (see
    // README.org for more of these)
    let readcap = ImmutableReadCap::try_from(
        "mcap0r_Tt5hP4SB1duRxRLV4LBoglY0vpP0ZXBsg1SO2EOhObiUM7gHs4lwQnc2VyfzIJH",
        //        "mcap0rTDDL618penLGr1UcWqpSK6aTm7ZaDuLffE5CJkFCczHjDrO-pk8s2j3D7Ut6BMgr",
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
