use magic_cap::{
    ImmutableCatalog, ImmutableDirectoryCatalog, ImmutableIdentifier, ImmutableReadCap, ReadCap,
};

fn main() {
    let mut root = std::path::PathBuf::from("../kitten-catalog");
    if !root.exists() {
        // ..but users probably run from the git checkout root
        root = std::path::PathBuf::from("kitten-catalog");
    }
    let catalog = ImmutableDirectoryCatalog::create(root).expect("catalog init");

    // to load something, we need a ReadCap from somewhere; here we
    // choose our favourite kitten from the README.org example catalog
    let bruennhilde = ImmutableReadCap::try_from(
        "mcap0rlnzyN_KuH9bRBUHP3QkXBlkWipQ6JMw50NbNBpt6aj15q2pSnh85eKib9Ac-2m51",
    )
    .expect("valid Magic Cap");

    // Catalogs reference things by LocationId which is only obtained
    // from an existing ReadCap
    let location = ImmutableIdentifier::from(&bruennhilde);
    println!("Location ID (sensitive but not secret): {}", location);
    // this example is identical to the catalog-read.rs example except this line:
    let mut imm = catalog.stream(&location).expect("loading");
    let plaintext = bruennhilde.decrypt(&mut imm).expect("decrypt");

    // 'plaintext' contains JPEG data, so we should see that in the 3
    // "magic bytes" at the start; see https://en.wikipedia.org/wiki/JPEG
    assert_eq!(b"\xff\xd8\xff", &plaintext.as_slice()[0..3],);
    println!("Loaded {} bytes of JPEG properly.", plaintext.len());
}
