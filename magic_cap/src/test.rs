use super::*;
use aes::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use proptest::prelude::*;
use std::fs::File;
use tempfile::TempDir;

#[test]
fn golden_tahoe_tagged_hash() {
    let gold = b"\xee\x19\x0f\x82\xb1\x962\xaf\xf9\x97\x18SN\xd8\x96y0\xc4\xf8\xd1\x8fEqh\xab\r27\xae\r\x95\x0b";
    let alleged = tahoe::tagged_hash::<32>(b"foo", b"bar");
    assert_eq!(*gold, alleged);
}

#[test]
fn doc_example_capstrings() {
    let cap_string = "mcap0r-Gshm9tyvjXDnfWpLWKMgjcK0AOdC-O12vvLW5rxeV7752pj2a2uogG4RpvMFS0g";
    let cap: ImmutableReadCap = cap_string.try_into().unwrap();
    println!("The cap is: {}", cap);
}

#[test]
fn doc_example_verifycap() {
    let cap_string = "mcap0r-Gshm9tyvjXDnfWpLWKMgjcK0AOdC-O12vvLW5rxeV7752pj2a2uogG4RpvMFS0g";
    let readcap: ImmutableReadCap = cap_string.try_into().unwrap();
    let verifycap: ImmutableVerifyCap = readcap.into();
    let verifycap_string = format!("{}", verifycap);
    assert_eq!(
        verifycap_string,
        "mcap0v-Gshm9tyvjXDnfWpLWKMgjcK0AOdC-O12vvLW5rxeV4"
    );
}

// #[test]
// fn doc_example_in_memory() {
//     let plaintext: Vec<u8> = "To light a candle is to cast a shadow...".into();

//     if let Ok((ImmutableCap::Read(readcap), immutable)) =
//         Immutable::encrypt(plaintext.as_slice(), 4096)
//     {
//         println!("Read Cap: {:?}", readcap);

//         let verifycap: ImmutableVerifyCap = readcap.into();
//         if !verifycap.corresponds_to(&immutable) {
//             println!("Verify Cap does not match data");
//         }
//     }
// }

#[test]
fn doc_example_verify() {
    let verifycap: ImmutableVerifyCap = "mcap0vCaeC8weUj758t7AedxEy3jwepUmAyX8p_owj0gf8OCU"
        .try_into()
        .unwrap();
    let mut ciphertext = Immutable::read(File::open("../kitten.mcap").unwrap()).unwrap();
    assert!(verifycap.corresponds_to(&ciphertext));
    verifycap.verify(&mut ciphertext).unwrap();
}

#[test]
fn handcrafted_illegal_cap_tag() {
    let data = b"notmcap";
    assert!(Immutable::read(std::io::Cursor::new(data)).is_err());
}

#[test]
fn handcrafted_illegal_cap_version() {
    let data = b"mcap\xff\xff\xff\xff";
    assert!(Immutable::read(std::io::Cursor::new(data)).is_err());
}

#[test]
fn power_of_two() {
    // test our assumptions about how next_power_of_two() works
    assert_eq!(2u32.next_power_of_two(), 2);
    assert_eq!(3u32.next_power_of_two(), 4);
    assert_eq!(4u32.next_power_of_two(), 4);
}

#[test]
fn merkle_behavior() {
    let mut leaves: Vec<[u8; 32]> = vec![
        TahoeLeaf::hash(b"foo"),
        TahoeLeaf::hash(b"bar"),
        TahoeLeaf::hash(b"quux"),
    ];
    let mt = MerkleTree::<TahoeInside>::from_leaves(&leaves);
    println!("root: {:?}", mt.root().unwrap());

    leaves.push([0u8; 32]);
    let mt = MerkleTree::<TahoeInside>::from_leaves(&leaves);
    println!("root: {:?}", mt.root().unwrap());

    let foo = [[1u8; 32], [0u8; 32]].concat();
    let bar = vec![1u8; 32];
    println!("X {:?}", TahoeInside::hash(&foo));
    println!("X {:?}", TahoeInside::hash(&bar));
}
#[test]
fn decrypt_with_iv() {
    /* How do we decrypt blocks somewhere deep inside the stream?
    Our temple robbing has discovered try_seek as part of StreamCipherSeek */
    let mut key_bytes = [1u8; 16];
    getrandom::fill(&mut key_bytes).unwrap();
    let iv = [0u8; 16]; // 16 bytes of 0's (I wonder if IV is allowed to rollover? looks like yes?)
    let mut key = TahoeAesCtr::new(&key_bytes.into(), &iv.into());
    let mut b: Vec<u8> = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".to_vec();
    key.apply_keystream(&mut b);
    // let cpos:usize = key.current_pos();
    // println!("Size is {total_size}\nThe IV is now set to {cpos}");
    let bad_iv = [0u8; 16];
    let mut unkey = TahoeAesCtr::new(&key_bytes.into(), &bad_iv.into());
    unkey.try_seek(26).unwrap();
    let mut subvec: Vec<u8> = b.clone();
    subvec.drain(0..26);
    unkey.apply_keystream(&mut subvec);
    println!("Hopefully decrypted: {:?}", subvec);
}

#[test]
fn read_and_verify_same_identifier() {
    let cap_string = "mcap0r-Gshm9tyvjXDnfWpLWKMgjcK0AOdC-O12vvLW5rxeV7752pj2a2uogG4RpvMFS0g";
    let readcap: ImmutableReadCap = cap_string.try_into().unwrap();
    let verifycap: ImmutableVerifyCap = readcap.clone().into();

    assert_eq!(
        ImmutableIdentifier::from(readcap),
        ImmutableIdentifier::from(verifycap)
    );
}

#[test]
fn invalid_caps() {
    let cap_string = "MCAP0z-Gshm9tyvjXDnfWpLWKMgjcK0AOdC-O12vvLW5rxeV7752pj2a2uogG4RpvMFS0g";
    // suggestions from the compiler .. shorter way to say this?
    assert!(<&str as std::convert::TryInto<ImmutableVerifyCap>>::try_into(cap_string).is_err());
    assert!(<&str as std::convert::TryInto<ImmutableReadCap>>::try_into(cap_string).is_err());
}

#[test]
fn find_catalog_basic() {
    let tmpd = TempDir::new().unwrap();
    let tmp = tmpd.path().to_owned();
    let mut catalog = ImmutableDirectoryCatalog::create(tmp).unwrap();

    let message = b"To light a candle is to cast a shadow...";
    let mut builder = catalog.insert(4096).unwrap();
    let _written_amount = builder.write(message).unwrap();
    let (cap, _) = builder.done(None, None).unwrap();
    // note: we have to drop "writer", which is the "_" above, so it
    // flushes / closes properly

    let id: ImmutableIdentifier = (&cap).into();
    let mut immutable = catalog.load(&id).unwrap();
    let data = cap.decrypt(&mut immutable).unwrap();
    assert_eq!(message, data.as_slice());
}

#[test]
fn round_trip_encrypted_metadata_optional() {
    let tmpd = TempDir::new().unwrap();
    let tmp = tmpd.path().to_owned();
    let mut catalog = ImmutableDirectoryCatalog::create(tmp).unwrap();

    let message = b"To light a candle is to cast a shadow...";
    let mut builder = catalog.insert(4096).unwrap();
    let _written_amount = builder.write(message).unwrap();
    let (cap, _) = builder.done(Some(Path::new("foo.png")), None).unwrap();
    // note: we have to drop "writer", which is the "_" above, so it
    // flushes / closes properly

    let id: ImmutableIdentifier = (&cap).into();
    let mut immutable = catalog.load(&id).unwrap();
    let data = cap.decrypt(&mut immutable).unwrap();
    let sim = immutable.metadata.secret_metadata(&cap);
    assert_eq!(sim.suggested_filename, "foo.png");
    assert_eq!(message, data.as_slice());
}


#[test]
fn round_trip_encrypted_metadata() {
    let meta = SecretImmutableMetadata {
        mime_type: "mime/foo".to_string(),
        suggested_filename: "ohai.pdf".to_string(),
    };
    let key_bytes = [0u8; 16];
    let key = derive_key(&key_bytes, "magic-cap-metadata-0");

    let enc = EncryptedSecretImmutableMetadata::new(key, &meta);
    let key2 = derive_key(&key_bytes, "magic-cap-metadata-0");
    let meta2 = decrypt_metadata(key2, &enc).unwrap();

    assert_eq!(meta, meta2);
}

proptest! {
    #![proptest_config(ProptestConfig {
        max_shrink_iters: 2500, cases: 5, .. ProptestConfig::default()
    })]

    #[test]
    fn capability_round_trip(key: [u8;16], metadata_hash:[u8;32]) {
        let cap = ImmutableReadCap{
            key,
            verify: ImmutableVerifyCap {
                metadata_hash,
            },
            leaves: vec![],
        };
        let human_readable: String = format!("{}", cap);
        let round_cap = ImmutableReadCap::try_from(human_readable.as_str()).unwrap();
        assert_eq!(cap, round_cap);
    }

    #[test]
    fn base64_round_trip(input: Vec<u8>) {
        // base64 does round trip with sufficient type conversions.
        let encoded = BASE64URL_NOPAD.encode(&input);
        let decoded = BASE64URL_NOPAD.decode(encoded.as_bytes()).unwrap();
        assert!(input == decoded);
    }

}
