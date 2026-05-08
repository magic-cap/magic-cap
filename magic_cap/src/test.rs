use super::*;
use aes::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use proptest::prelude::*;
use tempfile::TempDir;

#[test]
fn golden_tahoe_tagged_hash() {
    let gold = b"\xee\x19\x0f\x82\xb1\x962\xaf\xf9\x97\x18SN\xd8\x96y0\xc4\xf8\xd1\x8fEqh\xab\r27\xae\r\x95\x0b";
    let alleged = tahoe::tagged_hash::<32>(b"foo", b"bar");
    assert_eq!(*gold, alleged);
}

#[test]
fn doc_example_in_memory() {
    let plaintext: Vec<u8> = "To light a candle is to cast a shadow...".into();

    if let Ok((ImmutableCap::Read(readcap), immutable)) =
        Immutable::encrypt(plaintext.as_slice(), 4096)
    {
        println!("Read Cap: {:?}", readcap);

        let verifycap: ImmutableVerifyCap = readcap.into();
        if !verifycap.corresponds_to(&immutable) {
            println!("Verify Cap does not match data");
        }
    }
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

#[test]
fn doc_example_verify() {
    let verifycap: ImmutableVerifyCap = "mcap0v-Gshm9tyvjXDnfWpLWKMgjcK0AOdC-O12vvLW5rxeV4"
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
fn handcrafted_filesystem_round_trip() {
    let blocksize = 2;
    let input: Vec<u8> = b"abcdef".to_vec();
    let tmp = TempDir::new().unwrap();

    let fm = File::create(tmp.path().join("encrypted")).unwrap();
    let cap = ImmutableReadCap::encrypt(
        input.clone(),
        std::io::BufWriter::new(fm),
        blocksize as usize,
    )
    .unwrap();

    let fm = File::open(tmp.path().join("encrypted")).unwrap();
    let data = std::io::BufReader::new(fm);
    let mut imm2 = Immutable::read(data).unwrap();
    let plain_text = cap.decrypt(&mut imm2).unwrap();
    assert_eq!(input, plain_text);
}

#[test]
fn handcrafted_filesystem_round_trip_stream() {
    let blocksize = 2;
    let input: Vec<u8> = b"abcdef".to_vec();
    let tmp = TempDir::new().unwrap();

    let fm = File::create(tmp.path().join("encrypted")).unwrap();
    let cap =
        ImmutableReadCap::encrypt(input.clone(), std::io::BufWriter::new(fm), blocksize).unwrap();

    let fm = File::open(tmp.path().join("encrypted")).unwrap();
    let mut data = std::io::BufReader::new(fm);
    let mut imm = Immutable::stream(&mut data).unwrap();

    println!("{:?}", imm.metadata.merkle_leaves);

    // stream just one block out .. we only HAVE one block, but hey
    let mut plain: Vec<u8> = vec![0u8; blocksize];
    cap.decrypt_one_block(&mut imm, 0, &mut plain[0..blocksize])
        .unwrap();
    assert_eq!(input[0..2], plain);
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
    let (cap, _) = builder.done().unwrap();
    // note: we have to drop "writer", which is the "_" above, so it
    // flushes / closes properly

    let id: ImmutableIdentifier = (&cap).into();
    let mut immutable = catalog.open(&id).unwrap();
    let data = cap.decrypt(&mut immutable).unwrap();
    assert_eq!(message, data.as_slice());
}

proptest! {
    #[test]
    fn encrypt_doesnt_crash(s in "\\PC+") {
        Immutable::encrypt(s.as_bytes(), 4096).unwrap();
    }

    #[test]
    fn round_trip(s in "\\PC+") {
        let (cap, mut immutable) = Immutable::encrypt(s.as_bytes(), 4096).unwrap();
        if let ImmutableCap::Read(readcap) = cap {
            let round = readcap.decrypt(&mut immutable).unwrap();
            assert!(s.as_bytes() == round);
        } else {
            assert!(false);
        }
    }

    #[test]
    fn verify_fails_corrupted_ciphertext(s in "\\PC+") {
        let (cap0, _immutable0) = Immutable::encrypt(s.as_bytes(), 4096).unwrap();
        let (_cap1, mut immutable1) = Immutable::encrypt(s.as_bytes(), 4096).unwrap();
        if let ImmutableCap::Read(rcap) = cap0 {
            let rcap0 = rcap.clone();
            let vcap: ImmutableVerifyCap = rcap.into();
            assert!(vcap.verify(&mut immutable1).is_err());
            assert!(rcap0.verify(&mut immutable1).is_err());
        } else {
            panic!("asdf");
        }
    }

    #[test]
    fn test_verify(s in "\\PC+") {
        let (cap, mut immutable) = Immutable::encrypt(s.as_bytes(), 4096).unwrap();
        if let ImmutableCap::Verify(verifycap) = cap {
            assert!(verifycap.verify(&mut immutable).is_ok());
        }
    }

    #[test]
    fn test_verify_fail_ciphertext(s in "\\PC+") {
        // we cannot decrypt the ciphertext
        let (cap0, immutable0) = Immutable::encrypt(s.as_bytes(), 4096).unwrap();
        let (_, immutable1) = Immutable::encrypt(s.as_bytes(), 4096).unwrap();
        let mut failed = Immutable {
            metadata: immutable1.metadata,
            data_provider: immutable0.data_provider,
        };
        if let ImmutableCap::Verify(verifycap) = cap0 {
            assert!(verifycap.verify(&mut failed).is_err());
        }
    }

    #[test]
    fn test_verify_fail_metadata(s in "\\PC+") {
        // the metadata doesn't verify
        let (cap0, immutable0) = Immutable::encrypt(s.as_bytes(), 4096).unwrap();
        let (_, immutable1) = Immutable::encrypt(s.as_bytes(), 4096).unwrap();
        let mut failed = Immutable {
            metadata: immutable1.metadata,
            data_provider: immutable0.data_provider,
        };
        if let ImmutableCap::Verify(verifycap) = cap0 {
            assert!(verifycap.verify(&mut failed).is_err());
        }
    }

    #[test]
    fn negative_test(s in "\\PC+", idx in 0usize..32usize) {
        // confirm that we REJECT an Immutable with incorrect merkle entries
        let (cap, immutable) = Immutable::encrypt(s.as_bytes(), 4096).unwrap();
        // corrupt some of the merkle tree
        let mut corrupt_root = immutable.metadata.ciphertext_root;
        // try inverting various pieces of the merkle tree
        corrupt_root[idx] ^= 0xff;

        let mut corrupted = Immutable{
            metadata: ImmutableMetadata{
                ciphertext_root: corrupt_root,
                ..immutable.metadata
            },
            ..immutable
        };

        // this decrypt should fail, because we messed up the merkle root above
        if let ImmutableCap::Read(readcap) = cap {
            let round = readcap.decrypt(&mut corrupted);
            assert!(round.is_err());
        } else {
            assert!(false);
        }
    }

    #[test]
    fn wrong_mcap(s in "\\PC+") {
        // if we use the wrong mcap string against valid
        // metadata+cipherttext, it should still be an error
        let (_, mut immutable1) = Immutable::encrypt(s.as_bytes(), 4096).unwrap();
        let (cap2, _) = Immutable::encrypt(s.as_bytes(), 4096).unwrap();

        // this decrypt should fail
        if let ImmutableCap::Read(readcap2) = cap2 {
            let round = readcap2.decrypt(&mut immutable1);
            if round.is_ok() {
                assert!(false);
            }
        } else {
            assert!(false);
        }
    }

}

proptest! {
    #![proptest_config(ProptestConfig {
        max_shrink_iters: 2500, cases: 5, .. ProptestConfig::default()
    })]


    #[test]
    fn big_round_trip(bad in 4096..(4096*63)) {
        // test sizes 1 block to 63 blocks (and fractions thereof)
        let s = bad as u64;
        let mut b: Vec<u8> = vec![0; s as usize];
        b.resize(s as usize, 0u8);
        getrandom::fill(b.as_mut_slice()).unwrap();
        let (cap, mut immutable) = Immutable::encrypt(b.as_slice(), 4096).unwrap();
        println!("{:?} {:?}" , immutable.metadata.size, immutable.metadata.blocks);
        assert!(immutable.metadata.size == s);
        if let ImmutableCap::Read(readcap) = cap {
            let round = readcap.decrypt(&mut immutable).unwrap();
            assert!(b.as_slice() == round);
        } else {
            assert!(false);
        }
    }

    #[test]
    fn random_block_size_round_trip(input_size in 2..20usize, block_size in 1..40usize) {
        // test sizes 1 block to 63 blocks (and fractions thereof)
        let s = input_size as u64;
        let mut b: Vec<u8> = vec![0; s as usize];
        b.resize(s as usize, 0u8);
        getrandom::fill(b.as_mut_slice()).unwrap();
        let (cap, mut immutable) = Immutable::encrypt(b.as_slice(), block_size).unwrap();
        println!("{:?} {:?}" , immutable.metadata.size, immutable.metadata.blocks);
        assert!(immutable.metadata.size == s);
        if let ImmutableCap::Read(readcap) = cap {
            let round = readcap.decrypt(&mut immutable).unwrap();
            assert_eq!(b, round);
        } else {
            assert!(false);
        }
    }

    #[test]
    fn leaf_round_trip(bad in 4096..(4096*63)) {
        // test sizes 1 block to 63 blocks (and fractions thereof)
        let s = bad as u64;
        let mut b: Vec<u8> = vec![0; s as usize];
        b.resize(s as usize, 0u8);
        getrandom::fill(b.as_mut_slice()).unwrap();
        let (_cap, immutable) = Immutable::encrypt(b.as_slice(), 4096).unwrap();
        println!("{:?} {:?}" , immutable.metadata.size, immutable.metadata.blocks);
        // changing "len() > 0" to "is_empty()" breaks this test
        assert!(immutable.metadata.merkle_leaves.len() > 0);
    }

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

    #[test]
    fn filesystem_round_trip(input: Vec<u8>, blocksize in 2u16..70u16) {
        let tmp = TempDir::new()?;

        let fm = File::create(tmp.path().join("encrypted"))?;
        let cap = ImmutableReadCap::encrypt(input.clone(), std::io::BufWriter::new(fm), blocksize as usize)?;

        let fm = File::open(tmp.path().join("encrypted"))?;
        let data = std::io::BufReader::new(fm);
        let mut imm2 = Immutable::read(data).unwrap();
        let plain_text = cap.decrypt(&mut imm2).unwrap();
        assert_eq!(input, plain_text);
    }
}
