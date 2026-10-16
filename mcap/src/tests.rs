#[cfg(test)]
pub mod test {
    use crate::{main_decrypt, main_encrypt, main_reduce, main_verify};
    use magic_cap::ImmutableReadCap;
    use magic_cap::err::MagicCapError;
    use proptest::prelude::*;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::str::FromStr;
    use tempfile::tempdir;

    #[test]
    fn reduce_unknown() {
        let capstr = "mcap0x_deadbeef";
        let mut output = vec![];
        if let Err(x) = main_reduce(&mut output, capstr) {
            match x {
                MagicCapError::InvalidCap(_) => (),
                _ => {
                    panic!("Unexpected error")
                }
            }
        } else {
            panic!("Expected an error");
        }
    }

    proptest! {
            #[test]
            fn mcap_round_trip_main(s in "\\PC+") {
                // write to a file so we can exercise via paths
                println!("we have reached the inside of mcap round_trip_main proptest");
                let tmpd = tempdir()?;

                let mut catalogs: Vec<Box<dyn magic_cap::ImmutableCatalog<'_>>> = vec![
                    std::boxed::Box::new(magic_cap::ImmutableDirectoryCatalog::create(tmpd.as_ref().to_path_buf())?),
                ];

                let plain = tmpd.path().join("plain");
                println!("creating plain file at {:?}",plain);
                {
                    let mut tmp = File::create(&plain)?;
                    let _written_amount = tmp.write(s.as_bytes())?;
                }  // close tmp
                println!("finished writing to tmp");
                let mut output = vec!();
                main_encrypt(&mut output, &plain, &mut catalogs, 4096).unwrap();

                let capstr: &str = std::str::from_utf8(&output)?.trim_end();
                let round = tmpd.path().join("decrypted");

                // turn this into a Verify Cap and confirm the ciphertext
                let mut output = vec!();
                main_reduce(&mut output, capstr)?;
                let verifycap = std::str::from_utf8(&output)?.trim_end();
    //            main_verify(verifycap, &cipher).unwrap();

                // "reducing" a Verify Cap is a no-op
                let mut output = vec!();
                main_reduce(&mut output, verifycap).unwrap();
                assert_eq!(String::from_utf8(output).unwrap().trim(), verifycap);

                // confirm that "decrypt" can turn back into plaintext
                let immutable_read_cap = ImmutableReadCap::from_str(capstr).unwrap();
                // XXX why does this test pass? The println at the top certainly runs! Something is wrong here!
                main_decrypt(&immutable_read_cap, &mut catalogs, &Some(round.clone())).unwrap();

                let mut og = String::new();
                let mut other = String::new();
                File::open(plain)?.read_to_string(&mut og)?;
                File::open(round)?.read_to_string(&mut other)?;

                assert_eq!(og, other);
            }
        }
}
