#[cfg(test)]
pub mod test {
    use crate::{main_decrypt, main_encrypt, main_reduce, main_verify};
    use magic_cap::err::MagicCapError;
    use proptest::prelude::*;
    use std::fs::File;
    use std::io::{Read, Write};
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
        fn round_trip_main(s in "\\PC+") {
            // write to a file so we can exercise via paths
            let outd = tempdir()?;
            let plain = outd.path().join("plain");
            {
                let mut tmp = File::create(&plain)?;
                tmp.write(s.as_bytes())?;
            }  // close tmp
            let cipher = outd.path().join("cipher");
            let mut output = vec!();
            main_encrypt(&mut output, &plain, &Some(cipher.clone()), &None).unwrap();

            let capstr: &str = std::str::from_utf8(&output)?.trim_end();
            let round = outd.path().join("decrypted");

            // turn this into a Verify Cap and confirm the ciphertext
            let mut output = vec!();
            main_reduce(&mut output, capstr)?;
            let verifycap = std::str::from_utf8(&output)?.trim_end();
            main_verify(verifycap, &cipher).unwrap();

            // "reducing" a Verify Cap is a no-op
            let mut output = vec!();
            main_reduce(&mut output, verifycap).unwrap();
            assert_eq!(String::from_utf8(output).unwrap().trim(), verifycap);

            // confirm that "decrypt" can turn back into plaintext
            let mut output = vec!();
            main_decrypt(&mut output, capstr, &None, &None, &Some(cipher), &None, &Some(round.clone())).unwrap();

            let mut og = String::new();
            let mut other = String::new();
            File::open(plain)?.read_to_string(&mut og)?;
            File::open(round)?.read_to_string(&mut other)?;

            assert_eq!(og, other);
        }
    }
}
