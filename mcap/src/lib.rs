use magic_cap::err::MagicCapError;
/// Functions that implement the core CLI commands
use magic_cap::{
    Immutable, ImmutableBuilder, ImmutableReadCap, ImmutableVerifier, ImmutableVerifyCap, ReadCap,
};
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;

/// Implementation of "mcap encrypt"
/// This is the top level function for easy use of this crate by applications or other libraries.
/// This function does not consider memory use, but instead just does the thing using all the memory.
pub fn main_encrypt(
    output: &mut impl Write,
    plain_text: &PathBuf,
    output_fname: &PathBuf,
) -> anyhow::Result<()> {
    let mut input_file = std::fs::File::open(plain_text)?;

    // "write as one file"
    // write "mcap"
    // write 4-byte version number (1?)
    // write all the ciphertext blocks
    // write the metadata
    // write 8-byte offset to metadata
    // done

    // file format version 1 is:
    // 4 bytes: "mcap"
    // 4 bytes: 0x01  (the version number, big-endian)
    // <all the ciphertext blocks>
    // <meta_offset>: <metadata>
    // 8 bytes: u64 meta_offset to start of metadata

    let output_file = File::create(output_fname.as_path())?;
    let bufw = std::io::BufWriter::new(output_file);

    let mut plaintext: Vec<u8> = vec![0u8; 4096];
    let mut cryptor = ImmutableBuilder::new(4096, bufw)?;

    let mut r = input_file.read(&mut plaintext)?;
    while r != 0 {
        plaintext.resize(r, 0);
        cryptor.write(&plaintext)?;
        r = input_file.read(&mut plaintext)?;
    }
    let cap = cryptor.done()?;

    let capstr = format!("{}", cap);
    writeln!(output, "{}", capstr)?;
    Ok(())
}

/// "mcap decrypt"
pub fn main_decrypt(
    //    input: &mut impl Read,
    output: &mut impl Write,
    cap: &str,
    input_fname: &PathBuf,
    outfile: &PathBuf,
) -> anyhow::Result<()> {
    let cap = ImmutableReadCap::try_from(cap)?;
    let f = std::fs::File::open(input_fname.as_path())?;
    let imm = Immutable::read(&mut std::io::BufReader::new(f))?;

    match cap.decrypt(&imm) {
        Ok(plain) => {
            let out = outfile.as_path();
            let mut out = std::fs::File::create(out)?;
            out.write_all(plain.as_slice())?;
            match outfile.to_str() {
                Some(of) => {
                    writeln!(
                        output,
                        "Wrote {} bytes of plaintext to \"{}\".",
                        plain.len(),
                        of,
                    )?;
                    Ok(())
                }
                None => Ok(()),
            }
        }
        Err(e) => match &e {
            MagicCapError::McapMetadataDiscordant() => {
                writeln!(
                    output,
                    "Error: this Magic Cap does not correspond to the Data in \"{}\".",
                    input_fname.to_str().unwrap(), // how to nicer error?
                )?;
                Ok(())
            }
            _ => {
                writeln!(output, "Error decrypting: {}", e)?;
                Ok(())
            }
        },
    }
}

/// "mcap verify"
pub fn main_verify(cap: &str, input_fname: &PathBuf) -> anyhow::Result<()> {
    let cap = ImmutableVerifyCap::try_from(cap)?;
    let f = std::fs::File::open(input_fname.as_path())?;
    let imm = Immutable::read(&mut std::io::BufReader::new(f))?;

    cap.verify(&imm.metadata, imm.data_provider)?;
    Ok(())
}

/// "mcap reduce"
pub fn main_reduce(output: &mut impl Write, cap: &str) -> Result<(), MagicCapError> {
    if let Ok(readcap) = ImmutableReadCap::try_from(cap) {
        let verifycap = ImmutableVerifyCap::from(readcap);
        writeln!(output, "{}", verifycap)?;
    } else if let Ok(verifycap) = ImmutableVerifyCap::try_from(cap) {
        writeln!(output, "{}", verifycap)?;
    } else {
        writeln!(output, "Unknown kind of cap.")?;
        return Err(MagicCapError::InvalidCap(cap.to_string())).into();
    }
    Ok(())
}

#[cfg(test)]
pub mod test {
    use super::*;
    use proptest::prelude::*;
    use tempfile::tempdir;

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
            main_encrypt(&mut output, &plain, &cipher).unwrap();

            let capstr: &str = std::str::from_utf8(&output)?.trim_end();
            let round = outd.path().join("decrypted");

            // turn this into a Verify Cap and confirm the ciphertext
            let mut output = vec!();
            main_reduce(&mut output, capstr)?;
            let verifycap = std::str::from_utf8(&output)?.trim_end();
            main_verify(verifycap, &cipher).unwrap();

            // confirm that "decrypt" can turn back into plaintext
            let mut output = vec!();
            main_decrypt(&mut output, capstr, &cipher, &round).unwrap();

            let mut og = String::new();
            let mut other = String::new();
            File::open(plain)?.read_to_string(&mut og)?;
            File::open(round)?.read_to_string(&mut other)?;

            assert_eq!(og, other);
        }
    }
}
