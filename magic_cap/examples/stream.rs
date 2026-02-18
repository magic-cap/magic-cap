use magic_cap::{ImmutableVerifyCap, Immutable, ImmutableCap};

fn main() {
    let plaintext: Vec<u8> = "attack at dawn".into();

    if let Ok((ImmutableCap::Read(readcap), immutable)) = Immutable::encrypt(plaintext.as_slice(), 4096) {
        println!("Read Cap: {:?}", readcap);

        let verifycap: ImmutableVerifyCap = readcap.into();
        if ! verifycap.corresponds_to(&immutable) {
            println!("Verify Cap does not match data");
        }
    }

}
