use magic_cap::{Immutable, ImmutableCap, ImmutableVerifyCap};

fn main() {
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
