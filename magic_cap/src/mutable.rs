#![allow(warnings)]
use mainline::Dht;
use mainline::MutableItem;
use mainline::SigningKey;
use crate::err::MagicCapError;
use crate::ImmutableReadCap;


pub struct MutablePublisher {
    client: mainline::Dht,
}

pub struct MutableWriter {
    signing_key_bytes: [u8; 32]
}


impl MutablePublisher {
    fn connect_mainline() -> Result<MutablePublisher, MagicCapError> {
        Ok(
            MutablePublisher {
                client: Dht::client()?,
            }
        )
    }

    fn create(self: &mut Self, initial_value: &ImmutableReadCap) -> Result<MutableWriter, MagicCapError> {
        let value = format!("{}", initial_value);
        // todo: double-check that arbitrary bytes are sufficient for this signing key (must be, given api?)
        let mut signing_key_bytes = [0u8; 32];
        getrandom::fill(&mut signing_key_bytes)?;
        let item = MutableItem::new(
            SigningKey::from_bytes(&signing_key_bytes),
            &value.into_bytes(),
            0i64,
            None,
        );
        self.client.put_mutable(item, None)?;
        Ok(
            MutableWriter {
                signing_key_bytes,
            }
        )
    }

    fn from_str(self: &mut Self, existing_mutable: &str) -> Result<MutableWriter, MagicCapError> {
        // use self.client to fetch the existing one, so we learn the sequence number
        todo!()
    }
}

impl MutableWriter {
    fn update(self: &mut Self, publisher: &MutablePublisher, new_value: &ImmutableReadCap) -> Result<(), MagicCapError> {
        let value = format!("{}", new_value);
        let signer = SigningKey::from_bytes(&self.signing_key_bytes);

        let item = publisher.client.get_mutable_most_recent(signer.verifying_key().as_bytes(), None).ok_or(MagicCapError::GenericError("stuff".to_string()))?;
        let newitem = MutableItem::new(
            signer,
            value.as_bytes(),
            item.seq() + 1,
            None,
        );
        publisher.client.put_mutable(item, None)?;
        Ok(())
    }
}
