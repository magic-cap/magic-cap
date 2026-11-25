#![allow(warnings)]

use std::fmt::{Display, Formatter};
use mainline::Dht;
use mainline::MutableItem;
use mainline::SigningKey;
use crate::err::MagicCapError;
use crate::ImmutableReadCap;
use data_encoding::BASE64URL_NOPAD;
use crate::vec_to_array;


pub struct MutablePublisher {
    client: mainline::Dht,
}


#[derive(Clone, Debug)]
pub struct MutableWriteCap {
    signing_key_bytes: [u8; 32]
}


impl std::convert::TryFrom<&str> for MutableWriteCap {
    type Error = MagicCapError;

    fn try_from(uri: &str) -> Result<MutableWriteCap, Self::Error> {
        if !uri.starts_with("mcap0w") {
            return Err(MagicCapError::InvalidCap(uri.to_string()));
        }

        let binary_data = BASE64URL_NOPAD.decode(&uri.as_bytes()[6..])?;
        assert_eq!(binary_data.len(), 32);  // todo: nice error

        let signing_key_bytes = vec_to_array(binary_data[0..32].to_vec())?;
        Ok(MutableWriteCap{
            signing_key_bytes,
        })
    }
}

impl Display for MutableWriteCap {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        let private_key: String = BASE64URL_NOPAD.encode(&self.signing_key_bytes);
        write!(f, "mcap0w{}", private_key)?;
        Ok(())
    }
}


impl std::str::FromStr for MutableWriteCap {
    type Err = MagicCapError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        MutableWriteCap::try_from(s)
    }
}



impl MutablePublisher {
    pub fn connect_mainline() -> Result<MutablePublisher, MagicCapError> {
        Ok(
            MutablePublisher {
                client: Dht::client()?,
            }
        )
    }

    pub fn create(self: &mut Self, initial_value: &ImmutableReadCap) -> Result<MutableWriteCap, MagicCapError> {
        let value = format!("{}", initial_value);
        // todo: double-check that arbitrary bytes are sufficient for this signing key (must be, given api?)
        let mut signing_key_bytes = [0u8; 32];
        getrandom::fill(&mut signing_key_bytes)?;
        let item = MutableItem::new(
            SigningKey::from_bytes(&signing_key_bytes),
            &value.into_bytes(),
            1i64, // does 0 have special meaning?
            None,
        );
        self.client.put_mutable(item, None)?;
        Ok(
            MutableWriteCap {
                signing_key_bytes,
            }
        )
    }

    pub fn get(self: &mut Self, mutable: &MutableWriteCap) -> Result<ImmutableReadCap, MagicCapError> {
        let signer = SigningKey::from_bytes(&mutable.signing_key_bytes);
        let item = self.client.get_mutable_most_recent(signer.verifying_key().as_bytes(), None).ok_or(MagicCapError::GenericError("failed to fetch mutable DHT slot".to_string()))?;
        let capstr = String::from_utf8(item.value().to_vec())?;
        //let capstr = item.value().try_from()?;
        let readcap = ImmutableReadCap::try_from(capstr.as_str())?;
        Ok(readcap)
    }
}

impl MutableWriteCap {
    pub fn update(self: &Self, publisher: &MutablePublisher, new_value: &ImmutableReadCap) -> Result<(), MagicCapError> {
        let value = format!("{}", new_value);
        let signer = SigningKey::from_bytes(&self.signing_key_bytes);

        let item = publisher.client.get_mutable_most_recent(signer.verifying_key().as_bytes(), None).ok_or(MagicCapError::GenericError("failed to get current value of mutable".to_string()))?;
        let newitem = MutableItem::new(
            signer,
            value.as_bytes(),
            item.seq() + 1,
            None,
        );
        publisher.client.put_mutable(newitem, None)?;
        Ok(())
    }
}
