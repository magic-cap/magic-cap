use data_encoding::DecodeError;
use getrandom;
use thiserror::Error;

#[derive(Debug, Error)]
/// All Errors produced from this crate
pub enum MagicCapError {
    #[error("Failed to Base64 decode mcap hash")]
    HashInvalid(
        #[from]
        #[source]
        DecodeError,
    ),

    #[error("VecToArray unhappiness")]
    VecToArray(String),

    #[error("Cannot decrypt without a capability")]
    NoCapability,

    #[error("Invalid Magic Cap ({0}).")]
    InvalidCap(String),

    #[error("Invalid Magic Cap tag: {0:?}")]
    InvalidCapTag([u8; 4]),

    #[error("Invalid Magic Cap version: {0}")]
    InvalidCapVersion(u32),

    #[error("Invalid Magic Cap tag: {0}")]
    InvalidCapKind(String),

    #[error("Magic Cap does not correspond to Metadata hash")]
    McapMetadataDiscordant(),

    #[error("Ciphertext does not correspond")]
    CipherTextDiscordant(String),

    #[error("Merkle Tree cannot be constructed")]
    MerkleError(),

    #[error("Wrong data size: expected {0} got {1}")]
    WrongDataSize(usize, usize), // expected, actual

    #[error("msgpack encoding error: {0}")]
    MsgpackEncodeError(#[from] rmp_serde::encode::Error),

    #[error("msgpack encoding error: {0}")]
    MsgpackDecodeError(#[from] rmp_serde::decode::Error),

    #[error("I/O Error: {0}")]
    IOError(#[from] std::io::Error),

    #[error("Failed to obtain entropy: {0}")]
    GetRandomError(#[from] getrandom::Error),

    #[error("ImmutableDirectoryCollection must be a directory")]
    NotDirectory(),

    #[error("{0}")]
    GenericError(String),
}
