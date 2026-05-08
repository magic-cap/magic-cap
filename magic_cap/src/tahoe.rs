use rs_merkle::Hasher;
use sha2::{Digest, Sha256};

/// Produce a "tagged hash" by concatenating a netstring of the tag
/// with the value, and applying SHA256d to the result. [^tahoe]
///
/// [^tahoe]: This is the same way Tahoe-LAFS does it.
pub fn tagged_hash<const TAGSIZE: usize>(tag: &[u8], val: &[u8]) -> [u8; TAGSIZE] {
    // todo: Chris' code had "truncate_to" as an arg ... and then we
    // wnated to do that as const-generics ... but "sha256d" _is_ just
    // always 32 bytes so what does the truncate_to even do?
    // tagged_hash<16>
    const {
        assert!(TAGSIZE <= 32, "illegal tag size");
    }
    let mut hasher = Sha256::new();
    hasher.update(netstring(tag));
    hasher.update(val);
    let hash = hasher.finalize();
    let hash2 = Sha256::digest(hash);
    let mut rtn: [u8; TAGSIZE] = [0u8; TAGSIZE];
    rtn.copy_from_slice(&hash2[0..TAGSIZE]);
    rtn
}

/// Produce a "netstring" from the provided slice, which prepends a
/// length and appends a comma. That is, the "netstring" version of
/// ``"foo"`` is ``"3:foo,"`` [^djb97]
///
/// [^djb97]: <https://cr.yp.to/proto/netstrings.txt>
pub fn netstring(s: &[u8]) -> Vec<u8> {
    //format!("{}:{},", s.len(), std::str::from_utf8(s).unwrap()).into_bytes()

    // what Python does is output BYTES here, where we have some
    // number of ASCII-numeral bytes that represent the length, then a
    // ':' byte, and then 32 arbitrary bytes of key
    let tag = format!("{}:", s.len());
    // stuff two byte-sequences together; better way?
    [tag.as_bytes(), s, b","].concat()
}

// from binrw-tahoe experiments -- mirroring the Tahoe way of
// using tagged hashes for merkel nodes, with different tags for
// leaves vs. interior vs. empty nodes.
#[derive(Clone)]
/// Marker struct for Merkle Tree nodes that are leaves
pub struct TahoeLeaf {}

#[derive(Clone)]
/// Marker struct interior Merkle Tree nodes
pub struct TahoeInside {}

impl Hasher for TahoeLeaf {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> [u8; 32] {
        //why not "Hash" as return type?
        //let mut engine = sha256d::Hash::engine();
        //engine.input(data);
        //sha256d::Hash::from_engine(engine).to_byte_array()
        let hash = tagged_hash::<32>(b"allmydata_crypttext_segment_v1", data);
        let mut ret = [0; 32];
        ret.copy_from_slice(hash.as_slice());
        ret
    }

    /*
    fn concat_and_hash(left: &Self::Hash, right: Option<&Self::Hash>) -> Self::Hash {
    match right {
    //Some(r) => Hasher::concat_and_hash::<[u8; 32]>(left, right),
    Some(r) => Hasher::concat_and_hash(left, right),
    None => panic!("Tahoe can't have an un-full tree")
    }
    }
     */
}

impl Hasher for TahoeInside {
    type Hash = [u8; 32];
    // we don't really want "generics, of u32 or str" etc we can just
    // add those as "things your Trait needs ot have"? is that the pattern?
    // a tahoe inside node in python is "tagged_pair_hash(constant, left_hash, right_hash)"
    // but the left and right hashes both get wrapped in a netstring()

    fn hash(data: &[u8]) -> [u8; 32] {
        //why not "Hash" as return type?
        // tahoe does netstring() of _each_ node's hash
        /*
        let net0: Vec<u8> = netstring(&data[0..32]);
        let net1: Vec<u8> = netstring(&data[32..64]);
        let netfinal = vec![net0, net1].concat();
         */
        let hash = tagged_hash::<32>(b"Merkle tree internal node", data);
        let mut ret = [0; 32];
        ret.copy_from_slice(hash.as_slice());
        ret
    }
}

pub type TahoeAesCtr = ctr::Ctr128BE<aes::Aes128>;
