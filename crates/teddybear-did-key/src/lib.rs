mod ed25519;
mod p256;
mod x25519;

use ssi_dids_core::{
    DIDMethod, DIDMethodResolver,
    resolution::{self, Error},
};
use ssi_multicodec::MultiEncoded;
use ssi_security::{Multibase, MultibaseBuf};

pub use ed25519::Ed25519;
pub use p256::P256;
pub use x25519::X25519;

pub trait KeyType {
    type PublicKey;

    const CODEC: u64;

    fn fragment(source: &Self::PublicKey) -> MultibaseBuf;

    fn resolve(
        raw: &str,
        value: &[u8],
        options: resolution::Options,
    ) -> Result<resolution::Output<Vec<u8>>, Error>;
}

pub struct DIDKey;

impl DIDMethod for DIDKey {
    const DID_METHOD_NAME: &'static str = "key";
}

impl DIDMethodResolver for DIDKey {
    async fn resolve_method_representation<'a>(
        &'a self,
        key: &'a str,
        options: resolution::Options,
    ) -> Result<resolution::Output<Vec<u8>>, Error> {
        let (_, data) = Multibase::new(key)
            .decode()
            .map_err(|e| Error::InvalidMethodSpecificId(e.to_string()))?;

        if data.len() < 2 {
            return Err(Error::NotFound);
        }

        let (codec, value) = MultiEncoded::new(&data)
            .map_err(|_| Error::NotFound)?
            .parts();

        match codec {
            ssi_multicodec::ED25519_PUB => Ed25519::resolve(key, value, options),
            ssi_multicodec::X25519_PUB => X25519::resolve(key, value, options),
            ssi_multicodec::P256_PUB => P256::resolve(key, value, options),
            _ => Err(Error::NotFound),
        }
    }
}
