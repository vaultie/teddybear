use std::io::{Read, Seek, Write};

use c2pa::{Builder, Signer, SigningAlg};
use ed25519_dalek::{Signer as _, SigningKey};

pub use c2pa::ManifestDefinition;

pub struct Ed25519Signer {
    key: SigningKey,
    certificates: Vec<Vec<u8>>,
}

impl Ed25519Signer {
    pub fn new(key: SigningKey, certificate: Vec<u8>) -> Self {
        Self {
            key,
            certificates: vec![certificate],
        }
    }
}

impl Signer for Ed25519Signer {
    #[inline]
    fn sign(&self, data: &[u8]) -> c2pa::Result<Vec<u8>> {
        Ok(self.key.sign(data).to_vec())
    }

    #[inline]
    fn alg(&self) -> SigningAlg {
        SigningAlg::Ed25519
    }

    #[inline]
    fn certs(&self) -> c2pa::Result<Vec<Vec<u8>>> {
        Ok(self.certificates.clone())
    }

    #[inline]
    fn reserve_size(&self) -> usize {
        2048
    }
}

pub fn embed_manifest<R: Read + Seek + Send, W: Write + Read + Seek + Send, S: Signer>(
    source: &mut R,
    dest: &mut W,
    format: &str,
    definition: ManifestDefinition,
    signer: &S,
) -> c2pa::Result<Vec<u8>> {
    let mut builder = Builder::default();
    builder.definition = definition;
    builder.sign(signer, format, source, dest)
}
