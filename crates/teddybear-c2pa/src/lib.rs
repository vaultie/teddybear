use c2pa::{Signer, SigningAlg};
use ed25519_dalek::{Signer as _, SigningKey};

pub use c2pa::{Builder, Error, ManifestDefinition, Reader};

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
