use async_trait::async_trait;
use c2pa::{AsyncSigner, SigningAlg};
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

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl AsyncSigner for Ed25519Signer {
    async fn sign(&self, data: Vec<u8>) -> c2pa::Result<Vec<u8>> {
        Ok(self.key.sign(&data).to_vec())
    }

    #[cfg(target_arch = "wasm32")]
    async fn send_timestamp_request(&self, _message: &[u8]) -> Option<c2pa::Result<Vec<u8>>> {
        None
    }

    fn alg(&self) -> SigningAlg {
        SigningAlg::Ed25519
    }

    fn certs(&self) -> c2pa::Result<Vec<Vec<u8>>> {
        Ok(self.certificates.clone())
    }

    fn reserve_size(&self) -> usize {
        1024 + self
            .certificates
            .iter()
            .map(|cert| cert.len())
            .sum::<usize>()
    }
}
