use ssi_jwk::{Base64urlUInt, OctetParams};

pub trait OKPEncoder {
    fn encode_okp(&self) -> OctetParams;
}

impl OKPEncoder for ed25519_dalek::VerifyingKey {
    fn encode_okp(&self) -> OctetParams {
        OctetParams {
            curve: "Ed25519".to_string(),
            public_key: Base64urlUInt(self.to_bytes().to_vec()),
            private_key: None,
        }
    }
}

impl OKPEncoder for ed25519_dalek::SigningKey {
    fn encode_okp(&self) -> OctetParams {
        OctetParams {
            curve: "Ed25519".to_string(),
            public_key: Base64urlUInt(self.verifying_key().to_bytes().to_vec()),
            private_key: Some(Base64urlUInt(self.to_bytes().to_vec())),
        }
    }
}

impl OKPEncoder for x25519_dalek::PublicKey {
    fn encode_okp(&self) -> OctetParams {
        OctetParams {
            curve: "X25519".to_string(),
            public_key: Base64urlUInt(self.to_bytes().to_vec()),
            private_key: None,
        }
    }
}

impl OKPEncoder for x25519_dalek::StaticSecret {
    fn encode_okp(&self) -> OctetParams {
        let public = x25519_dalek::PublicKey::from(self);

        OctetParams {
            curve: "X25519".to_string(),
            public_key: Base64urlUInt(public.to_bytes().to_vec()),
            private_key: Some(Base64urlUInt(self.to_bytes().to_vec())),
        }
    }
}
