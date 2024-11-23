use ssi_jwk::{Base64urlUInt, OctetParams};

pub trait KeyEncoder {
    type Params;

    fn encode(&self) -> Self::Params;
}

impl KeyEncoder for ed25519_dalek::VerifyingKey {
    type Params = OctetParams;

    fn encode(&self) -> OctetParams {
        OctetParams {
            curve: "Ed25519".to_string(),
            public_key: Base64urlUInt(self.to_bytes().to_vec()),
            private_key: None,
        }
    }
}

impl KeyEncoder for ed25519_dalek::SigningKey {
    type Params = OctetParams;

    fn encode(&self) -> OctetParams {
        OctetParams {
            curve: "Ed25519".to_string(),
            public_key: Base64urlUInt(self.verifying_key().to_bytes().to_vec()),
            private_key: Some(Base64urlUInt(self.to_bytes().to_vec())),
        }
    }
}

impl KeyEncoder for x25519_dalek::PublicKey {
    type Params = OctetParams;

    fn encode(&self) -> OctetParams {
        OctetParams {
            curve: "X25519".to_string(),
            public_key: Base64urlUInt(self.to_bytes().to_vec()),
            private_key: None,
        }
    }
}

impl KeyEncoder for x25519_dalek::StaticSecret {
    type Params = OctetParams;

    fn encode(&self) -> OctetParams {
        let public = x25519_dalek::PublicKey::from(self);

        OctetParams {
            curve: "X25519".to_string(),
            public_key: Base64urlUInt(public.to_bytes().to_vec()),
            private_key: Some(Base64urlUInt(self.to_bytes().to_vec())),
        }
    }
}
