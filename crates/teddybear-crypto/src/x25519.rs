use std::{borrow::Cow, str::FromStr};

use serde::{Deserialize, Serialize};
use ssi_dids_core::ssi_json_ld::{iref::UriBuf, Iri, IriBuf};
use ssi_jwk::{Params, JWK};
use ssi_multicodec::MultiEncodedBuf;
use ssi_security::{multibase, Multibase, MultibaseBuf};
use ssi_verification_methods::{
    ExpectedType, GenericVerificationMethod, InvalidVerificationMethod, JwkVerificationMethod,
    TypedVerificationMethod, VerificationMethod, VerificationMethodSet,
};

use crate::encoder::KeyEncoder;

pub const X25519_KEY_AGREEMENT_KEY_TYPE: &str = "X25519KeyAgreementKey2020";

#[derive(Debug, thiserror::Error)]
pub enum InvalidPublicKey {
    #[error("invalid key type")]
    InvalidKeyType,

    #[error("invalid key length")]
    InvalidKeyLength,

    #[error(transparent)]
    Multibase(#[from] multibase::Error),

    #[error(transparent)]
    Multicodec(#[from] ssi_multicodec::Error),
}

#[derive(Debug, Clone)]
pub struct PublicKey {
    encoded: MultibaseBuf,
    decoded: x25519_dalek::PublicKey,
}

impl PublicKey {
    pub fn encode(decoded: x25519_dalek::PublicKey) -> Self {
        let multi_encoded =
            MultiEncodedBuf::encode_bytes(ssi_multicodec::X25519_PUB, decoded.as_bytes());

        Self {
            encoded: MultibaseBuf::encode(multibase::Base::Base58Btc, multi_encoded.as_bytes()),
            decoded,
        }
    }

    pub fn decode(encoded: MultibaseBuf) -> Result<Self, InvalidPublicKey> {
        let pk_multi_encoded = MultiEncodedBuf::new(encoded.decode()?.1)?;

        let (pk_codec, pk_data) = pk_multi_encoded.parts();

        if pk_codec == ssi_multicodec::X25519_PUB {
            let typed_pk: [u8; 32] = pk_data
                .try_into()
                .map_err(|_| InvalidPublicKey::InvalidKeyLength)?;

            let decoded = x25519_dalek::PublicKey::from(typed_pk);

            Ok(Self { encoded, decoded })
        } else {
            Err(InvalidPublicKey::InvalidKeyType)
        }
    }

    pub fn encoded(&self) -> &Multibase {
        &self.encoded
    }

    pub fn decoded(&self) -> &x25519_dalek::PublicKey {
        &self.decoded
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.encoded.serialize(serializer)
    }
}

impl<'a> Deserialize<'a> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'a>,
    {
        use serde::de::Error;
        let encoded = MultibaseBuf::deserialize(deserializer)?;
        Self::decode(encoded).map_err(D::Error::custom)
    }
}

impl FromStr for PublicKey {
    type Err = InvalidPublicKey;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::decode(MultibaseBuf::new(s.to_owned()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename = "X25519KeyAgreementKey2020")]
pub struct X25519KeyAgreementKey2020 {
    pub id: IriBuf,

    pub controller: UriBuf,

    #[serde(rename = "publicKeyMultibase")]
    pub public_key: PublicKey,
}

impl X25519KeyAgreementKey2020 {
    pub fn from_public_key(
        id: IriBuf,
        controller: UriBuf,
        public_key: x25519_dalek::PublicKey,
    ) -> Self {
        Self {
            id,
            controller,
            public_key: PublicKey::encode(public_key),
        }
    }
}

impl VerificationMethod for X25519KeyAgreementKey2020 {
    fn id(&self) -> &Iri {
        self.id.as_iri()
    }

    fn controller(&self) -> Option<&Iri> {
        Some(self.controller.as_iri())
    }
}

impl VerificationMethodSet for X25519KeyAgreementKey2020 {
    type TypeSet = &'static str;

    fn type_set() -> Self::TypeSet {
        X25519_KEY_AGREEMENT_KEY_TYPE
    }
}

impl TypedVerificationMethod for X25519KeyAgreementKey2020 {
    fn expected_type() -> Option<ExpectedType> {
        Some(X25519_KEY_AGREEMENT_KEY_TYPE.to_string().into())
    }

    fn type_match(ty: &str) -> bool {
        ty == X25519_KEY_AGREEMENT_KEY_TYPE
    }

    fn type_(&self) -> &str {
        X25519_KEY_AGREEMENT_KEY_TYPE
    }
}

impl JwkVerificationMethod for X25519KeyAgreementKey2020 {
    fn to_jwk(&self) -> Cow<JWK> {
        Cow::Owned(JWK::from(Params::OKP(self.public_key.decoded.encode())))
    }
}

impl TryFrom<GenericVerificationMethod> for X25519KeyAgreementKey2020 {
    type Error = InvalidVerificationMethod;

    fn try_from(m: GenericVerificationMethod) -> Result<Self, Self::Error> {
        Ok(Self {
            id: m.id,
            controller: m.controller,
            public_key: m
                .properties
                .get("publicKeyMultibase")
                .ok_or_else(|| InvalidVerificationMethod::missing_property("publicKeyMultibase"))?
                .as_str()
                .ok_or_else(|| {
                    InvalidVerificationMethod::invalid_property(
                        "publicKeyMultibase is not a string",
                    )
                })?
                .parse()
                .map_err(|e| {
                    InvalidVerificationMethod::invalid_property(&format!(
                        "publicKeyMultibase parsing failed because: {e}"
                    ))
                })?,
        })
    }
}
