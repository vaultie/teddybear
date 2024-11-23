use ssi_dids_core::DIDURLBuf;
use ssi_jwk::{Params, JWK};
use ssi_verification_methods::{EcdsaSecp256r1VerificationKey2019, Ed25519VerificationKey2020};
use teddybear_did_key::KeyType;
use thiserror::Error;

pub enum DynamicVerificationMethod {
    Ed25519VerificationKey2020(Ed25519VerificationKey2020),
    EcdsaSecp256r1VerificationKey2019(EcdsaSecp256r1VerificationKey2019),
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("the key type of the provided JWK is not supported")]
    UnsupportedKeyType,

    #[error(transparent)]
    Other(#[from] ssi_jwk::Error),
}

// FIXME: Add X25519 support
pub fn jwk_to_verification_method(jwk: &JWK) -> Result<DynamicVerificationMethod, Error> {
    match &jwk.params {
        Params::EC(ec) => {
            let public_key = p256::PublicKey::try_from(ec)?;
            let fragment = teddybear_did_key::P256::fragment(&public_key);

            let id = DIDURLBuf::from_string(format!("did:key:{fragment}#{fragment}"))
                .expect("DIDKey is expected to generate a valid DIDURL");

            let controller = id.did().as_uri().to_owned();

            Ok(
                DynamicVerificationMethod::EcdsaSecp256r1VerificationKey2019(
                    EcdsaSecp256r1VerificationKey2019::from_public_key(
                        id.into_iri(),
                        controller,
                        public_key,
                    ),
                ),
            )
        }
        Params::OKP(okp) => match &*okp.curve {
            "Ed25519" => {
                let public_key = ed25519_dalek::VerifyingKey::try_from(okp)?;
                let fragment = teddybear_did_key::Ed25519::fragment(&public_key);

                let id = DIDURLBuf::from_string(format!("did:key:{fragment}#{fragment}"))
                    .expect("DIDKey is expected to generate a valid DIDURL");

                let controller = id.did().as_uri().to_owned();

                Ok(DynamicVerificationMethod::Ed25519VerificationKey2020(
                    Ed25519VerificationKey2020::from_public_key(
                        id.into_iri(),
                        controller,
                        public_key,
                    ),
                ))
            }
            _ => Err(Error::UnsupportedKeyType),
        },
        _ => Err(Error::UnsupportedKeyType),
    }
}
