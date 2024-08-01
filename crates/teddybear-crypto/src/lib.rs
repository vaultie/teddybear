use std::{borrow::Cow, sync::Arc};

use ed25519_dalek::SigningKey;
use ssi_dids_core::{
    document::DIDVerificationMethod, method_resolver::VerificationMethodDIDResolver,
    resolution::Options, DIDResolver, Document, Unexpected, DID,
};
use ssi_jwk::{Algorithm, Base64urlUInt, OctetParams, Params};
use ssi_jws::{
    decode_jws_parts, decode_verify, encode_sign_custom_header, split_jws, verify_bytes, Header,
};
use ssi_verification_methods::{Ed25519VerificationKey2020, MethodWithSecret, Signer};
use thiserror::Error;

pub use ssi_jwk::JWK;
pub use teddybear_did_key::DidKey;

#[derive(Error, Debug)]
pub enum Error {
    #[error("provided JWK is missing a private key value")]
    MissingPrivateKey,

    #[error(transparent)]
    Ed25519(#[from] ed25519_dalek::SignatureError),

    #[error(transparent)]
    Jwk(#[from] ssi_jwk::Error),

    #[error(transparent)]
    Jws(#[from] ssi_jws::Error),

    #[error(transparent)]
    MultibaseError(#[from] multibase::Error),

    #[error(transparent)]
    InvalidDid(#[from] Unexpected),

    #[error(transparent)]
    DidResolve(#[from] ssi_dids_core::resolution::Error),
}

#[derive(Clone, Debug)]
pub struct KeyInfo {
    jwk: JWK,
}

#[derive(Clone, Debug)]
pub struct Public;

#[derive(Clone, Debug)]
pub struct Private {
    signing_key: SigningKey,
}

#[derive(Clone, Debug)]
pub struct Ed25519<T> {
    raw: T,
    document: Document,
    pub ed25519: KeyInfo,
    pub x25519: KeyInfo,
}

impl Ed25519<Private> {
    pub async fn generate() -> Result<Self, Error> {
        Self::from_private_jwk(
            JWK::generate_ed25519().expect("ed25519 should always generate successfully"),
        )
        .await
    }

    pub async fn from_private_jwk(jwk: JWK) -> Result<Self, Error> {
        let private_key = match &jwk.params {
            Params::OKP(okp) => okp.private_key.as_ref(),
            _ => None,
        };

        let key = SigningKey::try_from(&*private_key.ok_or(Error::MissingPrivateKey)?.0)?;

        Self::from_signing_key(key, jwk).await
    }

    pub async fn from_bytes(value: [u8; 32]) -> Result<Self, Error> {
        let key = SigningKey::from_bytes(&value);

        let jwk = JWK::from(Params::OKP(OctetParams {
            curve: "Ed25519".to_string(),
            public_key: Base64urlUInt(key.verifying_key().as_bytes().to_vec()),
            private_key: Some(Base64urlUInt(value.to_vec())),
        }));

        Self::from_signing_key(key, jwk).await
    }

    #[inline]
    pub fn sign(&self, payload: &str, embed_signing_key: bool) -> Result<String, ssi_jws::Error> {
        let header = Header {
            algorithm: Algorithm::EdDSA,
            key_id: if embed_signing_key {
                self.ed25519.jwk.key_id.clone()
            } else {
                None
            },
            jwk: embed_signing_key.then(|| self.to_ed25519_public_jwk()),
            ..Default::default()
        };

        encode_sign_custom_header(payload, &self.ed25519.jwk, &header)
    }

    #[inline]
    pub fn raw_signing_key(&self) -> &SigningKey {
        &self.raw.signing_key
    }

    #[inline]
    pub fn as_ed25519_private_jwk(&self) -> &JWK {
        &self.ed25519.jwk
    }

    #[inline]
    pub fn as_x25519_private_jwk(&self) -> &JWK {
        &self.x25519.jwk
    }

    async fn from_signing_key(signing_key: SigningKey, jwk: JWK) -> Result<Self, Error> {
        let (document, ed25519, mut x25519) = Ed25519::<()>::parts_from_jwk(jwk).await?;

        match &mut x25519.jwk.params {
            Params::OKP(okp) => {
                okp.private_key = Some(Base64urlUInt(signing_key.to_scalar_bytes().to_vec()))
            }
            _ => unreachable!("X25519 keys should always have OKP params"),
        }

        Ok(Self {
            document,
            ed25519,
            x25519,
            raw: Private { signing_key },
        })
    }
}

impl Ed25519<Public> {
    pub async fn from_jwk(jwk: JWK) -> Result<Self, Error> {
        let (document, ed25519, x25519) = Ed25519::<()>::parts_from_jwk(jwk).await?;

        Ok(Self {
            document,
            ed25519,
            x25519,
            raw: Public,
        })
    }

    pub async fn from_did(did: &str) -> Result<Self, Error> {
        let did = DID::new(did).map_err(|e| e.1)?;

        let document = VerificationMethodDIDResolver::<_, Ed25519VerificationKey2020>::new(DidKey)
            .resolve_with(did, Options::default())
            .await?
            .document
            .into_document();

        let ed25519 = extract_key_info(
            String::from("Ed25519"),
            document
                .verification_method
                .first()
                .expect("teddybear-did-key should provide at least one ed25519 key"),
        )?;

        let x25519 = extract_key_info(
            String::from("X25519"),
            document
                .verification_relationships
                .key_agreement
                .first()
                .and_then(|val| val.as_value())
                .expect("teddybear-did-key should provide at least one x25519 key"),
        )?;

        Ok(Self {
            document,
            ed25519,
            x25519,
            raw: Public,
        })
    }
}

impl<T> Ed25519<T> {
    #[inline]
    pub fn document(&self) -> &Document {
        &self.document
    }

    #[inline]
    pub fn document_did(&self) -> &str {
        &self.document.id
    }

    #[inline]
    pub fn to_ed25519_public_jwk(&self) -> JWK {
        self.ed25519.jwk.to_public()
    }

    #[inline]
    pub fn to_x25519_public_jwk(&self) -> JWK {
        self.x25519.jwk.to_public()
    }

    #[inline]
    pub fn ed25519_did(&self) -> &str {
        self.ed25519
            .jwk
            .key_id
            .as_deref()
            .expect("key id should always be present")
    }

    #[inline]
    pub fn x25519_did(&self) -> &str {
        self.x25519
            .jwk
            .key_id
            .as_deref()
            .expect("key id should always be present")
    }

    async fn parts_from_jwk(mut jwk: JWK) -> Result<(Document, KeyInfo, KeyInfo), Error> {
        let did = DidKey
            .generate(&jwk)
            .expect("ed25519 key should produce a correct did document");

        let document = VerificationMethodDIDResolver::<_, Ed25519VerificationKey2020>::new(DidKey)
            .resolve_with(did.as_did(), Options::default())
            .await?
            .document
            .into_document();

        jwk.key_id = Some(
            document
                .verification_method
                .first()
                .expect("at least one key is expected")
                .id
                .to_string(),
        );
        jwk.algorithm = Some(Algorithm::EdDSA);

        let x25519 = extract_key_info(
            String::from("X25519"),
            document
                .verification_relationships
                .key_agreement
                .first()
                .and_then(|val| val.as_value())
                .expect("teddybear-did-key should provide at least one x25519 key"),
        )?;

        Ok((document, KeyInfo { jwk }, x25519))
    }
}

impl<T, U> PartialEq<Ed25519<U>> for Ed25519<T> {
    fn eq(&self, other: &Ed25519<U>) -> bool {
        self.ed25519.jwk.equals_public(&other.ed25519.jwk)
    }
}

impl<T> PartialEq<JWK> for Ed25519<T> {
    fn eq(&self, other: &JWK) -> bool {
        self.ed25519.jwk.equals_public(other)
    }
}

impl Signer<Ed25519VerificationKey2020> for Ed25519<Private> {
    type MessageSigner = MethodWithSecret<Ed25519VerificationKey2020, JWK>;

    async fn for_method(
        &self,
        method: Cow<'_, Ed25519VerificationKey2020>,
    ) -> Result<Option<Self::MessageSigner>, ssi_claims::SignatureError> {
        if method.id.as_str() != self.ed25519_did() {
            return Ok(None);
        }

        Ok(Some(MethodWithSecret::new(
            method.into_owned(),
            Arc::new(self.ed25519.jwk.clone()),
        )))
    }
}

#[inline]
pub fn verify_jws(jws: &str, key: &JWK) -> Result<Vec<u8>, Error> {
    Ok(decode_verify(jws, key)?.1)
}

#[inline]
pub fn verify_jws_with_embedded_jwk(jws: &str) -> Result<(JWK, Vec<u8>), Error> {
    let (header_b64, payload_enc, signature_b64) = split_jws(jws)?;

    let (jws, signing_bytes) = decode_jws_parts(header_b64, payload_enc.as_bytes(), signature_b64)?
        .into_jws_and_signing_bytes();

    let key = jws.header.jwk.ok_or(ssi_jws::Error::InvalidJWS)?;

    verify_bytes(jws.header.algorithm, &signing_bytes, &key, &jws.signature)?;

    Ok((key, jws.payload))
}

#[inline]
fn extract_key_info(
    curve: String,
    verification_method: &DIDVerificationMethod,
) -> Result<KeyInfo, Error> {
    let public_key_multibase = verification_method
        .properties
        .get("publicKeyMultibase")
        .and_then(|val| val.as_str())
        .expect("publicKeyMultibase should always be present");

    let public_key = multibase::decode(public_key_multibase)?.1;

    let mut jwk = JWK::from(Params::OKP(OctetParams {
        curve,
        public_key: Base64urlUInt(public_key[2..].to_owned()),
        private_key: None,
    }));

    jwk.key_id = Some(verification_method.id.to_string());
    jwk.algorithm = Some(Algorithm::EdDSA);

    Ok(KeyInfo { jwk })
}
