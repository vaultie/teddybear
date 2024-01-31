use std::marker::PhantomData;

use ed25519_dalek::SigningKey;
use ssi_dids::{did_resolve::easy_resolve, DIDMethod, Document, Source, VerificationMethod};
use ssi_jwk::{Algorithm, Base64urlUInt, OctetParams, Params};
use ssi_jws::{
    decode_jws_parts, encode_sign_custom_header, split_jws, verify_bytes, DecodedJWS, Header,
};
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
    DidResolve(#[from] ssi_dids::Error),
}

#[derive(Clone, Debug)]
pub struct KeyInfo {
    jwk: JWK,
}

#[derive(Copy, Clone, Debug)]
pub struct Public;

#[derive(Copy, Clone, Debug)]
pub struct Private;

#[derive(Clone, Debug)]
pub struct Ed25519<T> {
    document: Document,
    pub ed25519: KeyInfo,
    pub x25519: KeyInfo,
    __type: PhantomData<T>,
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

        let (document, ed25519, mut x25519) = Ed25519::<()>::parts_from_jwk(jwk).await?;

        match &mut x25519.jwk.params {
            Params::OKP(okp) => {
                okp.private_key = Some(Base64urlUInt(key.to_scalar_bytes().to_vec()))
            }
            _ => unreachable!("X25519 keys should always have OKP params"),
        }

        Ok(Self {
            document,
            ed25519,
            x25519,
            __type: PhantomData,
        })
    }

    #[inline]
    pub fn sign(&self, payload: &str) -> Result<String, ssi_jws::Error> {
        let header = Header {
            algorithm: Algorithm::EdDSA,
            key_id: self.ed25519.jwk.key_id.clone(),
            jwk: Some(self.to_ed25519_public_jwk()),
            ..Default::default()
        };

        encode_sign_custom_header(payload, &self.ed25519.jwk, &header)
    }

    #[inline]
    pub fn as_ed25519_private_jwk(&self) -> &JWK {
        &self.ed25519.jwk
    }

    #[inline]
    pub fn as_x25519_private_jwk(&self) -> &JWK {
        &self.x25519.jwk
    }
}

impl Ed25519<Public> {
    pub async fn from_jwk(jwk: JWK) -> Result<Self, Error> {
        let (document, ed25519, x25519) = Ed25519::<()>::parts_from_jwk(jwk).await?;

        Ok(Self {
            document,
            ed25519,
            x25519,
            __type: PhantomData,
        })
    }

    pub async fn from_did(did: &str) -> Result<Self, Error> {
        let document = easy_resolve(did, &DidKey).await?;

        let ed25519 = extract_key_info(
            String::from("Ed25519"),
            &document,
            first_verification_method(document.verification_method.as_deref())
                .expect("teddybear-did-key should provide at least one ed25519 key"),
        )?;

        let x25519 = extract_key_info(
            String::from("X25519"),
            &document,
            first_verification_method(document.key_agreement.as_deref())
                .expect("teddybear-did-key should provide at least one x25519 key"),
        )?;

        Ok(Self {
            document,
            ed25519,
            x25519,
            __type: PhantomData,
        })
    }
}

impl<T> Ed25519<T> {
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
            .generate(&Source::Key(&jwk))
            .expect("ed25519 key should produce a correct did document");

        let document = easy_resolve(&did, &DidKey).await?;

        jwk.key_id = Some(
            first_verification_method(document.verification_method.as_deref())
                .expect("at least one key is expected")
                .get_id(&document.id),
        );
        jwk.algorithm = Some(Algorithm::EdDSA);

        let x25519 = extract_key_info(
            String::from("X25519"),
            &document,
            first_verification_method(document.key_agreement.as_deref())
                .expect("at least one key is expected"),
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

pub fn verify_jws_with_embedded_jwk(jws: &str) -> Result<(JWK, Vec<u8>), Error> {
    let (header_b64, payload_enc, signature_b64) = split_jws(jws)?;

    let DecodedJWS {
        header,
        signing_input,
        payload,
        signature,
    } = decode_jws_parts(header_b64, payload_enc.as_bytes(), signature_b64)?;

    let key = header.jwk.ok_or(ssi_jws::Error::InvalidSignature)?;

    verify_bytes(header.algorithm, &signing_input, &key, &signature)?;

    Ok((key, payload))
}

#[inline]
fn extract_key_info(
    curve: String,
    document: &Document,
    verification_method: &VerificationMethod,
) -> Result<KeyInfo, Error> {
    let id = verification_method.get_id(&document.id);

    let public_key_multibase = match verification_method {
        VerificationMethod::Map(map) => map
            .property_set
            .as_ref()
            .and_then(|val| val.get("publicKeyMultibase").and_then(|val| val.as_str()))
            .expect("publicKeyMultibase should always be present"),
        _ => unreachable!(),
    };

    let public_key = multibase::decode(public_key_multibase)?.1;

    let mut jwk = JWK::from(Params::OKP(OctetParams {
        curve,
        public_key: Base64urlUInt(public_key[2..].to_owned()),
        private_key: None,
    }));

    jwk.key_id = Some(id);
    jwk.algorithm = Some(Algorithm::EdDSA);

    Ok(KeyInfo { jwk })
}

#[inline]
fn first_verification_method(
    verification_methods: Option<&[VerificationMethod]>,
) -> Option<&VerificationMethod> {
    verification_methods.and_then(|methods| methods.first())
}
