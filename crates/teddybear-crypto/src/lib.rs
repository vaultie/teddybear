use ssi_dids::{did_resolve::easy_resolve, DIDMethod, Document, Source, VerificationMethod};
use ssi_jwk::{Base64urlUInt, OctetParams, Params};
use teddybear_did_key::DidKey;
use thiserror::Error;

pub use ssi_jwk::JWK;

#[derive(Error, Debug)]
pub enum ResolveError {
    #[error("jwk error: {0}")]
    Jwk(#[from] ssi_jwk::Error),

    #[error("multibase decode error: {0}")]
    MultibaseError(#[from] multibase::Error),

    #[error("did resolve error: {0}")]
    DidResolve(#[from] ssi_dids::Error),
}

#[derive(Debug)]
pub struct KeyInfo {
    pub id: String,
    jwk: JWK,
}

#[derive(Debug)]
pub struct Ed25519 {
    pub ed25519: KeyInfo,
    pub x25519: KeyInfo,
}

impl Ed25519 {
    pub async fn generate() -> Result<Ed25519, ResolveError> {
        Ed25519::from_jwk(JWK::generate_ed25519().unwrap()).await
    }

    pub async fn from_jwk(jwk: JWK) -> Result<Ed25519, ResolveError> {
        let did = DidKey
            .generate(&Source::Key(&jwk))
            .expect("ed25519 key should produce a correct did document");
        let document = easy_resolve(&did, &DidKey).await?;

        let ed25519_id = first_verification_method(document.verification_method.as_deref())
            .expect("at least one key is expected")
            .get_id(&document.id);

        let x25519 = extract_key_info(
            String::from("X25519"),
            &document,
            first_verification_method(document.key_agreement.as_deref())
                .expect("at least one key is expected"),
        )?;

        Ok(Ed25519 {
            ed25519: KeyInfo {
                id: ed25519_id,
                jwk,
            },
            x25519,
        })
    }

    pub async fn from_did(did: &str) -> Result<Ed25519, ResolveError> {
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

        Ok(Ed25519 { ed25519, x25519 })
    }

    pub fn to_ed25519_public_jwk(&self) -> JWK {
        self.ed25519.jwk.to_public()
    }

    pub fn to_x25519_public_jwk(&self) -> JWK {
        self.x25519.jwk.to_public()
    }

    pub fn ed25519_did(&self) -> &str {
        &self.ed25519.id
    }

    pub fn x25519_did(&self) -> &str {
        &self.x25519.id
    }
}

fn extract_key_info(
    curve: String,
    document: &Document,
    verification_method: &VerificationMethod,
) -> Result<KeyInfo, ResolveError> {
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

    Ok(KeyInfo {
        id,
        jwk: JWK::from(Params::OKP(OctetParams {
            curve,
            public_key: Base64urlUInt(public_key[2..].to_owned()),
            private_key: None,
        })),
    })
}

fn first_verification_method(
    verification_methods: Option<&[VerificationMethod]>,
) -> Option<&VerificationMethod> {
    verification_methods.and_then(|methods| methods.first())
}
