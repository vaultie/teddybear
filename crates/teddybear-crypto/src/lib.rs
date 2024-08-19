mod okp_encoder;
mod x25519;

use std::borrow::Cow;

use did_web::DIDWeb;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use ssi_dids_core::{
    document::{verification_method::ValueOrReference, DIDVerificationMethod, ResourceRef},
    ssi_json_ld::Iri,
    DIDBuf, DIDURLReference, DIDURLReferenceBuf, InvalidDIDURL, VerificationMethodDIDResolver,
};
use ssi_jwk::{Algorithm, Params};
use ssi_jws::{
    decode_jws_parts, decode_verify, encode_sign_custom_header, split_jws, verify_bytes, Header,
};
use ssi_security::MultibaseBuf;
use ssi_verification_methods::{
    ControllerError, ControllerProvider, GenericVerificationMethod, InvalidVerificationMethod,
    ProofPurpose,
};
use teddybear_did_key::DIDKey;
use teddybear_high_assurance::DnsError;

use crate::okp_encoder::OKPEncoder;

pub use ssi_dids_core::{
    ssi_json_ld::{iref::UriBuf, IriBuf},
    DIDURLBuf, DID, DIDURL,
};
pub use ssi_jwk::JWK;
pub use ssi_verification_methods::{Ed25519VerificationKey2020, JwkVerificationMethod};

pub use crate::x25519::X25519KeyAgreementKey2020;

const DEFAULT_RESOLVER: &str = "https://cloudflare-dns.com/dns-query";

pub type SupportedDIDMethods = (DIDKey, DIDWeb);

pub fn default_did_method() -> SupportedDIDMethods {
    (DIDKey, DIDWeb)
}

pub type CustomVerificationMethodDIDResolver =
    VerificationMethodDIDResolver<SupportedDIDMethods, Ed25519VerificationKey2020>;

#[derive(Debug, thiserror::Error)]
pub enum Ed25519Error {
    #[error("invalid key identifier")]
    InvalidKeyIdentifier,

    #[error("invalid JWK type")]
    InvalidJWKType,

    #[error("missing private key value")]
    MissingPrivateKey,

    #[error("invalid private key value")]
    InvalidPrivateKeyValue,

    #[error("resource not found")]
    ResourceNotFound,

    #[error("invalid resource type")]
    InvalidResourceType,

    #[error("high assurance verification failed")]
    HighAssuranceVerificationFailed,

    #[error("{0}")]
    ControllerError(String),

    #[error(transparent)]
    InvalidDIDUrl(#[from] InvalidDIDURL<String>),

    #[error(transparent)]
    InvalidVerificationMethod(#[from] InvalidVerificationMethod),

    #[error(transparent)]
    DnsError(#[from] DnsError),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Document {
    inner: ssi_dids_core::Document,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct DocumentResolveOptions<'a> {
    /// Whether to require high assurance DID verification.
    require_high_assurance_verification: bool,

    /// Preferred DNS-over-HTTPS resolver.
    dns_over_https_resolver: Option<Cow<'a, str>>,
}

fn proof_purpose_iter<'a, I: IntoIterator<Item = &'a ValueOrReference>>(
    proof_purpose: ProofPurpose,
    values: I,
) -> impl Iterator<Item = (ProofPurpose, DIDURLReference<'a>)> {
    values.into_iter().map(move |vr| (proof_purpose, vr.id()))
}

impl Document {
    pub async fn create<PI: IntoIterator<Item = ProofPurpose>>(
        id: DIDBuf,
        keys: Vec<(DIDVerificationMethod, PI)>,
    ) -> Result<Self, Ed25519Error> {
        let mut inner = ssi_dids_core::Document::new(id);

        for (key, purposes) in keys {
            for purpose in purposes {
                let reference =
                    ValueOrReference::Reference(DIDURLReferenceBuf::Absolute(key.id.clone()));

                match purpose {
                    ProofPurpose::Assertion => inner
                        .verification_relationships
                        .assertion_method
                        .push(reference),
                    ProofPurpose::Authentication => inner
                        .verification_relationships
                        .authentication
                        .push(reference),
                    ProofPurpose::CapabilityInvocation => inner
                        .verification_relationships
                        .capability_invocation
                        .push(reference),
                    ProofPurpose::CapabilityDelegation => inner
                        .verification_relationships
                        .capability_delegation
                        .push(reference),
                    ProofPurpose::KeyAgreement => inner
                        .verification_relationships
                        .key_agreement
                        .push(reference),
                }
            }

            inner.verification_method.push(key);
        }

        Ok(Self { inner })
    }

    pub async fn resolve(
        id: &Iri,
        options: DocumentResolveOptions<'_>,
    ) -> Result<Self, Ed25519Error> {
        let inner = CustomVerificationMethodDIDResolver::new(default_did_method())
            .require_controller(id)
            .await
            .map_err(|e| match e {
                ControllerError::NotFound(e) => Ed25519Error::ControllerError(e),
                ControllerError::Invalid => {
                    Ed25519Error::ControllerError("Invalid controller".to_string())
                }
                ControllerError::Unsupported(e) => Ed25519Error::ControllerError(e),
                ControllerError::InternalError(e) => Ed25519Error::ControllerError(e),
            })?;

        if options.require_high_assurance_verification {
            // FIXME: Implement other parts of the RFC.
            if let Some(vm) = id.strip_prefix("did:web:") {
                if let Some(resolved_name) = teddybear_high_assurance::resolve_uri_record(
                    options
                        .dns_over_https_resolver
                        .as_deref()
                        .unwrap_or(DEFAULT_RESOLVER),
                    &format!("_did.{vm}"),
                )
                .await?
                {
                    if id.as_str() != resolved_name {
                        return Err(Ed25519Error::HighAssuranceVerificationFailed);
                    }
                }
            }
        }

        Ok(Self { inner })
    }

    pub fn verification_methods(&self) -> impl Iterator<Item = (ProofPurpose, DIDURLBuf)> + '_ {
        proof_purpose_iter(
            ProofPurpose::Authentication,
            &self.inner.verification_relationships.authentication,
        )
        .chain(proof_purpose_iter(
            ProofPurpose::Assertion,
            &self.inner.verification_relationships.assertion_method,
        ))
        .chain(proof_purpose_iter(
            ProofPurpose::KeyAgreement,
            &self.inner.verification_relationships.key_agreement,
        ))
        .chain(proof_purpose_iter(
            ProofPurpose::CapabilityInvocation,
            &self.inner.verification_relationships.capability_invocation,
        ))
        .chain(proof_purpose_iter(
            ProofPurpose::CapabilityDelegation,
            &self.inner.verification_relationships.capability_delegation,
        ))
        .map(|(proof_purpose, reference)| {
            (
                proof_purpose,
                reference.resolve(&self.inner.id).into_owned(),
            )
        })
    }

    pub fn get_verification_method<T, E>(&self, id: &DIDURL) -> Result<T, Ed25519Error>
    where
        T: TryFrom<GenericVerificationMethod, Error = E>,
        Ed25519Error: From<E>,
    {
        match self
            .inner
            .find_resource(id)
            .ok_or(Ed25519Error::ResourceNotFound)?
        {
            ResourceRef::VerificationMethod(vm) => {
                Ok(T::try_from(GenericVerificationMethod::from(vm.clone()))?)
            }
            ResourceRef::Document(_) => Err(Ed25519Error::InvalidResourceType),
        }
    }
}

pub struct PrivateEd25519 {
    inner: ed25519_dalek::SigningKey,
}

impl PrivateEd25519 {
    pub fn generate() -> Self {
        Self {
            inner: ed25519_dalek::SigningKey::generate(&mut OsRng),
        }
    }

    pub fn from_bytes(value: &[u8; 32]) -> Self {
        Self {
            inner: ed25519_dalek::SigningKey::from_bytes(value),
        }
    }

    pub fn inner(&self) -> &ed25519_dalek::SigningKey {
        &self.inner
    }

    pub fn to_x25519_private_key(&self) -> PrivateX25519 {
        PrivateX25519 {
            inner: x25519_dalek::StaticSecret::from(self.inner.to_scalar_bytes()),
        }
    }

    pub fn to_public_jwk(&self) -> JWK {
        JWK::from(Params::OKP(self.inner.verifying_key().encode_okp()))
    }

    pub fn to_private_jwk(&self) -> JWK {
        JWK::from(Params::OKP(self.inner.encode_okp()))
    }

    pub fn to_did_key(&self) -> DIDBuf {
        DIDKey.generate(&self.inner.verifying_key())
    }

    pub fn to_did_key_url_fragment(&self) -> MultibaseBuf {
        DIDKey.generate_ed25519_fragment(&self.inner.verifying_key())
    }

    pub fn to_verification_method(
        &self,
        id: IriBuf,
        controller: UriBuf,
    ) -> Ed25519VerificationKey2020 {
        Ed25519VerificationKey2020::from_public_key(id, controller, self.inner.verifying_key())
    }

    pub fn sign(&self, payload: &str, embed_signing_key: bool) -> Result<String, ssi_jws::Error> {
        let header = Header {
            algorithm: Algorithm::EdDSA,
            jwk: embed_signing_key.then(|| self.to_public_jwk()),
            ..Default::default()
        };

        encode_sign_custom_header(payload, &self.to_private_jwk(), &header)
    }
}

pub struct PrivateX25519 {
    inner: x25519_dalek::StaticSecret,
}

impl PrivateX25519 {
    pub fn inner(&self) -> &x25519_dalek::StaticSecret {
        &self.inner
    }

    pub fn to_public_jwk(&self) -> JWK {
        let public_key = x25519_dalek::PublicKey::from(&self.inner);
        JWK::from(Params::OKP(public_key.encode_okp()))
    }

    pub fn to_private_jwk(&self) -> JWK {
        JWK::from(Params::OKP(self.inner.encode_okp()))
    }

    pub fn to_did_key_url_fragment(&self) -> MultibaseBuf {
        DIDKey.generate_x25519_fragment(&x25519_dalek::PublicKey::from(&self.inner))
    }

    pub fn to_verification_method(
        &self,
        id: IriBuf,
        controller: UriBuf,
    ) -> X25519KeyAgreementKey2020 {
        let public_key = x25519_dalek::PublicKey::from(&self.inner);
        X25519KeyAgreementKey2020::from_public_key(id, controller, public_key)
    }
}

pub fn verify_jws(jws: &str, key: &JWK) -> Result<Vec<u8>, ssi_jws::Error> {
    Ok(decode_verify(jws, key)?.1)
}

pub fn verify_jws_with_embedded_jwk(jws: &str) -> Result<(JWK, Vec<u8>), ssi_jws::Error> {
    let (header_b64, payload_enc, signature_b64) = split_jws(jws)?;

    let (jws, signing_bytes) = decode_jws_parts(header_b64, payload_enc.as_bytes(), signature_b64)?
        .into_jws_and_signing_bytes();

    let key = jws.header.jwk.ok_or(ssi_jws::Error::InvalidJWS)?;

    verify_bytes(jws.header.algorithm, &signing_bytes, &key, &jws.signature)?;

    Ok((key, jws.payload))
}
