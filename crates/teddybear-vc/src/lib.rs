mod credential_ref;

use ed25519_dalek::SigningKey;
use itertools::Itertools;
use ssi_claims::{
    data_integrity::{
        suites::Ed25519Signature2020, CryptographicSuite, DataIntegrity, ProofOptions,
    },
    Invalid, InvalidClaims, ProofValidationError, SignatureEnvironment, SignatureError,
    ValidateClaims, ValidateProof, VerifiableClaims, VerificationParameters,
};
use ssi_vc::v2::{Credential, Presentation};
use ssi_verification_methods::{
    Ed25519VerificationKey2020, ProofPurpose, ReferenceOrOwned, SingleSecretSigner,
};
use teddybear_crypto::{default_did_method, CustomVerificationMethodDIDResolver};

use crate::credential_ref::CredentialRef;

pub use ssi_json_ld::ContextLoader;
pub use ssi_vc::v2::syntax::{JsonCredential, JsonPresentation};

pub type DI<V> = DataIntegrity<V, Ed25519Signature2020>;

type CustomVerificationParameters<'a> =
    VerificationParameters<CustomVerificationMethodDIDResolver, &'a mut ContextLoader>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("expected a document with a single proof")]
    SingleProofOnly,

    #[error(transparent)]
    SignatureError(#[from] SignatureError),

    #[error(transparent)]
    InvalidClaims(#[from] InvalidClaims),

    #[error(transparent)]
    Invalid(#[from] Invalid),

    #[error(transparent)]
    ProofValidationError(#[from] ProofValidationError),
}

type SignedEd25519Credential<'a> = DI<CredentialRef<'a, JsonCredential>>;

#[inline]
pub async fn issue_vc<'a>(
    key: SigningKey,
    credential: &'a JsonCredential,
    context_loader: &mut ContextLoader,
) -> Result<SignedEd25519Credential<'a>, Error> {
    let resolver = CustomVerificationMethodDIDResolver::new(default_did_method());

    let params =
        VerificationParameters::from_resolver(&resolver).with_json_ld_loader(&context_loader);

    credential.validate_credential(&params)?;

    Ok(Ed25519Signature2020
        .sign_with(
            SignatureEnvironment {
                json_ld_loader: context_loader,
                eip712_loader: (),
            },
            CredentialRef(credential),
            resolver,
            SingleSecretSigner::new(key),
            ProofOptions::default(),
            (),
        )
        .await?)
}

type SignedEd25519Presentation<'a> = DI<CredentialRef<'a, JsonPresentation>>;

#[inline]
pub async fn present_vp<'a>(
    key: SigningKey,
    presentation: &'a JsonPresentation,
    domain: Option<String>,
    challenge: Option<String>,
    context_loader: &mut ContextLoader,
) -> Result<SignedEd25519Presentation<'a>, Error> {
    let resolver = CustomVerificationMethodDIDResolver::new(default_did_method());

    let params =
        VerificationParameters::from_resolver(&resolver).with_json_ld_loader(&context_loader);

    for vc in presentation.verifiable_credentials() {
        vc.validate_credential(&params)?;
    }

    Ok(Ed25519Signature2020
        .sign_with(
            SignatureEnvironment {
                json_ld_loader: context_loader,
                eip712_loader: (),
            },
            CredentialRef(presentation),
            resolver,
            SingleSecretSigner::new(key),
            ProofOptions {
                proof_purpose: ProofPurpose::Authentication,
                domains: domain.map(|val| vec![val]).unwrap_or_default(),
                challenge,
                ..Default::default()
            },
            (),
        )
        .await?)
}

pub async fn verify<'a, 'b, V>(
    value: &'a DI<V>,
    context_loader: &'b mut ContextLoader,
) -> Result<(&'a Ed25519VerificationKey2020, Option<&'a str>), Error>
where
    <DI<V> as VerifiableClaims>::Claims:
        ValidateClaims<CustomVerificationParameters<'b>, <DI<V> as VerifiableClaims>::Proof>,
    <DI<V> as VerifiableClaims>::Proof:
        ValidateProof<CustomVerificationParameters<'b>, <DI<V> as VerifiableClaims>::Claims>,
{
    let resolver = CustomVerificationMethodDIDResolver::new(default_did_method());

    let params =
        VerificationParameters::from_resolver(resolver).with_json_ld_loader(context_loader);

    value.verify(params).await??;

    let proof = value
        .proof()
        .iter()
        .exactly_one()
        .map_err(|_| Error::SingleProofOnly)?;

    let verification_method = match &proof.verification_method {
        ReferenceOrOwned::Owned(key) => key,
        _ => return Err(Error::SingleProofOnly),
    };

    Ok((verification_method, proof.challenge.as_deref()))
}
