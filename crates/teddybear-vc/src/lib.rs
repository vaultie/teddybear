mod credential_ref;

use itertools::Itertools;
use ssi_claims::{
    chrono::Utc,
    data_integrity::{
        suites::Ed25519Signature2020, CryptographicSuite, DataIntegrity, ProofOptions,
    },
    Invalid, InvalidClaims, ProofValidationError, SignatureEnvironment, SignatureError, Validate,
    ValidateProof, VerifiableClaims, VerificationEnvironment,
};
use ssi_dids_core::VerificationMethodDIDResolver;
use ssi_vc::v2::{Credential, Presentation};
use ssi_verification_methods::{Ed25519VerificationKey2020, ProofPurpose, ReferenceOrOwned};
use teddybear_crypto::{DidKey, Ed25519, Private, Public};

pub use ssi_json_ld::ContextLoader;
pub use ssi_vc::v2::syntax::{JsonCredential, JsonPresentation};

use crate::credential_ref::CredentialRef;

pub type DI<V> = DataIntegrity<V, Ed25519Signature2020>;

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
    key: &Ed25519<Private>,
    credential: &'a JsonCredential,
    context_loader: &mut ContextLoader,
) -> Result<SignedEd25519Credential<'a>, Error> {
    credential.validate_credential(&())?;

    let resolver = VerificationMethodDIDResolver::<_, Ed25519VerificationKey2020>::new(DidKey);

    Ok(Ed25519Signature2020
        .sign_with(
            SignatureEnvironment {
                json_ld_loader: context_loader,
                eip712_loader: (),
            },
            CredentialRef(credential),
            resolver,
            key,
            ProofOptions {
                ..Default::default()
            },
        )
        .await?)
}

type SignedEd25519Presentation<'a> = DI<CredentialRef<'a, JsonPresentation>>;

#[inline]
pub async fn present_vp<'a>(
    key: &Ed25519<Private>,
    presentation: &'a JsonPresentation,
    domain: Option<String>,
    challenge: Option<String>,
    context_loader: &mut ContextLoader,
) -> Result<SignedEd25519Presentation<'a>, Error> {
    for vc in presentation.verifiable_credentials() {
        vc.validate_credential(&())?;
    }

    let resolver = VerificationMethodDIDResolver::<_, Ed25519VerificationKey2020>::new(DidKey);

    Ok(Ed25519Signature2020
        .sign_with(
            SignatureEnvironment {
                json_ld_loader: context_loader,
                eip712_loader: (),
            },
            CredentialRef(presentation),
            resolver,
            key,
            ProofOptions {
                proof_purpose: ProofPurpose::Authentication,
                domains: domain.map(|val| vec![val]).unwrap_or_default(),
                challenge,
                ..Default::default()
            },
        )
        .await?)
}

type CustomVerificationEnvironment<'a> = VerificationEnvironment<&'a mut ContextLoader>;

pub async fn verify<'a, 'b, V>(
    value: &'a DI<V>,
    context_loader: &'b mut ContextLoader,
) -> Result<(Ed25519<Public>, Option<&'a str>), Error>
where
    <DI<V> as VerifiableClaims>::Claims:
        Validate<CustomVerificationEnvironment<'b>, <DI<V> as VerifiableClaims>::Proof>,
    <DI<V> as VerifiableClaims>::Proof: ValidateProof<
        <DI<V> as VerifiableClaims>::Claims,
        CustomVerificationEnvironment<'b>,
        VerificationMethodDIDResolver<DidKey, Ed25519VerificationKey2020>,
    >,
{
    let verifier = VerificationMethodDIDResolver::<_, Ed25519VerificationKey2020>::new(DidKey);

    value
        .verify_with(
            &verifier,
            VerificationEnvironment {
                date_time: Utc::now(),
                json_ld_loader: context_loader,
                eip712_loader: (),
            },
        )
        .await??;

    let proof = value
        .proof()
        .iter()
        .exactly_one()
        .map_err(|_| Error::SingleProofOnly)?;

    // FIXME: Remove this conversion by using Ed25519 as a verification method directly
    let verification_method = match &proof.verification_method {
        ReferenceOrOwned::Owned(key) => Ed25519::from_jwk(key.public_key_jwk())
            .await
            .expect("verification method jwk is always expected to be valid"),
        _ => return Err(Error::SingleProofOnly),
    };

    Ok((verification_method, proof.challenge.as_deref()))
}
