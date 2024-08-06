mod credential_ref;

use itertools::Itertools;
use ssi_claims::{
    data_integrity::{
        suites::Ed25519Signature2020, CryptographicSuite, DataIntegrity, ProofOptions,
    },
    Invalid, InvalidClaims, ProofValidationError, SignatureEnvironment, SignatureError,
    ValidateClaims, ValidateProof, VerifiableClaims, VerificationParameters,
};
use ssi_dids_core::VerificationMethodDIDResolver;
use ssi_vc::v2::{Credential, Presentation};
use ssi_verification_methods::{Ed25519VerificationKey2020, ProofPurpose, ReferenceOrOwned};
use teddybear_crypto::{DidKey, Ed25519, Private, Public};

pub use ssi_json_ld::ContextLoader;
pub use ssi_vc::v2::syntax::{JsonCredential, JsonPresentation};

use crate::credential_ref::CredentialRef;

pub type DI<V> = DataIntegrity<V, Ed25519Signature2020>;

type CustomResolver = VerificationMethodDIDResolver<DidKey, Ed25519VerificationKey2020>;

type CustomVerificationParameters<'a> =
    VerificationParameters<CustomResolver, &'a mut ContextLoader>;

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
    let resolver = CustomResolver::new(DidKey);

    let params = VerificationParameters::<&CustomResolver, _, _>::from_resolver(&resolver)
        .with_json_ld_loader(&context_loader);

    credential.validate_credential(&params)?;

    let verification_method = Ed25519VerificationKey2020::from_public_key(
        key.ed25519.id().as_iri().to_owned(),
        key.document().id.as_uri().to_owned(),
        key.raw_signing_key().verifying_key(),
    );

    Ok(Ed25519Signature2020
        .sign_with(
            SignatureEnvironment {
                json_ld_loader: context_loader,
                eip712_loader: (),
            },
            CredentialRef(credential),
            resolver,
            key,
            ProofOptions::from_method(ReferenceOrOwned::Owned(verification_method)),
            (),
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
    let resolver = CustomResolver::new(DidKey);

    let params = VerificationParameters::<&CustomResolver, _, _>::from_resolver(&resolver)
        .with_json_ld_loader(&context_loader);

    for vc in presentation.verifiable_credentials() {
        vc.validate_credential(&params)?;
    }

    let resolver = CustomResolver::new(DidKey);

    let verification_method = Ed25519VerificationKey2020::from_public_key(
        key.ed25519.id().as_iri().to_owned(),
        key.document().id.as_uri().to_owned(),
        key.raw_signing_key().verifying_key(),
    );

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
                verification_method: Some(ReferenceOrOwned::Owned(verification_method)),
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
) -> Result<(Ed25519<Public>, Option<&'a str>), Error>
where
    <DI<V> as VerifiableClaims>::Claims:
        ValidateClaims<CustomVerificationParameters<'b>, <DI<V> as VerifiableClaims>::Proof>,
    <DI<V> as VerifiableClaims>::Proof:
        ValidateProof<CustomVerificationParameters<'b>, <DI<V> as VerifiableClaims>::Claims>,
{
    let resolver = CustomResolver::new(DidKey);

    let params =
        VerificationParameters::from_resolver(resolver).with_json_ld_loader(context_loader);

    value.verify(params).await??;

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
