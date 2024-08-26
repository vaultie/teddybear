mod credential_ref;

use ed25519_dalek::SigningKey;
use itertools::Itertools;
use serde::Serialize;
use ssi_claims::{
    data_integrity::{
        suites::Ed25519Signature2020, CryptographicSuite, DataIntegrity, ProofOptions,
    },
    Invalid, InvalidClaims, ProofValidationError, SignatureEnvironment, SignatureError,
    ValidateProof, VerificationParameters,
};
use ssi_json_ld::IriBuf;
use ssi_verification_methods::{
    Ed25519VerificationKey2020, ProofPurpose, ReferenceOrOwned, SingleSecretSigner,
    VerificationMethodResolutionError, VerificationMethodResolver,
};
use teddybear_crypto::{default_did_method, CustomVerificationMethodDIDResolver, Uri, DIDURL};

use crate::credential_ref::CredentialRef;

pub use ssi_claims::{ValidateClaims, VerifiableClaims};
pub use ssi_json_ld::{ContextLoader, Expand, Expandable, JsonLdNodeObject, ValidId};
pub use ssi_vc::{
    syntax::{RequiredContext, RequiredContextList, RequiredType, RequiredTypeSet},
    v2::{
        syntax::{JsonPresentation, SpecializedJsonCredential},
        Credential, Presentation,
    },
    Identified,
};

pub type DI<V> = DataIntegrity<V, Ed25519Signature2020>;

pub type CustomVerificationParameters<'a, 'b> =
    VerificationParameters<&'a CustomVerificationMethodDIDResolver, &'b mut ContextLoader>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("expected a document with a single proof")]
    SingleProofOnly,

    #[error("missing claimed signer")]
    MissingClaimedSigner,

    #[error("invalid verification method identifier")]
    InvalidVmIdentifier,

    #[error(transparent)]
    SignatureError(#[from] SignatureError),

    #[error(transparent)]
    InvalidClaims(#[from] InvalidClaims),

    #[error(transparent)]
    Invalid(#[from] Invalid),

    #[error(transparent)]
    ProofValidationError(#[from] ProofValidationError),

    #[error(transparent)]
    VerificationMethodResolutionError(#[from] VerificationMethodResolutionError),
}

pub type SignedEd25519Credential<'a, C> = DI<CredentialRef<'a, C>>;

pub async fn issue_vc<'a, C>(
    key: SigningKey,
    verification_method: IriBuf,
    credential: &'a C,
    context_loader: &mut ContextLoader,
) -> Result<SignedEd25519Credential<'a, C>, Error>
where
    C: Credential + JsonLdNodeObject + Expandable,
{
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
            ProofOptions {
                verification_method: Some(ReferenceOrOwned::Reference(verification_method)),
                ..Default::default()
            },
            (),
        )
        .await?)
}

pub type SignedEd25519Presentation<'a, C> = DI<CredentialRef<'a, JsonPresentation<C>>>;

pub async fn present_vp<'a, C>(
    key: SigningKey,
    verification_method: IriBuf,
    presentation: &'a JsonPresentation<C>,
    domain: Option<String>,
    challenge: Option<String>,
    context_loader: &mut ContextLoader,
) -> Result<SignedEd25519Presentation<'a, C>, Error>
where
    C: Credential + JsonLdNodeObject + Expandable + Serialize,
{
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
                verification_method: Some(ReferenceOrOwned::Reference(verification_method)),
                challenge,
                ..Default::default()
            },
            (),
        )
        .await?)
}

pub trait HasClaimedSigner {
    fn claimed_signer(&self) -> Option<&Uri>;
}

impl<
        Subject,
        RequiredContext,
        RequiredType,
        Issuer,
        Status,
        Evidence,
        Schema,
        RefreshService,
        TermsOfUse,
        ExtraProperties,
    > HasClaimedSigner
    for SpecializedJsonCredential<
        Subject,
        RequiredContext,
        RequiredType,
        Issuer,
        Status,
        Evidence,
        Schema,
        RefreshService,
        TermsOfUse,
        ExtraProperties,
    >
where
    Issuer: Identified,
{
    fn claimed_signer(&self) -> Option<&Uri> {
        Some(self.issuer.id())
    }
}

impl<C> HasClaimedSigner for JsonPresentation<C>
where
    Self: Presentation,
{
    fn claimed_signer(&self) -> Option<&Uri> {
        // For now expect only a single credential holder.
        Some(self.holders().iter().exactly_one().ok()?.id())
    }
}

pub async fn verify<'a, 'b, V>(
    value: &'a DI<V>,
    context_loader: &'b mut ContextLoader,
) -> Result<(Ed25519VerificationKey2020, Option<&'a str>), Error>
where
    V: HasClaimedSigner,
    for<'r> <DI<V> as VerifiableClaims>::Claims:
        ValidateClaims<CustomVerificationParameters<'r, 'b>, <DI<V> as VerifiableClaims>::Proof>,
    for<'r> <DI<V> as VerifiableClaims>::Proof:
        ValidateProof<CustomVerificationParameters<'r, 'b>, <DI<V> as VerifiableClaims>::Claims>,
{
    let claimed_signer = value.claimed_signer().ok_or(Error::MissingClaimedSigner)?;

    let resolver = CustomVerificationMethodDIDResolver::new(default_did_method());

    let params =
        VerificationParameters::from_resolver(&resolver).with_json_ld_loader(context_loader);

    value.verify(params).await??;

    let proof = value
        .proof()
        .iter()
        .exactly_one()
        .map_err(|_| Error::SingleProofOnly)?;

    let verification_method = resolver
        .resolve_verification_method(None, Some(proof.verification_method.borrowed()))
        .await?;

    let vm_id =
        DIDURL::new(verification_method.id.as_bytes()).map_err(|_| Error::InvalidVmIdentifier)?;

    if claimed_signer != vm_id.without_fragment().0.did().as_uri() {
        return Err(Error::InvalidVmIdentifier);
    }

    Ok((verification_method.into_owned(), proof.challenge.as_deref()))
}
