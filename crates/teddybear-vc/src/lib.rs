mod credential_ref;
pub mod status_list;

use std::collections::HashMap;

use itertools::Itertools;
use serde::{Deserialize, Serialize};
use ssi_claims::{
    Invalid, InvalidClaims, ProofValidationError, SignatureEnvironment, SignatureError,
    ValidateClaims, ValidateProof, VerifiableClaims, VerificationParameters,
    data_integrity::{
        AnySuite, CryptographicSuite, DataIntegrity, ProofOptions, StandardCryptographicSuite,
        suite::CryptographicSuiteSigning,
    },
};
use ssi_crypto::algorithm::SignatureAlgorithmType;
use ssi_data_integrity_core::suite::ConfigurationAlgorithm;
use ssi_json_ld::{ContextLoader, Expandable, IriBuf, JsonLdNodeObject};
use ssi_vc::{
    Identified,
    v2::{
        Credential, Presentation,
        syntax::{JsonPresentation, SpecializedJsonCredential},
    },
};
use ssi_verification_methods::{
    AnyMethod, ProofPurpose, ReferenceOrOwned, SigningMethod, SingleSecretSigner,
    VerificationMethod, VerificationMethodResolutionError, VerificationMethodResolver,
};
use teddybear_crypto::{
    CachedDIDResolver, CustomVerificationMethodDIDResolver, DIDBuf, DIDURL, Document, Uri,
    default_did_method,
};

use crate::credential_ref::CredentialRef;

pub use ssi_claims;
pub use ssi_crypto;
pub use ssi_json_ld;
pub use ssi_vc;
pub use ssi_verification_methods;

pub type DI<V, M> = DataIntegrity<V, M>;
pub type DIAny<V> = DataIntegrity<V, AnySuite>;

pub type CustomVerificationParameters<'a, 'b, K> =
    VerificationParameters<&'a CustomVerificationMethodDIDResolver<K>, &'b mut ContextLoader>;

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

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
pub struct IssueOptions {
    /// Cached DID documents.
    #[serde(rename = "cachedDocuments")]
    pub cached_documents: HashMap<DIDBuf, Document>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
pub struct PresentOptions {
    /// Cached DID documents.
    #[serde(rename = "cachedDocuments")]
    pub cached_documents: HashMap<DIDBuf, Document>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
pub struct VerifyOptions {
    /// Cached DID documents.
    #[serde(rename = "cachedDocuments")]
    pub cached_documents: HashMap<DIDBuf, Document>,
}

pub type SignedCredential<'a, C, M> = DI<CredentialRef<'a, C>, M>;

pub async fn issue_vc<'a, 'c, A, M, K, C>(
    key: K,
    verification_method: IriBuf,
    credential: &'a C,
    context_loader: &'c mut ContextLoader,
    cached_documents: HashMap<DIDBuf, Document>,
) -> Result<SignedCredential<'a, C, M>, Error>
where
    M: StandardCryptographicSuite
        + CryptographicSuiteSigning<
            CredentialRef<'a, C>,
            SignatureEnvironment<&'c mut ContextLoader>,
            CustomVerificationMethodDIDResolver<
                <M as StandardCryptographicSuite>::VerificationMethod,
            >,
            SingleSecretSigner<K>,
        > + Default,
    <M as StandardCryptographicSuite>::VerificationMethod: SigningMethod<K, A>,
    <M as CryptographicSuite>::Configuration:
        ConfigurationAlgorithm<M, InputSignatureOptions = (), InputSuiteOptions: Default>,
    A: SignatureAlgorithmType,
    C: Credential + JsonLdNodeObject + Expandable,
    K: 'c,
{
    let resolver = CustomVerificationMethodDIDResolver::new(CachedDIDResolver::new(
        default_did_method(),
        cached_documents,
    ));

    let params =
        VerificationParameters::from_resolver(&resolver).with_json_ld_loader(&context_loader);

    credential.validate_credential(&params)?;

    Ok(M::default()
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

pub type SignedPresentation<'a, C, M> = DI<CredentialRef<'a, JsonPresentation<C>>, M>;

pub async fn present_vp<'a, 'c, A, M, K, C>(
    key: K,
    verification_method: IriBuf,
    presentation: &'a JsonPresentation<C>,
    domain: Option<String>,
    challenge: Option<String>,
    context_loader: &'c mut ContextLoader,
    cached_documents: HashMap<DIDBuf, Document>,
) -> Result<SignedPresentation<'a, C, M>, Error>
where
    C: Credential + JsonLdNodeObject + Expandable + Serialize,
    M: StandardCryptographicSuite
        + CryptographicSuiteSigning<
            CredentialRef<'a, JsonPresentation<C>>,
            SignatureEnvironment<&'c mut ContextLoader>,
            CustomVerificationMethodDIDResolver<
                <M as StandardCryptographicSuite>::VerificationMethod,
            >,
            SingleSecretSigner<K>,
        > + Default,
    <M as StandardCryptographicSuite>::VerificationMethod: SigningMethod<K, A>,
    <M as CryptographicSuite>::Configuration:
        ConfigurationAlgorithm<M, InputSignatureOptions = (), InputSuiteOptions: Default>,
    A: SignatureAlgorithmType,
    C: Credential + JsonLdNodeObject + Expandable,
    K: 'c,
{
    let resolver = CustomVerificationMethodDIDResolver::new(CachedDIDResolver::new(
        default_did_method(),
        cached_documents,
    ));

    let params =
        VerificationParameters::from_resolver(&resolver).with_json_ld_loader(&context_loader);

    for vc in presentation.verifiable_credentials() {
        vc.validate_credential(&params)?;
    }

    Ok(M::default()
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

impl<C> HasClaimedSigner for JsonPresentation<C> {
    fn claimed_signer(&self) -> Option<&Uri> {
        // For now expect only a single credential holder.
        Some(self.holders.iter().exactly_one().ok()?.id())
    }
}

impl<T, S> HasClaimedSigner for DataIntegrity<T, S>
where
    T: HasClaimedSigner,
    S: StandardCryptographicSuite,
{
    fn claimed_signer(&self) -> Option<&Uri> {
        self.claims.claimed_signer()
    }
}

pub async fn verify<'a, 'b, V>(
    value: &'a DIAny<V>,
    context_loader: &'b mut ContextLoader,
    cached_documents: HashMap<DIDBuf, Document>,
) -> Result<Option<&'a str>, Error>
where
    V: HasClaimedSigner,
    for<'r> <DIAny<V> as VerifiableClaims>::Claims: ValidateClaims<
            CustomVerificationParameters<'r, 'b, AnyMethod>,
            <DIAny<V> as VerifiableClaims>::Proof,
        >,
    for<'r> <DIAny<V> as VerifiableClaims>::Proof: ValidateProof<
            CustomVerificationParameters<'r, 'b, AnyMethod>,
            <DIAny<V> as VerifiableClaims>::Claims,
        >,
{
    let claimed_signer = value.claimed_signer().ok_or(Error::MissingClaimedSigner)?;

    let resolver = CustomVerificationMethodDIDResolver::<AnyMethod>::new(CachedDIDResolver::new(
        default_did_method(),
        cached_documents,
    ));

    let params =
        VerificationParameters::from_resolver(&resolver).with_json_ld_loader(context_loader);

    value.verify(params).await??;

    let proof = value
        .proof()
        .iter()
        .exactly_one()
        .map_err(|_| Error::SingleProofOnly)?;

    let verification_method = resolver
        .resolve_verification_method(
            None,
            Some(
                proof
                    .verification_method
                    .clone()
                    .try_cast::<AnyMethod>()
                    .unwrap()
                    .borrowed(),
            ),
        )
        .await?;

    let vm_id =
        DIDURL::new(verification_method.id().as_bytes()).map_err(|_| Error::InvalidVmIdentifier)?;

    if claimed_signer != vm_id.without_fragment().0.did().as_uri() {
        return Err(Error::InvalidVmIdentifier);
    }

    Ok(proof.challenge.as_deref())
}
