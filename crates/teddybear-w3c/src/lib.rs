mod context_loader;
pub mod data;
mod did_web;
pub(crate) mod with_depth;

use itertools::Itertools;
use serde::Serialize;
use ssi_claims_core::{InvalidProof, ProofValidationError, ValidateProof, VerificationParameters};
use ssi_data_integrity::{AnyDataIntegrity, ssi_rdf};
use ssi_dids_core::{DIDURL, VerificationMethodDIDResolver};
use ssi_json_ld::{Expandable, JsonLdError, JsonLdNodeObject, Loader};
use ssi_status::{StatusPurpose, bitstring_status_list::BitstringStatusListEntry};
use ssi_vc::{
    syntax::{IdOr, IdentifiedObject, NonEmptyObject},
    v2::SpecializedJsonCredential,
};
use ssi_verification_methods::AnyMethod;

pub use ssi_status::bitstring_status_list::BitstringStatusListCredential;
use teddybear_common::HttpClient;

type W3CCredential = AnyDataIntegrity<
    SpecializedJsonCredential<
        NonEmptyObject,
        (),
        (),
        IdOr<IdentifiedObject>,
        BitstringStatusListEntry,
    >,
>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("missing proofs")]
    MissingProofs,

    #[error("verification method mismatch")]
    VerificationMethodMismatch,

    #[error("untrusted signer")]
    UntrustedSigner,

    #[error("unable to fetch the remote status list: {0}")]
    UnableToFetchRemoteStatusList(Box<dyn std::error::Error>),

    #[error("the credential is revoked")]
    RevocationCheckFailure,

    #[error("document expansion failure: {0}")]
    ExpansionFailed(#[from] JsonLdError),

    #[error("document recognition failed")]
    RecognitionFailed,

    #[error(transparent)]
    ProofValidationError(#[from] ProofValidationError),

    #[error(transparent)]
    InvalidProof(#[from] InvalidProof),
}

pub async fn verify_credential<S, R, DC>(
    credential: &W3CCredential,
    trusted_dids: &[String],
    status_list_fetcher: S,
    remote_context_fetcher: R,
    did_web_client: DC,
) -> Result<data::RecognizedW3CCredential, Error>
where
    S: HttpClient<BitstringStatusListCredential, Error: 'static>,
    R: HttpClient<serde_bytes::ByteBuf>,
    DC: HttpClient<serde_bytes::ByteBuf>,
{
    if credential.proofs.is_empty() {
        return Err(Error::MissingProofs);
    }

    let context_loader = context_loader::new(remote_context_fetcher);

    let verification_methods = verify_di(&context_loader, credential, did_web_client).await?;

    let vms_match_issuer = verification_methods
        .iter()
        .all(|didurl| didurl.did().as_uri() == credential.issuer.id());

    if !vms_match_issuer {
        return Err(Error::VerificationMethodMismatch);
    }

    let has_trusted_issuer = verification_methods.iter().any(|didurl| {
        trusted_dids
            .iter()
            .any(|trusted_did| didurl.did().as_str() == *trusted_did)
    });

    if !has_trusted_issuer {
        return Err(Error::UntrustedSigner);
    }

    let revocation_status_lists = credential
        .credential_status
        .iter()
        .filter(|status| status.status_purpose == StatusPurpose::Revocation);

    for status in revocation_status_lists {
        let remote_credential = status_list_fetcher
            .get(&status.status_list_credential)
            .await
            .map_err(|e| Error::UnableToFetchRemoteStatusList(e.into()))?;

        let status_list = remote_credential
            .decode_status_list()
            .map_err(|_| Error::RevocationCheckFailure)?;

        let flag = status_list
            .get(status.status_size, status.status_list_index)
            .ok_or(Error::RevocationCheckFailure)?;

        if flag != 0 {
            return Err(Error::RevocationCheckFailure);
        }
    }

    let expanded = credential.expand(&context_loader).await?;

    data::objects_to_fields(credential, expanded).ok_or(Error::RecognitionFailed)
}

async fn verify_di<'d, D, DC>(
    loader: &impl Loader,
    document: &'d AnyDataIntegrity<D>,
    did_web_client: DC,
) -> Result<Vec<&'d DIDURL>, Error>
where
    D: Serialize + JsonLdNodeObject + Expandable,
    D::Expanded<ssi_rdf::LexicalInterpretation, ()>: Into<ssi_json_ld::ExpandedDocument>,
    DC: HttpClient<serde_bytes::ByteBuf>,
{
    let resolver: VerificationMethodDIDResolver<_, AnyMethod> = VerificationMethodDIDResolver::new(
        (did_method_key::DIDKey, did_web::DIDWeb(did_web_client)),
    );

    let params = VerificationParameters::from_resolver(&resolver).with_json_ld_loader(loader);

    document
        .proofs
        .validate_proof(&params, &document.claims)
        .await??;

    let dids: Vec<_> = document
        .proofs
        .iter()
        .map(|proof| proof.verification_method.id())
        .map(|id| DIDURL::new(id))
        .try_collect()
        .map_err(|_| ProofValidationError::InvalidKey)?;

    // Check that all provided proofs have the same DID.
    let equal_dids = dids.iter().map(|v| v.did()).all_equal();

    if !equal_dids {
        return Err(Error::ProofValidationError(
            ProofValidationError::AmbiguousPublicKey,
        ));
    }

    Ok(dids)
}
