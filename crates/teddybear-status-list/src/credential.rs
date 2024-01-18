use iref::Iri;
use serde::{Deserialize, Serialize};
use serde_aux::field_attributes::deserialize_number_from_string;
use ssi_json_ld::CREDENTIALS_V2_CONTEXT;
use ssi_vc::{Credential, URI};
use thiserror::Error;

use crate::StatusList;

const STATUS_LIST_CONTEXT: Iri<'_> = CREDENTIALS_V2_CONTEXT;
const STATUS_LIST_CREDENTIAL_TYPE: &str = "BitstringStatusListCredential";
const STATUS_LIST_CREDENTIAL_SUBJECT_TYPE: &str = "BitstringStatusList";

/// Purpose of the status entry.
///
/// See more info at <https://www.w3.org/TR/vc-bitstring-status-list/#bitstringstatuslistentry>.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StatusPurpose {
    /// Used to cancel the validity of a verifiable credential.
    /// This status is not reversible.
    Revocation,

    /// Used to temporarily prevent the acceptance of a verifiable credential.
    /// This status is reversible.
    Suspension,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BitstringStatusListEntry {
    pub status_purpose: StatusPurpose,

    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub status_list_index: usize,

    pub status_list_credential: URI,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BitstringStatusListCredentialSubject {
    pub status_purpose: StatusPurpose,
    pub encoded_list: StatusList,
}

#[derive(Error, Debug)]
pub enum BitstringError {
    #[error("missing context: {}", STATUS_LIST_CONTEXT.as_str())]
    MissingContext,

    #[error("missing {} credential type", STATUS_LIST_CREDENTIAL_TYPE)]
    MissingCredentialType,

    #[error(
        "missing {} credential subject type",
        STATUS_LIST_CREDENTIAL_SUBJECT_TYPE
    )]
    MissingCredentialSubjectType,

    #[error("found multiple credential subjects while expecting one")]
    MultipleCredentialSubjects,

    #[error("serde_json error: {0}")]
    Serde(#[from] serde_json::Error),
}

impl<'a> TryFrom<&'a Credential> for BitstringStatusListCredentialSubject {
    type Error = BitstringError;

    fn try_from(credential: &'a Credential) -> Result<Self, Self::Error> {
        if !credential
            .context
            .contains_uri(STATUS_LIST_CONTEXT.as_str())
        {
            return Err(BitstringError::MissingContext);
        }

        // FIXME: API improvements can be upstreamed
        if !credential
            .type_
            .contains(&STATUS_LIST_CREDENTIAL_TYPE.to_string())
        {
            return Err(BitstringError::MissingCredentialType);
        }

        let subject = credential
            .credential_subject
            .to_single()
            .ok_or(BitstringError::MultipleCredentialSubjects)?;

        if subject
            .property_set
            .as_ref()
            .and_then(|set| set.get("type"))
            .and_then(|val| val.as_str())
            .filter(|val| *val == STATUS_LIST_CREDENTIAL_SUBJECT_TYPE)
            .is_none()
        {
            return Err(BitstringError::MissingCredentialSubjectType);
        }

        let bitstring_subject: BitstringStatusListCredentialSubject =
            serde_json::from_value(serde_json::to_value(subject)?)?;

        Ok(bitstring_subject)
    }
}
