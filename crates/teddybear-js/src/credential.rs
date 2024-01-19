use chrono::{DateTime, FixedOffset, Utc};
use ssi_json_ld::ContextLoader;
use ssi_ldp::{LinkedDataProofOptions, ProofSuiteType};
use ssi_vc::{Credential, CredentialOrJWT, Issuer, OneOrMany, Presentation, ProofPurpose, URI};
use teddybear_crypto::{DidKey, Ed25519, Private};
use thiserror::Error;
use uuid::Uuid;

#[inline]
pub async fn issue_vc(
    key: &Ed25519<Private>,
    credential: &mut Credential,
) -> Result<(), ssi_vc::Error> {
    credential.issuer = Some(Issuer::URI(URI::String(key.document_did().to_string())));

    credential.validate_unsigned()?;

    let proof_options = LinkedDataProofOptions {
        type_: Some(ProofSuiteType::Ed25519Signature2020),
        verification_method: Some(URI::String(key.ed25519_did().to_string())),
        ..Default::default()
    };

    let mut context_loader = ContextLoader::default();

    let proof = credential
        .generate_proof(
            key.as_ed25519_private_jwk(),
            &proof_options,
            &DidKey,
            &mut context_loader,
        )
        .await?;

    credential.add_proof(proof);

    Ok(())
}

#[inline]
pub async fn issue_vp(
    key: &Ed25519<Private>,
    folio_id: &str,
    presentation: &mut Presentation,
) -> Result<(), ssi_vc::Error> {
    presentation.holder = Some(URI::String(key.document_did().to_string()));

    presentation.validate_unsigned()?;

    let proof_options = LinkedDataProofOptions {
        type_: Some(ProofSuiteType::Ed25519Signature2020),
        verification_method: Some(URI::String(key.ed25519_did().to_string())),
        proof_purpose: Some(ProofPurpose::Authentication),
        domain: Some(format!("https://vaultie.io/folio/{folio_id}")),
        challenge: Some(Uuid::new_v4().to_string()),
        ..Default::default()
    };

    let mut context_loader = ContextLoader::default();

    let proof = presentation
        .generate_proof(
            key.as_ed25519_private_jwk(),
            &proof_options,
            &DidKey,
            &mut context_loader,
        )
        .await?;

    presentation.add_proof(proof);

    Ok(())
}

#[derive(Copy, Clone, Error, Debug)]
pub enum CredentialError {
    #[error("Missing proof value.")]
    MissingProof,

    #[error("Missing credential schema.")]
    MissingCredentialSchema,

    #[error("Missing credential.")]
    MissingCredential,

    #[error("Missing presentation.")]
    MissingPresentation,

    #[error("Invalid credential issuer.")]
    InvalidIssuer,

    #[error("Invalid credential holder.")]
    InvalidHolder,

    #[error("Invalid credential subject.")]
    InvalidSubject,

    #[error("Missing credential issuance date.")]
    MissingIssuanceDate,

    #[error("Missing VerifiableCredential type.")]
    MissingVerifiableCredentialType,

    #[error("Missing VerifiablePresentation type.")]
    MissingVerifiablePresentationType,

    #[error("Failed verification.")]
    FailedVerification,

    #[error("Credential and presentation subject mismatch.")]
    SubjectMismatch,

    #[error("The credential is expired.")]
    Expired,
}

#[derive(PartialEq, Eq)]
pub enum Level {
    Warning,
    Error,
}

impl CredentialError {
    pub fn level(&self) -> Level {
        match self {
            Self::Expired => Level::Warning,
            Self::SubjectMismatch => Level::Warning,
            _ => Level::Error,
        }
    }
}

impl TryFrom<ssi_vc::Error> for CredentialError {
    type Error = ssi_vc::Error;

    #[inline]
    fn try_from(value: ssi_vc::Error) -> Result<Self, Self::Error> {
        match value {
            ssi_vc::Error::MissingProof => Ok(Self::MissingProof),
            ssi_vc::Error::MissingCredentialSchema => Ok(Self::MissingCredentialSchema),
            ssi_vc::Error::MissingCredential => Ok(Self::MissingCredential),
            ssi_vc::Error::MissingPresentation => Ok(Self::MissingPresentation),
            ssi_vc::Error::InvalidIssuer => Ok(Self::InvalidIssuer),
            ssi_vc::Error::MissingHolder => Ok(Self::InvalidHolder),
            ssi_vc::Error::InvalidSubject => Ok(Self::InvalidSubject),
            ssi_vc::Error::MissingIssuanceDate => Ok(Self::MissingIssuanceDate),
            ssi_vc::Error::MissingTypeVerifiableCredential => {
                Ok(Self::MissingVerifiableCredentialType)
            }
            ssi_vc::Error::MissingTypeVerifiablePresentation => {
                Ok(Self::MissingVerifiablePresentationType)
            }
            err => Err(err),
        }
    }
}

#[inline]
pub async fn verify_credential(
    credential: &Credential,
) -> Result<Vec<CredentialError>, ssi_vc::Error> {
    let mut error_bag = Vec::new();

    match credential.validate().map_err(CredentialError::try_from) {
        Ok(_) => {}
        Err(Ok(credential_error)) => error_bag.push(credential_error),
        Err(Err(error)) => return Err(error),
    };

    let proof_options = LinkedDataProofOptions {
        type_: Some(ProofSuiteType::Ed25519Signature2020),
        proof_purpose: Some(ProofPurpose::AssertionMethod),
        ..Default::default()
    };

    let credential_valid = credential
        .verify(Some(proof_options), &DidKey, &mut ContextLoader::default())
        .await
        .errors
        .is_empty();

    if !credential_valid {
        error_bag.push(CredentialError::FailedVerification);
    }

    let valid_expiration_date = credential
        .expiration_date
        .clone()
        .map(|date| DateTime::<FixedOffset>::from(date) < Utc::now())
        .unwrap_or(true);

    if !valid_expiration_date {
        error_bag.push(CredentialError::Expired);
    }

    Ok(error_bag)
}

#[inline]
pub async fn verify_presentation<T>(
    key: &Ed25519<T>,
    presentation: &Presentation,
) -> Result<Vec<CredentialError>, ssi_vc::Error> {
    let mut error_bag = Vec::new();

    match presentation.validate().map_err(CredentialError::try_from) {
        Ok(_) => {}
        Err(Ok(credential_error)) => error_bag.push(credential_error),
        Err(Err(error)) => return Err(error),
    };

    let proof_options = LinkedDataProofOptions {
        type_: Some(ProofSuiteType::Ed25519Signature2020),
        verification_method: Some(URI::String(key.ed25519_did().to_string())),
        proof_purpose: Some(ProofPurpose::Authentication),
        ..Default::default()
    };

    let presentation_valid = presentation
        .verify(Some(proof_options), &DidKey, &mut ContextLoader::default())
        .await
        .errors
        .is_empty();

    if !presentation_valid {
        error_bag.push(CredentialError::FailedVerification);
    }

    match &presentation.verifiable_credential {
        Some(OneOrMany::One(CredentialOrJWT::Credential(credential))) => {
            error_bag.extend(verify_credential(credential).await?);

            if let Some(subject) = credential
                .credential_subject
                .first()
                .and_then(|subject| subject.id.as_ref())
            {
                // Enforce that the credential subject's DID is the same as the presentation holder's one.
                if presentation
                    .holder
                    .as_ref()
                    .filter(|holder| *holder == subject)
                    .is_none()
                {
                    error_bag.push(CredentialError::SubjectMismatch);
                }
            } else {
                error_bag.push(CredentialError::InvalidSubject);
            };
        }
        _ => error_bag.push(CredentialError::MissingCredential),
    }

    Ok(error_bag)
}
