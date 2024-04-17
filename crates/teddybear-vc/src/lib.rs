#[cfg(feature = "query")]
pub mod query;

use chrono::{DateTime, FixedOffset, Utc};
use ssi_ldp::{LinkedDataProofOptions, ProofSuiteType};
use ssi_vc::{Credential, CredentialOrJWT, Issuer, OneOrMany, Presentation, ProofPurpose, URI};
use teddybear_crypto::{DidKey, Ed25519, Private, Public};
use thiserror::Error;

pub use ssi_json_ld::ContextLoader;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed credential verification.")]
    VerificationFailed(Vec<String>),

    #[error("Credential expired.")]
    CredentialExpired,

    #[error(transparent)]
    Crypto(#[from] teddybear_crypto::Error),

    #[error(transparent)]
    Lib(#[from] ssi_vc::Error),
}

#[inline]
pub async fn issue_vc(
    key: &Ed25519<Private>,
    credential: &mut Credential,
    context_loader: &mut ContextLoader,
) -> Result<(), ssi_vc::Error> {
    credential.issuer = Some(Issuer::URI(URI::String(key.document_did().to_string())));

    credential.validate_unsigned()?;

    let proof_options = LinkedDataProofOptions {
        type_: Some(ProofSuiteType::Ed25519Signature2020),
        verification_method: Some(URI::String(key.ed25519_did().to_string())),
        ..Default::default()
    };

    let proof = credential
        .generate_proof(
            key.as_ed25519_private_jwk(),
            &proof_options,
            &DidKey,
            context_loader,
        )
        .await?;

    credential.add_proof(proof);

    Ok(())
}

#[inline]
pub async fn issue_vp(
    key: &Ed25519<Private>,
    presentation: &mut Presentation,
    domain: Option<String>,
    challenge: Option<String>,
    context_loader: &mut ContextLoader,
) -> Result<(), ssi_vc::Error> {
    presentation.holder = Some(URI::String(key.document_did().to_string()));

    presentation.validate_unsigned()?;

    let proof_options = LinkedDataProofOptions {
        type_: Some(ProofSuiteType::Ed25519Signature2020),
        verification_method: Some(URI::String(key.ed25519_did().to_string())),
        proof_purpose: Some(ProofPurpose::Authentication),
        domain,
        challenge,
        ..Default::default()
    };

    let proof = presentation
        .generate_proof(
            key.as_ed25519_private_jwk(),
            &proof_options,
            &DidKey,
            context_loader,
        )
        .await?;

    presentation.add_proof(proof);

    Ok(())
}

#[inline]
pub async fn verify_credential(
    credential: &Credential,
    context_loader: &mut ContextLoader,
) -> Result<(), Error> {
    credential.validate()?;

    let proof_options = LinkedDataProofOptions {
        type_: Some(ProofSuiteType::Ed25519Signature2020),
        proof_purpose: Some(ProofPurpose::AssertionMethod),
        ..Default::default()
    };

    let credential_errors = credential
        .verify(Some(proof_options), &DidKey, context_loader)
        .await
        .errors;

    if !credential_errors.is_empty() {
        return Err(Error::VerificationFailed(credential_errors));
    }

    let valid_expiration_date = credential
        .expiration_date
        .clone()
        .map(|date| DateTime::<FixedOffset>::from(date) < Utc::now())
        .unwrap_or(true);

    if !valid_expiration_date {
        return Err(Error::CredentialExpired);
    }

    Ok(())
}

#[inline]
pub async fn verify_presentation<'a>(
    presentation: &'a Presentation,
    context_loader: &mut ContextLoader,
) -> Result<(Ed25519<Public>, Option<&'a str>), Error> {
    presentation.validate()?;

    let holder = Ed25519::from_did(
        presentation
            .holder
            .as_ref()
            .ok_or(ssi_vc::Error::MissingHolder)?
            .as_str(),
    )
    .await?;

    let proof_options = LinkedDataProofOptions {
        type_: Some(ProofSuiteType::Ed25519Signature2020),
        verification_method: Some(URI::String(holder.ed25519_did().to_string())),
        proof_purpose: Some(ProofPurpose::Authentication),
        ..Default::default()
    };

    let presentation_errors = presentation
        .verify(Some(proof_options), &DidKey, context_loader)
        .await
        .errors;

    if !presentation_errors.is_empty() {
        return Err(Error::VerificationFailed(presentation_errors));
    }

    match &presentation.verifiable_credential {
        Some(OneOrMany::One(CredentialOrJWT::Credential(credential))) => {
            verify_credential(credential, context_loader).await?;

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
                    return Err(ssi_vc::Error::InvalidSubject.into());
                }
            } else {
                return Err(ssi_vc::Error::InvalidSubject.into());
            };
        }
        _ => return Err(ssi_vc::Error::MissingCredential.into()),
    }

    let challenge = presentation
        .proof
        .as_ref()
        .ok_or(ssi_vc::Error::MissingProof)?
        .to_single()
        .ok_or(ssi_vc::Error::MissingProof)?
        .challenge
        .as_deref();

    Ok((holder, challenge))
}
