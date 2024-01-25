use chrono::{DateTime, FixedOffset, Utc};
use ssi_json_ld::ContextLoader;
use ssi_ldp::{LinkedDataProofOptions, ProofSuiteType};
use ssi_vc::{Credential, CredentialOrJWT, Issuer, OneOrMany, Presentation, ProofPurpose, URI};
use teddybear_crypto::{DidKey, Ed25519, Private};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed credential verification.")]
    VerificationFailed,

    #[error("Credential expired.")]
    CredentialExpired,

    #[error(transparent)]
    Lib(#[from] ssi_vc::Error)
}

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
    challenge: Option<String>,
    presentation: &mut Presentation,
) -> Result<(), ssi_vc::Error> {
    presentation.holder = Some(URI::String(key.document_did().to_string()));

    presentation.validate_unsigned()?;

    let proof_options = LinkedDataProofOptions {
        type_: Some(ProofSuiteType::Ed25519Signature2020),
        verification_method: Some(URI::String(key.ed25519_did().to_string())),
        proof_purpose: Some(ProofPurpose::Authentication),
        domain: Some(format!("https://vaultie.io/folio/{folio_id}")),
        challenge,
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

#[inline]
pub async fn verify_credential(
    credential: &Credential,
) -> Result<(), Error> {
    credential.validate()?;

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
        return Err(Error::VerificationFailed);
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
pub async fn verify_presentation<'a, T>(
    key: &Ed25519<T>,
    presentation: &'a Presentation,
) -> Result<Option<&'a str>, Error> {
    presentation.validate()?;

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
        return Err(Error::VerificationFailed);
    }

    match &presentation.verifiable_credential {
        Some(OneOrMany::One(CredentialOrJWT::Credential(credential))) => {
            verify_credential(credential).await?;

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

    let challenge = presentation.proof
        .as_ref()
        .ok_or(Error::VerificationFailed)?
        .to_single()
        .ok_or(Error::VerificationFailed)?
        .challenge
        .as_deref();

    Ok(challenge)
}
