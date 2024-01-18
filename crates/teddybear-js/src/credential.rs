use ssi_json_ld::ContextLoader;
use ssi_ldp::{LinkedDataProofOptions, ProofSuiteType};
use ssi_vc::{Credential, CredentialOrJWT, Issuer, OneOrMany, Presentation, ProofPurpose, URI};
use teddybear_crypto::{DidKey, Ed25519, Private};
use uuid::Uuid;

#[inline]
pub async fn issue_vc(key: &Ed25519<Private>, credential: &mut Credential) {
    credential.issuer = Some(Issuer::URI(URI::String(key.document_did().to_string())));

    credential.validate_unsigned().unwrap();

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
        .await
        .unwrap();

    credential.add_proof(proof);
}

#[inline]
pub async fn issue_vp(key: &Ed25519<Private>, folio_id: &str, presentation: &mut Presentation) {
    presentation.validate_unsigned().unwrap();

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
        .await
        .unwrap();

    presentation.add_proof(proof);
}

#[inline]
pub async fn verify_credential(credential: &Credential) -> bool {
    if credential.validate().is_err() {
        return false;
    }

    let proof_options = LinkedDataProofOptions {
        type_: Some(ProofSuiteType::Ed25519Signature2020),
        proof_purpose: Some(ProofPurpose::AssertionMethod),
        ..Default::default()
    };

    credential
        .verify(Some(proof_options), &DidKey, &mut ContextLoader::default())
        .await
        .errors
        .is_empty()
}

#[inline]
pub async fn verify_presentation<T>(key: &Ed25519<T>, presentation: &Presentation) -> bool {
    if presentation.validate().is_err() {
        return false;
    }

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
        return false;
    }

    match &presentation.verifiable_credential {
        Some(OneOrMany::One(CredentialOrJWT::Credential(credential))) => {
            if !verify_credential(credential).await {
                return false;
            }

            let Some(subject) = credential
                .credential_subject
                .first()
                .and_then(|subject| subject.id.as_ref())
            else {
                return false;
            };

            // Enforce that the credential subject's DID is the same as the presentation holder's one.
            if presentation
                .holder
                .as_ref()
                .filter(|holder| *holder == subject)
                .is_none()
            {
                return false;
            }

            true
        }
        _ => false,
    }
}
