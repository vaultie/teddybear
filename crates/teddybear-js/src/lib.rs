extern crate alloc;

use js_sys::{Object, Uint8Array};
use serde::Serialize;
use serde_wasm_bindgen::Serializer;
use ssi_json_ld::ContextLoader;
use ssi_ldp::ProofSuiteType;
use ssi_vc::{Credential, Issuer, LinkedDataProofOptions, Presentation, ProofPurpose, URI};
use teddybear_crypto::{DidKey, Ed25519, JWK};
use teddybear_status_list::RevocationList;
use uuid::Uuid;
use wasm_bindgen::prelude::*;

const OBJECT_SERIALIZER: Serializer = Serializer::new().serialize_maps_as_objects(true);

#[wasm_bindgen]
pub fn set_panic_hook() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub struct WrappedEd25519(Ed25519);

#[wasm_bindgen]
impl WrappedEd25519 {
    pub async fn generate() -> WrappedEd25519 {
        WrappedEd25519(Ed25519::generate().await.unwrap())
    }

    #[wasm_bindgen(js_name = "fromJWK")]
    pub async fn from_jwk(jwk: WrappedJWK) -> WrappedEd25519 {
        WrappedEd25519(Ed25519::from_jwk(jwk.0).await.unwrap())
    }

    #[wasm_bindgen(js_name = "fromDID")]
    pub async fn from_did(did: &str) -> WrappedEd25519 {
        WrappedEd25519(Ed25519::from_did(did).await.unwrap())
    }

    #[wasm_bindgen(js_name = "toEd25519PublicJWK")]
    pub fn to_ed25519_public_jwk(&self) -> WrappedJWK {
        WrappedJWK(self.0.to_ed25519_public_jwk())
    }

    #[wasm_bindgen(js_name = "toEd25519PrivateJWK")]
    pub fn to_ed25519_private_jwk(&self) -> WrappedJWK {
        WrappedJWK(self.0.to_ed25519_private_jwk().clone())
    }

    #[wasm_bindgen(js_name = "toX25519PublicJWK")]
    pub fn to_x25519_public_jwk(&self) -> WrappedJWK {
        WrappedJWK(self.0.to_x25519_public_jwk())
    }

    #[wasm_bindgen(js_name = "ed25519DID")]
    pub fn ed25519_did(&self) -> String {
        self.0.ed25519_did().to_string()
    }

    #[wasm_bindgen(js_name = "x25519DID")]
    pub fn x25519_did(&self) -> String {
        self.0.x25519_did().to_string()
    }

    #[wasm_bindgen(js_name = "signJWS")]
    pub fn sign_jws(&self, payload: &str) -> String {
        self.0.sign(payload).unwrap()
    }

    #[wasm_bindgen(js_name = "issueVC")]
    pub async fn issue_vc(&self, vc: Object) -> String {
        let mut credential: Credential = serde_wasm_bindgen::from_value(vc.into()).unwrap();
        credential.issuer = Some(Issuer::URI(URI::String(
            self.0.ed25519_did().split_once('#').unwrap().0.to_string(),
        )));

        credential.validate_unsigned().unwrap();

        let proof_options = LinkedDataProofOptions {
            type_: Some(ProofSuiteType::Ed25519Signature2020),
            verification_method: Some(URI::String(self.0.ed25519_did().to_string())),
            ..Default::default()
        };

        let mut context_loader = ContextLoader::default();

        let proof = credential
            .generate_proof(
                self.0.to_ed25519_private_jwk(),
                &proof_options,
                &DidKey,
                &mut context_loader,
            )
            .await
            .unwrap();

        credential.add_proof(proof);

        serde_json::to_string(&credential).unwrap()
    }

    #[wasm_bindgen(js_name = "issueVP")]
    pub async fn issue_vp(&self, folio_id: &str, issued_vc: Object) -> String {
        let credential: Credential = serde_wasm_bindgen::from_value(issued_vc.into()).unwrap();

        credential.validate().unwrap();

        let mut presentation: Presentation = serde_json::from_value(serde_json::json!({
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": "VerifiablePresentation",
            "holder": credential.issuer,
            "verifiableCredential": credential
        }))
        .unwrap();

        let proof_options = LinkedDataProofOptions {
            type_: Some(ProofSuiteType::Ed25519Signature2020),
            verification_method: Some(URI::String(self.0.ed25519_did().to_string())),
            proof_purpose: Some(ProofPurpose::Authentication),
            domain: Some(format!("https://vaultie.io/folio/{folio_id}")),
            challenge: Some(Uuid::new_v4().to_string()),
            ..Default::default()
        };

        let mut context_loader = ContextLoader::default();

        let proof = presentation
            .generate_proof(
                self.0.to_ed25519_private_jwk(),
                &proof_options,
                &DidKey,
                &mut context_loader,
            )
            .await
            .unwrap();

        presentation.add_proof(proof);

        serde_json::to_string(&presentation).unwrap()
    }
}

#[wasm_bindgen]
pub struct WrappedJWK(JWK);

#[wasm_bindgen]
impl WrappedJWK {
    #[wasm_bindgen(js_name = "fromObject")]
    pub fn from_object(object: &Object) -> Self {
        Self(serde_wasm_bindgen::from_value(object.into()).unwrap())
    }

    #[wasm_bindgen(js_name = "asObject")]
    pub fn as_object(&self) -> Object {
        self.0.serialize(&OBJECT_SERIALIZER).unwrap().into()
    }
}

#[wasm_bindgen]
pub struct WrappedRevocationList(RevocationList);

#[wasm_bindgen]
impl WrappedRevocationList {
    #[wasm_bindgen(constructor)]
    pub fn new() -> WrappedRevocationList {
        WrappedRevocationList(RevocationList::default())
    }

    #[wasm_bindgen(js_name = "isRevoked")]
    pub fn is_revoked(&self, idx: usize) -> bool {
        self.0.is_revoked(idx)
    }

    pub fn issue(&mut self) -> usize {
        self.0.issue()
    }

    pub fn revoke(&mut self, idx: usize) -> bool {
        self.0.revoke(idx)
    }
}

#[wasm_bindgen]
pub fn encrypt(payload: Uint8Array, recipients: Vec<WrappedJWK>) -> Object {
    let jwe = teddybear_jwe::encrypt(
        &mut payload.to_vec(),
        &recipients.iter().map(|val| &val.0).collect::<Vec<_>>(),
    );

    jwe.serialize(&OBJECT_SERIALIZER).unwrap().into()
}