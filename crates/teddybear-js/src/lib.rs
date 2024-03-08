//! # Teddybear JS/WASM wrapper.
//!
//! `teddybear-js` is a JavaScript/TypeScript library designed to make working with W3C verifiable credentials easier and more accessible.
//! It provides a collection of tools and utilities to issue, validate and query verifiable credentials, and to execute common cryptographic operations.
//!
//! ## Key management
//!
//! Teddybear's [`PrivateEd25519`] structure provides a central access point for Ed25519 key management and cryptographic operations.
//!
//! It allows you to:
//! * Generate new key pairs
//! * Import existing keys from JSON Web Key (JWK) or Decentralized Identifier (DID) formats
//! * Extract DID values for both Ed25519 and X25519 public keys
//! * Generate JWKs for Ed25519 and X25519 public and private keys
//! * Sign JSON Web Signatures (JWS)
//! * Encrypt and decrypt JSON Web Encryption (JWE) values
//!
//! ```ignore
//! import { PrivateEd25519 } from "@vaultie/teddybear";
//!
//! const key = await PrivateEd25519.generate();
//!
//! // Extract document DID value
//! console.log(key.documentDID());
//!
//! // Extract public key JWK value
//! console.log(JSON.stringify(key.toEd25519PublicJWK()));
//! //          ^^^^^^^^^^^^^^ Important for correct serialization
//!
//! // Produce a JWS value
//! console.log(key.signJWS("Value to sign"));
//!
//! // Issue a verifiable credential
//! // https://www.w3.org/TR/vc-data-model-2.0/#example-usage-of-the-context-property
//! const credential = {
//!     "@context": [
//!         "https://www.w3.org/ns/credentials/v2",
//!         "https://www.w3.org/ns/credentials/examples/v2"
//!     ],
//!     "id": "http://university.example/credentials/58473",
//!     "type": ["VerifiableCredential", "ExampleAlumniCredential"],
//!     "issuer": "https://university.example/issuers/565049",
//!     "issuanceDate": "2024-01-01T00:00:00Z",
//!     "validFrom": "2024-01-01T00:00:00Z",
//!     "credentialSubject": {
//!         "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
//!         "alumniOf": {
//!             "id": "did:example:c276e12ec21ebfeb1f712ebc6f1",
//!             "name": "Example University"
//!         }
//!     }
//! };
//!
//! console.log(await key.issueVC(credential))
//! ```
//!
//! ## JWE encryption and decryption
//!
//! Teddybear supports JWE encryption and decryption using X25519 keys.
//!
//! Additionally, you can convert Ed25519 keys to X25519 keys, allowing you to publish just a single DID value for both signing and encryption purposes.
//!
//! ```ignore
//! import { PrivateEd25519, PublicEd25519, encryptAES } from "@vaultie/teddybear";
//!
//! const firstKey = await PrivateEd25519.generate();
//! const secondKey = await PublicEd25519.fromDID(
//!     "did:key:z6MkmpNwNTy4ATx87tZWHqSwNf1ZdeQrBHFWyhtvUwqrt32R"
//! );
//!
//! // Encrypt using recipient public keys.
//! const jwe = encryptAES(new Uint8Array([0, 1, 2, 3], [
//!     firstKey.toX25519PublicJWK(),
//!     secondKey.toX25519PublicJWK(),
//! ]));
//!
//! console.log(jwe);
//!
//! // Decrypt using any suitable recipient private key.
//! console.log(firstKey.decryptAES(jwe));
//! ```
//!
//! ## Revocation/status list
//!
//! Teddybear also implements bitstring-encoded [W3C status lists](https://www.w3.org/TR/vc-bitstring-status-list/).
//!
//! Status lists can be used to track revoked credentials in a privacy-preserving manner, without disclosing any
//! details about the credential itself.
//!
//! To start, create a new status list (all bits set to 0) and [publish it as a verifiable credential](https://www.w3.org/TR/vc-bitstring-status-list/#example-example-bitstringstatuslistcredential):
//!
//! ```ignore
//! import { StatusListCredential } from "@vaultie/teddybear";
//!
//! const statusList = new StatusListCredential();
//! const partialCredentialSubject = statusList.toJSON();
//!
//! // ...
//! ```
//!
//! During credential issuance generate a random index number between 0 and 131072, unique to this new credential:
//!
//! ```ignore
//! const idx = /* credential index */;
//! ```
//!
//! Set this index as a [statusListIndex value](https://www.w3.org/TR/vc-bitstring-status-list/#example-example-statuslistcredential).
//!
//! If a situation occurs where you have to revoke a previously issued verifiable credential, set the bit corresponding
//! to the credential index to 1 (thus revoking the corresponding verifiable credential) and re-publish the updated status list verifiable credential:
//!
//! ```ignore
//! statusList.revoke(idx);
//! const updatedPartialCredentialSubject = statusList.toJSON();
//! ```
//!
//! Status lists can be queried for the index revocation status:
//!
//! ```ignore
//! console.log(statusList.isRevoked(idx)); // true
//! ```

extern crate alloc;

use std::collections::HashMap;

use js_sys::{Object, Uint8Array};
use serde::Serialize;
use serde_json::json;
use serde_wasm_bindgen::Serializer;
use teddybear_crypto::{Ed25519, Private, Public, JWK as InnerJWK};
use teddybear_jwe::{add_recipient, decrypt, A256Gcm, XC20P};
use teddybear_status_list::{
    credential::{BitstringStatusListCredentialSubject, StatusPurpose},
    StatusList,
};
use wasm_bindgen::prelude::*;

use teddybear_vc::{
    issue_vc, issue_vp, verify_credential, verify_presentation, ContextLoader as InnerContextLoader,
};

const OBJECT_SERIALIZER: Serializer = Serializer::new().serialize_maps_as_objects(true);

/// A public/private Ed25519/X25519 keypair.
#[wasm_bindgen]
pub struct PrivateEd25519(Ed25519<Private>);

#[wasm_bindgen]
impl PrivateEd25519 {
    /// Create a new random keypair.
    pub async fn generate() -> Result<PrivateEd25519, JsError> {
        Ok(PrivateEd25519(Ed25519::generate().await?))
    }

    /// Convert an Ed25519 JWK value to a public/private keypair.
    #[wasm_bindgen(js_name = "fromJWK")]
    pub async fn from_jwk(jwk: JWK) -> Result<PrivateEd25519, JsError> {
        Ok(PrivateEd25519(Ed25519::from_private_jwk(jwk.0).await?))
    }

    /// Get the JWK value (with the private key) of the Ed25519 key within the current keypair.
    #[wasm_bindgen(js_name = "toEd25519PrivateJWK")]
    pub fn to_ed25519_private_jwk(&self) -> JWK {
        JWK(self.0.as_ed25519_private_jwk().clone())
    }

    /// Get the JWK value (without the private key) of the Ed25519 key within the current keypair.
    #[wasm_bindgen(js_name = "toEd25519PublicJWK")]
    pub fn to_ed25519_public_jwk(&self) -> JWK {
        JWK(self.0.to_ed25519_public_jwk())
    }

    /// Get the JWK value (with the private key) of the X25519 key within the current keypair.
    #[wasm_bindgen(js_name = "toX25519PrivateJWK")]
    pub fn to_x25519_private_jwk(&self) -> JWK {
        JWK(self.0.as_x25519_private_jwk().clone())
    }

    /// Get the JWK value (without the private key) of the X25519 key within the current keypair.
    #[wasm_bindgen(js_name = "toX25519PublicJWK")]
    pub fn to_x25519_public_jwk(&self) -> JWK {
        JWK(self.0.to_x25519_public_jwk())
    }

    /// Get the key document value.
    pub fn document(&self) -> Result<Object, JsError> {
        Ok(self.0.document().serialize(&OBJECT_SERIALIZER)?.into())
    }

    /// Get the document DID value.
    ///
    /// This value is usually used to idenfity an entity as a whole.
    ///
    /// If you want to refer to a specific key see `ed25519DID` and `x25519DID`
    /// methods instead.
    #[wasm_bindgen(js_name = "documentDID")]
    pub fn document_did(&self) -> String {
        self.0.document_did().to_string()
    }

    /// Get the DID value of the Ed25519 key.
    #[wasm_bindgen(js_name = "ed25519DID")]
    pub fn ed25519_did(&self) -> String {
        self.0.ed25519_did().to_string()
    }

    /// Get the DID value of the X25519 key.
    #[wasm_bindgen(js_name = "x25519DID")]
    pub fn x25519_did(&self) -> String {
        self.0.x25519_did().to_string()
    }

    /// Decrypt the provided JWE object using the X25519 key and the A256GCM algorithm.
    #[wasm_bindgen(js_name = "decryptAES")]
    pub fn decrypt_aes(&self, jwe: Object) -> Result<Uint8Array, JsError> {
        let jwe = serde_wasm_bindgen::from_value(jwe.into())?;
        let payload = &*decrypt::<A256Gcm>(&jwe, self.0.as_x25519_private_jwk())?;
        Ok(payload.into())
    }

    /// Decrypt the provided JWE object using the X25519 key and the XC20P algorithm.
    #[wasm_bindgen(js_name = "decryptChaCha20")]
    pub fn decrypt_chacha20(&self, jwe: Object) -> Result<Uint8Array, JsError> {
        let jwe = serde_wasm_bindgen::from_value(jwe.into())?;
        let payload = &*decrypt::<XC20P>(&jwe, self.0.as_x25519_private_jwk())?;
        Ok(payload.into())
    }

    #[wasm_bindgen(js_name = "addAESRecipient")]
    pub fn add_aes_recipient(&self, jwe: Object, recipient: JWK) -> Result<Object, JsError> {
        let jwe = serde_wasm_bindgen::from_value(jwe.into())?;
        let recipient =
            add_recipient::<A256Gcm>(&jwe, self.0.as_x25519_private_jwk(), &recipient.0)?;
        Ok(recipient.serialize(&OBJECT_SERIALIZER)?.into())
    }

    #[wasm_bindgen(js_name = "addChaCha20Recipient")]
    pub fn add_chacha20_recipient(&self, jwe: Object, recipient: JWK) -> Result<Object, JsError> {
        let jwe = serde_wasm_bindgen::from_value(jwe.into())?;
        let recipient = add_recipient::<XC20P>(&jwe, self.0.as_x25519_private_jwk(), &recipient.0)?;
        Ok(recipient.serialize(&OBJECT_SERIALIZER)?.into())
    }

    /// Sign the provided payload using the Ed25519 key.
    #[wasm_bindgen(js_name = "signJWS")]
    pub fn sign_jws(&self, payload: &str) -> Result<String, JsError> {
        Ok(self.0.sign(payload)?)
    }

    /// Create a new verifiable credential.
    ///
    /// The `vc` object should contain all the necessary information except
    /// for the issuer and proof values, which will be filled automatically.
    #[wasm_bindgen(js_name = "issueVC")]
    pub async fn issue_vc(
        &self,
        vc: Object,
        context_loader: &mut ContextLoader,
    ) -> Result<Object, JsError> {
        let mut credential = serde_wasm_bindgen::from_value(vc.into())?;
        issue_vc(&self.0, &mut credential, &mut context_loader.0).await?;
        Ok(credential.serialize(&OBJECT_SERIALIZER)?.into())
    }

    /// Create a new verifiable presentation.
    ///
    /// The `vp` object should contain all the necessary information except
    /// for the holder and proof values, which will be filled automatically.
    #[wasm_bindgen(js_name = "issueVP")]
    pub async fn issue_vp(
        &self,
        vp: Object,
        context_loader: &mut ContextLoader,
        domain: Option<String>,
        challenge: Option<String>,
    ) -> Result<Object, JsError> {
        let mut presentation = serde_wasm_bindgen::from_value(vp.into())?;
        issue_vp(
            &self.0,
            &mut presentation,
            domain,
            challenge,
            &mut context_loader.0,
        )
        .await?;
        Ok(presentation.serialize(&OBJECT_SERIALIZER)?.into())
    }
}

/// A public Ed25519/X25519 keypair.
#[wasm_bindgen]
#[derive(Clone)]
pub struct PublicEd25519(Ed25519<Public>);

#[wasm_bindgen]
impl PublicEd25519 {
    /// Convert an Ed25519 JWK value to a public keypair.
    #[wasm_bindgen(js_name = "fromJWK")]
    pub async fn from_jwk(jwk: JWK) -> Result<PublicEd25519, JsError> {
        Ok(PublicEd25519(Ed25519::from_jwk(jwk.0).await?))
    }

    /// Convert a `did:key` document value to a public keypair.
    #[wasm_bindgen(js_name = "fromDID")]
    pub async fn from_did(did: &str) -> Result<PublicEd25519, JsError> {
        Ok(PublicEd25519(Ed25519::from_did(did).await?))
    }

    /// Get the JWK value (without the private key) of the Ed25519 key within the current keypair.
    #[wasm_bindgen(js_name = "toEd25519PublicJWK")]
    pub fn to_ed25519_public_jwk(&self) -> JWK {
        JWK(self.0.to_ed25519_public_jwk())
    }

    /// Get the JWK value (without the private key) of the X25519 key within the current keypair.
    #[wasm_bindgen(js_name = "toX25519PublicJWK")]
    pub fn to_x25519_public_jwk(&self) -> JWK {
        JWK(self.0.to_x25519_public_jwk())
    }

    /// Get the key document value.
    pub fn document(&self) -> Result<Object, JsError> {
        Ok(self.0.document().serialize(&OBJECT_SERIALIZER)?.into())
    }

    /// Get the document DID value.
    ///
    /// This value is usually used to idenfity an entity as a whole.
    ///
    /// If you want to refer to a specific key see `ed25519DID` and `x25519DID`
    /// methods instead.
    #[wasm_bindgen(js_name = "documentDID")]
    pub fn document_did(&self) -> String {
        self.0.document_did().to_string()
    }

    /// Get the DID value of the Ed25519 key.
    #[wasm_bindgen(js_name = "ed25519DID")]
    pub fn ed25519_did(&self) -> String {
        self.0.ed25519_did().to_string()
    }

    /// Get the DID value of the X25519 key.
    #[wasm_bindgen(js_name = "x25519DID")]
    pub fn x25519_did(&self) -> String {
        self.0.x25519_did().to_string()
    }
}

/// Verify the provided verifiable credential.
///
/// See the `ErrorBag` documentation for more details on how to handle errors
/// that may occur during the validation process.
#[wasm_bindgen(js_name = "verifyCredential")]
pub async fn js_verify_credential(
    document: Object,
    context_loader: &mut ContextLoader,
) -> Result<(), JsError> {
    let credential = serde_wasm_bindgen::from_value(document.into())?;
    Ok(verify_credential(&credential, &mut context_loader.0).await?)
}

#[wasm_bindgen]
pub struct ContextLoader(InnerContextLoader);

#[wasm_bindgen]
impl ContextLoader {
    #[wasm_bindgen(constructor)]
    pub fn new(contexts: Option<Object>) -> Result<ContextLoader, JsError> {
        let context_loader = InnerContextLoader::default();

        let contexts: Option<HashMap<String, String>> = contexts
            .map(|obj| serde_wasm_bindgen::from_value(obj.into()))
            .transpose()?;

        Ok(ContextLoader(if let Some(contexts) = contexts {
            context_loader.with_context_map_from(contexts)?
        } else {
            context_loader
        }))
    }
}

#[wasm_bindgen]
pub struct PresentationVerificationResult {
    key: PublicEd25519,
    challenge: Option<String>,
}

#[wasm_bindgen]
impl PresentationVerificationResult {
    pub fn key(self) -> PublicEd25519 {
        self.key
    }

    pub fn challenge(self) -> Option<String> {
        self.challenge
    }
}

/// Verify the provided verifiable presentation against the current keypair.
///
/// See the `ErrorBag` documentation for more details on how to handle errors
/// that may occur during the validation process.
#[wasm_bindgen(js_name = "verifyPresentation")]
pub async fn js_verify_presentation(
    document: Object,
    context_loader: &mut ContextLoader,
) -> Result<PresentationVerificationResult, JsError> {
    let presentation = serde_wasm_bindgen::from_value(document.into())?;

    let (key, challenge) = verify_presentation(&presentation, &mut context_loader.0).await?;

    Ok(PresentationVerificationResult {
        key: PublicEd25519(key),
        challenge: challenge.map(ToString::to_string),
    })
}

/// Wrapped JWK value.
#[wasm_bindgen]
pub struct JWK(InnerJWK);

#[wasm_bindgen]
impl JWK {
    /// Create a new wrapped JWK value from the provided JWK object.
    #[wasm_bindgen(constructor)]
    pub fn new(object: &Object) -> Result<JWK, JsError> {
        Ok(Self(serde_wasm_bindgen::from_value(object.into())?))
    }

    /// Serialize the current wrapped JWK as an object.
    #[wasm_bindgen(js_name = "toJSON")]
    pub fn to_json(&self) -> Result<Object, JsError> {
        Ok(self.0.serialize(&OBJECT_SERIALIZER)?.into())
    }
}

/// Encoded W3C-compatible status list credential.
#[wasm_bindgen]
pub struct StatusListCredential(StatusList);

#[wasm_bindgen]
impl StatusListCredential {
    /// Create new StatusListCredential with all bits set to 0.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        StatusListCredential(StatusList::default())
    }

    /// Create new StatusListCredential from a credential subject object.
    #[wasm_bindgen(js_name = "fromCredentialSubject")]
    pub fn from_credential_subject(
        credential_subject: &Object,
    ) -> Result<StatusListCredential, JsError> {
        let credential: BitstringStatusListCredentialSubject =
            serde_wasm_bindgen::from_value(credential_subject.into())?;

        Ok(StatusListCredential(credential.encoded_list))
    }

    /// Check if a given index is revoked (bit set to 1).
    #[wasm_bindgen(js_name = "isRevoked")]
    pub fn is_revoked(&self, idx: usize) -> bool {
        self.0.is_set(idx)
    }

    /// Revoke a given index (set bit to 1).
    pub fn revoke(&mut self, idx: usize) {
        self.0.set(idx);
    }

    /// Serialize the current status list as an object.
    #[wasm_bindgen(js_name = "toJSON")]
    pub fn to_json(&self) -> Result<Object, JsError> {
        Ok(json!({
            "status_purpose": StatusPurpose::Revocation,
            "encoded_list": self.0,
        })
        .serialize(&OBJECT_SERIALIZER)?
        .into())
    }
}

impl Default for StatusListCredential {
    fn default() -> Self {
        Self::new()
    }
}

/// Encrypt the provided payload for the provided recipient array using A256GCM algorithm.
///
/// The provided recipients array must contain only wrapped X25519 JWK values.
///
/// You may acquire X25519 JWK values using the `toX25519PublicJWK` method on the keypair structs.
#[wasm_bindgen(js_name = "encryptAES")]
pub fn encrypt_aes(payload: Uint8Array, recipients: Vec<JWK>) -> Result<Object, JsError> {
    let jwe = teddybear_jwe::encrypt::<A256Gcm>(
        &payload.to_vec(),
        &recipients.iter().map(|val| &val.0).collect::<Vec<_>>(),
    )?;

    Ok(jwe.serialize(&OBJECT_SERIALIZER)?.into())
}

/// Encrypt the provided payload for the provided recipient array using XC20P algorithm.
///
/// The provided recipients array must contain only wrapped X25519 JWK values.
///
/// You may acquire X25519 JWK values using the `toX25519PublicJWK` method on the keypair structs.
#[wasm_bindgen(js_name = "encryptChaCha20")]
pub fn encrypt_chacha20(payload: Uint8Array, recipients: Vec<JWK>) -> Result<Object, JsError> {
    let jwe = teddybear_jwe::encrypt::<XC20P>(
        &payload.to_vec(),
        &recipients.iter().map(|val| &val.0).collect::<Vec<_>>(),
    )?;

    Ok(jwe.serialize(&OBJECT_SERIALIZER)?.into())
}
