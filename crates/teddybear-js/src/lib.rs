#![allow(
    // FIXME: https://github.com/rustwasm/wasm-bindgen/issues/3945
    clippy::empty_docs,

    // This crate is not meant to be used in Rust at all,
    // so ToString trait impls play no role in here.
    clippy::inherent_to_string
)]

extern crate alloc;

use std::{collections::HashMap, io::Cursor, str::FromStr};

use itertools::Itertools;
use js_sys::{Object, Uint8Array};
use serde::Serialize;
use serde_wasm_bindgen::Serializer;
use ssi_status::bitstring_status_list::{
    BitstringStatusList, StatusList, StatusPurpose, StatusSize, TimeToLive,
};
use teddybear_c2pa::{Builder, Ed25519Signer, Reader, ValidationStatus};
use teddybear_crypto::{
    DIDBuf, DIDURLBuf, Ed25519VerificationKey2020, JwkVerificationMethod, SignOptions,
    ValueOrReference, X25519KeyAgreementKey2020,
};
use teddybear_jwe::{A256Gcm, XC20P};
use wasm_bindgen::prelude::*;

use teddybear_vc::{
    issue_vc, present_vp, verify, ContextLoader as InnerContextLoader, JsonPresentation,
    SpecializedJsonCredential, DI,
};

const OBJECT_SERIALIZER: Serializer = Serializer::new().serialize_maps_as_objects(true);

#[wasm_bindgen(typescript_custom_section)]
const TYPESCRIPT_SECTION: &'static str = r#"
/**
 * A single X25519 JWE recipient.
 *
 * @category JOSE
 */
export type JWERecipient = {
    header: {
        kid: string;
        alg: "ECDH-ES+A256KW";
        epk: {
            kty: "OKP";
            crv: "X25519";
            x: string;
        };
        apu: string;
        apv: string;
    };
    encrypted_key: string;
};

/**
 * JWE object.
 *
 * @category JOSE
 */
export type JWE = {
    protected: string;
    recipients: JWERecipient[];
    iv: string;
    ciphertext: string;
    tag: string;
};

/**
 * JWS signing options.
 *
 * @category JOSE
 */
export type JWSOptions = {
    embedSigningKey?: boolean;
    keyIdentifier?: string;
};
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "JWERecipient")]
    pub type JweRecipient;

    #[wasm_bindgen(typescript_type = "JWE")]
    pub type Jwe;

    #[wasm_bindgen(typescript_type = "JWSOptions")]
    pub type JwsOptions;
}

/// DID value.
///
/// @category DID
#[wasm_bindgen]
pub struct DID(DIDBuf);

#[wasm_bindgen]
impl DID {
    #[wasm_bindgen(constructor)]
    pub fn new(value: String) -> Result<DID, JsError> {
        Ok(DID(DIDBuf::from_string(value)?))
    }

    #[wasm_bindgen(js_name = "toString")]
    pub fn to_string(&self) -> String {
        self.0.to_string()
    }
}

/// DIDURL value.
///
/// @category DID
#[wasm_bindgen]
#[derive(Clone)]
pub struct DIDURL(DIDURLBuf);

#[wasm_bindgen]
impl DIDURL {
    #[wasm_bindgen(constructor)]
    pub fn new(value: String) -> Result<DIDURL, JsError> {
        Ok(DIDURL(DIDURLBuf::from_string(value)?))
    }

    pub fn did(&self) -> DID {
        DID(self.0.did().to_owned())
    }

    #[wasm_bindgen(js_name = "toString")]
    pub fn to_string(&self) -> String {
        self.0.to_string()
    }
}

#[wasm_bindgen]
pub struct VerificationMethods {
    assertion_method: Vec<DIDURL>,
    authentication: Vec<DIDURL>,
    capability_invocation: Vec<DIDURL>,
    capability_delegation: Vec<DIDURL>,
    key_agreement: Vec<DIDURL>,
}

#[wasm_bindgen]
impl VerificationMethods {
    #[wasm_bindgen(js_name = "assertionMethod", getter)]
    pub fn assertion_method(&self) -> Vec<DIDURL> {
        self.assertion_method.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn authentication(&self) -> Vec<DIDURL> {
        self.authentication.clone()
    }

    #[wasm_bindgen(js_name = "capabilityInvocation", getter)]
    pub fn capability_invocation(&self) -> Vec<DIDURL> {
        self.capability_invocation.clone()
    }

    #[wasm_bindgen(js_name = "capabilityDelegation", getter)]
    pub fn capability_delegation(&self) -> Vec<DIDURL> {
        self.capability_delegation.clone()
    }

    #[wasm_bindgen(js_name = "keyAgreement", getter)]
    pub fn key_agreement(&self) -> Vec<DIDURL> {
        self.key_agreement.clone()
    }
}

/// DID document.
///
/// @category DID
#[wasm_bindgen]
pub struct Document(teddybear_crypto::Document);

#[wasm_bindgen]
impl Document {
    #[wasm_bindgen(constructor)]
    pub fn new(document: Object) -> Result<Document, JsError> {
        let document = serde_wasm_bindgen::from_value(document.into())?;
        Ok(Document(document))
    }

    #[wasm_bindgen(getter)]
    pub fn id(&self) -> DID {
        DID(self.0.inner.id.to_owned())
    }

    pub async fn resolve(did: &DID, options: Option<Object>) -> Result<Document, JsError> {
        let options = options
            .map(Into::into)
            .map(serde_wasm_bindgen::from_value)
            .transpose()?
            .unwrap_or_default();

        Ok(Document(
            teddybear_crypto::Document::resolve(&did.0, options).await?,
        ))
    }

    #[wasm_bindgen(js_name = "verificationMethods")]
    pub fn verification_methods(&self) -> VerificationMethods {
        fn convert_vr(id: &teddybear_crypto::DID, values: &[ValueOrReference]) -> Vec<DIDURL> {
            values
                .iter()
                .map(|vr| DIDURL(vr.id().resolve(id).into_owned()))
                .collect()
        }

        VerificationMethods {
            assertion_method: convert_vr(
                &self.0.inner.id,
                &self.0.inner.verification_relationships.assertion_method,
            ),
            authentication: convert_vr(
                &self.0.inner.id,
                &self.0.inner.verification_relationships.authentication,
            ),
            capability_invocation: convert_vr(
                &self.0.inner.id,
                &self
                    .0
                    .inner
                    .verification_relationships
                    .capability_invocation,
            ),
            capability_delegation: convert_vr(
                &self.0.inner.id,
                &self
                    .0
                    .inner
                    .verification_relationships
                    .capability_delegation,
            ),
            key_agreement: convert_vr(
                &self.0.inner.id,
                &self.0.inner.verification_relationships.key_agreement,
            ),
        }
    }

    #[wasm_bindgen(js_name = "getEd25519VerificationMethod")]
    pub fn get_ed25519_verification_method(&self, id: &DIDURL) -> Result<PublicEd25519, JsError> {
        Ok(PublicEd25519(self.0.get_verification_method(&id.0)?))
    }

    #[wasm_bindgen(js_name = "getX25519VerificationMethod")]
    pub fn get_x25519_verification_method(&self, id: &DIDURL) -> Result<PublicX25519, JsError> {
        Ok(PublicX25519(self.0.get_verification_method(&id.0)?))
    }

    /// Serialize the current document as an object.
    #[wasm_bindgen(js_name = "toJSON")]
    pub fn to_json(&self) -> Result<Object, JsError> {
        Ok(self.0.serialize(&OBJECT_SERIALIZER)?.into())
    }
}

/// Private Ed25519 key.
///
/// @category Keys
#[wasm_bindgen]
pub struct PrivateEd25519(teddybear_crypto::PrivateEd25519);

#[wasm_bindgen]
impl PrivateEd25519 {
    /// Create a new random keypair.
    pub fn generate() -> PrivateEd25519 {
        PrivateEd25519(teddybear_crypto::PrivateEd25519::generate())
    }

    /// Convert private key bytes into a public/private Ed25519 keypair.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(value: Uint8Array) -> PrivateEd25519 {
        let mut dst = [0; 32];
        value.copy_to(&mut dst);
        PrivateEd25519(teddybear_crypto::PrivateEd25519::from_bytes(&dst))
    }

    /// Get Ed25519 private key bytes.
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Uint8Array {
        self.0.inner().as_bytes().as_slice().into()
    }

    /// Convert Ed25519 private key to X25519 private key.
    #[wasm_bindgen(js_name = "toX25519PrivateKey")]
    pub fn to_x25519_private_key(&self) -> PrivateX25519 {
        PrivateX25519(self.0.to_x25519_private_key())
    }

    /// Get the JWK value (without the private key) of the Ed25519 key.
    #[wasm_bindgen(js_name = "toPublicJWK")]
    pub fn to_public_jwk(&self) -> JWK {
        JWK(self.0.to_public_jwk())
    }

    /// Get the JWK value (with the private key) of the Ed25519 key.
    #[wasm_bindgen(js_name = "toPrivateJWK")]
    pub fn to_private_jwk(&self) -> JWK {
        JWK(self.0.to_private_jwk())
    }

    /// Get the did:key document DID value of the Ed25519 key.
    #[wasm_bindgen(js_name = "toDIDKey")]
    pub fn to_did_key(&self) -> DID {
        DID(self.0.to_did_key())
    }

    /// Get the did:key DID URL fragment value of the Ed25519 key.
    #[wasm_bindgen(js_name = "toDIDKeyURLFragment")]
    pub fn to_did_key_url_fragment(&self) -> String {
        self.0.to_did_key_url_fragment().to_string()
    }

    /// Derive an Ed25519 public key from the private key.
    #[wasm_bindgen(js_name = "toPublicKey")]
    pub fn to_public_key(&self, id: &DIDURL, controller: &DID) -> Result<PublicEd25519, JsError> {
        let verification_method = self
            .0
            .to_verification_method(id.0.as_iri().to_owned(), controller.0.as_uri().to_owned());

        Ok(PublicEd25519(verification_method))
    }

    /// Sign the provided payload using the Ed25519 key.
    #[wasm_bindgen(js_name = "signJWS")]
    pub fn sign_jws(&self, payload: &str, options: Option<JwsOptions>) -> Result<String, JsError> {
        let options: SignOptions = options
            .map(Into::into)
            .map(serde_wasm_bindgen::from_value)
            .transpose()?
            .unwrap_or_default();

        Ok(self.0.sign(payload, options)?)
    }

    /// Create a new verifiable credential.
    #[wasm_bindgen(js_name = "issueVC")]
    pub async fn issue_vc(
        &self,
        verification_method: &DIDURL,
        vc: Object,
        context_loader: &mut ContextLoader,
    ) -> Result<Object, JsError> {
        let credential: SpecializedJsonCredential = serde_wasm_bindgen::from_value(vc.into())?;

        Ok(issue_vc(
            self.0.inner().clone(),
            verification_method.0.as_iri().to_owned(),
            &credential,
            &mut context_loader.0,
        )
        .await?
        .serialize(&OBJECT_SERIALIZER)?
        .into())
    }

    /// Create a new verifiable presentation.
    #[wasm_bindgen(js_name = "presentVP")]
    pub async fn present_vp(
        &self,
        verification_method: &DIDURL,
        vp: Object,
        context_loader: &mut ContextLoader,
        domain: Option<String>,
        challenge: Option<String>,
    ) -> Result<Object, JsError> {
        let presentation: JsonPresentation<SpecializedJsonCredential> =
            serde_wasm_bindgen::from_value(vp.into())?;

        Ok(present_vp(
            self.0.inner().clone(),
            verification_method.0.as_iri().to_owned(),
            &presentation,
            domain,
            challenge,
            &mut context_loader.0,
        )
        .await?
        .serialize(&OBJECT_SERIALIZER)?
        .into())
    }
}

/// Private X25519 key.
///
/// @category Keys
#[wasm_bindgen]
pub struct PrivateX25519(teddybear_crypto::PrivateX25519);

#[wasm_bindgen]
impl PrivateX25519 {
    /// Get the JWK value (without the private key) of the X25519 key.
    #[wasm_bindgen(js_name = "toPublicJWK")]
    pub fn to_public_jwk(&self) -> JWK {
        JWK(self.0.to_public_jwk())
    }

    /// Get the JWK value (with the private key) of the X25519 key.
    #[wasm_bindgen(js_name = "toPrivateJWK")]
    pub fn to_private_jwk(&self) -> JWK {
        JWK(self.0.to_private_jwk())
    }

    /// Get the did:key DID URL fragment value of the X25519 key.
    #[wasm_bindgen(js_name = "toDIDKeyURLFragment")]
    pub fn to_did_key_url_fragment(&self) -> String {
        self.0.to_did_key_url_fragment().to_string()
    }

    /// Derive an X25519 public key from the private key.
    #[wasm_bindgen(js_name = "toPublicKey")]
    pub fn to_public_key(&self, id: &DIDURL, controller: &DID) -> Result<PublicX25519, JsError> {
        let verification_method = self
            .0
            .to_verification_method(id.0.as_iri().to_owned(), controller.0.as_uri().to_owned());

        Ok(PublicX25519(verification_method))
    }

    /// Decrypt the provided JWE object using the X25519 key and the A256GCM algorithm.
    #[wasm_bindgen(js_name = "decryptAES")]
    pub fn decrypt_aes(
        &self,
        verification_method: &DIDURL,
        jwe: Jwe,
    ) -> Result<Uint8Array, JsError> {
        let jwe = serde_wasm_bindgen::from_value(jwe.into())?;
        let payload =
            &*teddybear_jwe::decrypt::<A256Gcm>(&jwe, &verification_method.0, self.0.inner())?;
        Ok(payload.into())
    }

    /// Decrypt the provided JWE object using the X25519 key and the XC20P algorithm.
    #[wasm_bindgen(js_name = "decryptChaCha20")]
    pub fn decrypt_chacha20(
        &self,
        verification_method: &DIDURL,
        jwe: Jwe,
    ) -> Result<Uint8Array, JsError> {
        let jwe = serde_wasm_bindgen::from_value(jwe.into())?;
        let payload =
            &*teddybear_jwe::decrypt::<XC20P>(&jwe, &verification_method.0, self.0.inner())?;
        Ok(payload.into())
    }

    #[wasm_bindgen(js_name = "addAESRecipient")]
    pub fn add_aes_recipient(
        &self,
        verification_method: &DIDURL,
        jwe: Jwe,
        recipient: PublicX25519,
    ) -> Result<JweRecipient, JsError> {
        let jwe = serde_wasm_bindgen::from_value(jwe.into())?;
        let recipient = teddybear_jwe::add_recipient::<A256Gcm>(
            &jwe,
            &verification_method.0,
            self.0.inner(),
            recipient.0.id.as_str().to_owned(),
            recipient.0.public_key.decoded(),
        )?;
        Ok(recipient.serialize(&OBJECT_SERIALIZER)?.into())
    }

    #[wasm_bindgen(js_name = "addChaCha20Recipient")]
    pub fn add_chacha20_recipient(
        &self,
        verification_method: &DIDURL,
        jwe: Jwe,
        recipient: PublicX25519,
    ) -> Result<JweRecipient, JsError> {
        let jwe = serde_wasm_bindgen::from_value(jwe.into())?;
        let recipient = teddybear_jwe::add_recipient::<XC20P>(
            &jwe,
            &verification_method.0,
            self.0.inner(),
            recipient.0.id.as_str().to_owned(),
            recipient.0.public_key.decoded(),
        )?;
        Ok(recipient.serialize(&OBJECT_SERIALIZER)?.into())
    }
}

/// Public Ed25519 key.
///
/// @category Keys
#[wasm_bindgen]
pub struct PublicEd25519(Ed25519VerificationKey2020);

#[wasm_bindgen]
impl PublicEd25519 {
    /// Get the verification method identifier.
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> Result<DIDURL, JsError> {
        // FIXME: Remove the unnecessary double-conversion
        Ok(DIDURL(DIDURLBuf::from_str(&self.0.id)?))
    }

    /// Get the verification method controller.
    #[wasm_bindgen(getter)]
    pub fn controller(&self) -> Result<DID, JsError> {
        // FIXME: Remove the unnecessary double-conversion
        Ok(DID(DIDBuf::from_str(&self.0.controller)?))
    }

    /// Get the JWK value (without the private key) of the Ed25519 key within the current keypair.
    #[wasm_bindgen(js_name = "toJWK")]
    pub fn to_jwk(&self) -> JWK {
        JWK(self.0.to_jwk().into_owned())
    }

    /// Serialize the current public key as a verification method object.
    #[wasm_bindgen(js_name = "toJSON")]
    pub fn to_json(&self) -> Result<Object, JsError> {
        Ok(self.0.serialize(&OBJECT_SERIALIZER)?.into())
    }
}

/// Public X25519 key.
///
/// @category Keys
#[wasm_bindgen]
pub struct PublicX25519(X25519KeyAgreementKey2020);

#[wasm_bindgen]
impl PublicX25519 {
    /// Get the verification method identifier.
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> Result<DIDURL, JsError> {
        // FIXME: Remove the unnecessary double-conversion
        Ok(DIDURL(DIDURLBuf::from_str(&self.0.id)?))
    }

    /// Get the verification method controller.
    #[wasm_bindgen(getter)]
    pub fn controller(&self) -> Result<DID, JsError> {
        // FIXME: Remove the unnecessary double-conversion
        Ok(DID(DIDBuf::from_str(&self.0.controller)?))
    }

    /// Get the JWK value (without the private key) of the X25519 key within the current keypair.
    #[wasm_bindgen(js_name = "toJWK")]
    pub fn to_jwk(&self) -> JWK {
        JWK(self.0.to_jwk().into_owned())
    }

    /// Serialize the current public key as a verification method object.
    #[wasm_bindgen(js_name = "toJSON")]
    pub fn to_json(&self) -> Result<Object, JsError> {
        Ok(self.0.serialize(&OBJECT_SERIALIZER)?.into())
    }
}

/// JSON-LD context loader.
///
/// @category W3C VC
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

/// Verifiable presentation verification result.
///
/// @category W3C VC
#[wasm_bindgen]
pub struct VerificationResult {
    key: Ed25519VerificationKey2020,
    challenge: Option<String>,
}

#[wasm_bindgen]
impl VerificationResult {
    #[wasm_bindgen(getter)]
    pub fn key(&self) -> PublicEd25519 {
        PublicEd25519(self.key.clone())
    }

    #[wasm_bindgen(getter)]
    pub fn challenge(&self) -> Option<String> {
        self.challenge.clone()
    }
}

/// Verify the provided verifiable credential.
///
/// @category W3C VC
#[wasm_bindgen(js_name = "verifyCredential")]
pub async fn js_verify_credential(
    document: Object,
    context_loader: &mut ContextLoader,
) -> Result<VerificationResult, JsError> {
    let credential: DI<SpecializedJsonCredential> =
        serde_wasm_bindgen::from_value(document.into())?;

    let (key, challenge) = verify(&credential, &mut context_loader.0).await?;

    Ok(VerificationResult {
        key,
        challenge: challenge.map(ToString::to_string),
    })
}

/// Verify the provided verifiable presentation.
///
/// @category W3C VC
#[wasm_bindgen(js_name = "verifyPresentation")]
pub async fn js_verify_presentation(
    document: Object,
    context_loader: &mut ContextLoader,
) -> Result<VerificationResult, JsError> {
    let presentation: DI<JsonPresentation> = serde_wasm_bindgen::from_value(document.into())?;

    let (key, challenge) = verify(&presentation, &mut context_loader.0).await?;

    Ok(VerificationResult {
        key,
        challenge: challenge.map(ToString::to_string),
    })
}

/// Encoded W3C-compatible status list credential.
///
/// @category W3C VC
#[wasm_bindgen]
pub struct StatusListCredential(StatusList);

#[wasm_bindgen]
impl StatusListCredential {
    /// Create new StatusListCredential with all bits set to 0.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        StatusListCredential(StatusList::new(StatusSize::DEFAULT, TimeToLive::DEFAULT))
    }

    /// Create new StatusListCredential from a credential subject object.
    #[wasm_bindgen(js_name = "fromCredentialSubject")]
    pub fn from_credential_subject(
        credential_subject: &Object,
    ) -> Result<StatusListCredential, JsError> {
        let credential: BitstringStatusList =
            serde_wasm_bindgen::from_value(credential_subject.into())?;

        Ok(StatusListCredential(credential.decode()?))
    }

    #[wasm_bindgen]
    pub fn allocate(&mut self) -> Result<usize, JsError> {
        Ok(self.0.push(0)?)
    }

    /// Check if a given index is revoked (bit set to 1).
    #[wasm_bindgen(js_name = "isRevoked")]
    pub fn is_revoked(&self, idx: usize) -> bool {
        self.0.get(idx).map(|val| val == 1).unwrap_or(false)
    }

    /// Revoke a given index (set bit to 1).
    pub fn revoke(&mut self, idx: usize) -> Result<(), JsError> {
        self.0.set(idx, 1)?;
        Ok(())
    }

    /// Serialize the current status list as an object.
    #[wasm_bindgen(js_name = "toJSON")]
    pub fn to_json(&self) -> Result<Object, JsError> {
        Ok(self
            .0
            .to_credential_subject(None, StatusPurpose::Revocation, Vec::new())
            .serialize(&OBJECT_SERIALIZER)?
            .into())
    }
}

impl Default for StatusListCredential {
    fn default() -> Self {
        Self::new()
    }
}

/// Wrapped JWK value.
///
/// @category JOSE
#[wasm_bindgen]
pub struct JWK(teddybear_crypto::JWK);

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

/// Encrypt the provided payload for the provided recipient array using A256GCM algorithm.
///
/// @category JOSE
#[wasm_bindgen(js_name = "encryptAES")]
pub fn encrypt_aes(payload: Uint8Array, recipients: Vec<PublicX25519>) -> Result<Jwe, JsError> {
    let jwe = teddybear_jwe::encrypt::<A256Gcm, _>(
        &payload.to_vec(),
        recipients
            .iter()
            .map(|val| (val.0.id.as_str().to_owned(), val.0.public_key.decoded())),
    )?;

    Ok(jwe.serialize(&OBJECT_SERIALIZER)?.into())
}

/// Encrypt the provided payload for the provided recipient array using XC20P algorithm.
///
/// @category JOSE
#[wasm_bindgen(js_name = "encryptChaCha20")]
pub fn encrypt_chacha20(
    payload: Uint8Array,
    recipients: Vec<PublicX25519>,
) -> Result<Jwe, JsError> {
    let jwe = teddybear_jwe::encrypt::<XC20P, _>(
        &payload.to_vec(),
        recipients
            .iter()
            .map(|val| (val.0.id.as_str().to_owned(), val.0.public_key.decoded())),
    )?;

    Ok(jwe.serialize(&OBJECT_SERIALIZER)?.into())
}

/// JWS verification result.
///
/// @category JOSE
#[wasm_bindgen(js_name = "JWSVerificationResult")]
pub struct JwsVerificationResult(Option<teddybear_crypto::JWK>, Option<String>, Uint8Array);

#[wasm_bindgen(js_class = "JWSVerificationResult")]
impl JwsVerificationResult {
    /// Embedded JWK key.
    ///
    /// Corresponds to the `jwk` field within the JWS header.
    ///
    /// [`None`] if the JWS signing process had been completed without embedding the JWK value.
    #[wasm_bindgen(getter)]
    pub fn jwk(&self) -> Option<JWK> {
        self.0.clone().map(JWK)
    }

    /// Key identifier.
    ///
    /// [`None`] if the JWS signing process had been completed without embedding the key identifier.
    #[wasm_bindgen(getter, js_name = "keyID")]
    pub fn key_id(&self) -> Option<String> {
        self.1.clone()
    }

    /// JWS payload.
    #[wasm_bindgen(getter)]
    pub fn payload(&self) -> Uint8Array {
        self.2.clone()
    }
}

/// Verify JWS signature against the embedded JWK key.
///
/// Returns both the signed payload and the embedded JWK key used to sign the payload.
///
/// @category JOSE
#[wasm_bindgen(js_name = "verifyJWS")]
pub fn verify_jws(jws: &str, key: Option<JWK>) -> Result<JwsVerificationResult, JsError> {
    let (jwk, key_id, payload) = if let Some(key) = key {
        let (key_id, payload) = teddybear_crypto::verify_jws(jws, &key.0)?;
        (None, key_id, payload)
    } else {
        let (jwk, key_id, payload) = teddybear_crypto::verify_jws_with_embedded_jwk(jws)?;
        (Some(jwk), key_id, payload)
    };

    Ok(JwsVerificationResult(
        jwk,
        key_id,
        payload.as_slice().into(),
    ))
}

/// C2PA signing result.
///
/// @category C2PA
#[wasm_bindgen(js_name = "C2PASignatureResult")]
pub struct C2paSignatureResult(Vec<u8>, Vec<u8>);

#[wasm_bindgen(js_class = "C2PASignatureResult")]
impl C2paSignatureResult {
    /// Payload with C2PA manifest embedded within.
    #[wasm_bindgen(getter, js_name = "signedPayload")]
    pub fn signed_payload(&self) -> Uint8Array {
        self.0.as_slice().into()
    }

    /// C2PA manifest value.
    #[wasm_bindgen(getter)]
    pub fn manifest(&self) -> Uint8Array {
        self.1.as_slice().into()
    }
}

/// C2PA signature builder.
///
/// @category C2PA
#[wasm_bindgen(js_name = "C2PABuilder")]
pub struct C2paBuilder(Builder);

#[wasm_bindgen(js_class = "C2PABuilder")]
impl C2paBuilder {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self(Builder::default())
    }

    #[wasm_bindgen(js_name = "setManifestDefinition")]
    pub fn set_manifest_definition(mut self, definition: Object) -> Result<C2paBuilder, JsError> {
        self.0.definition = serde_wasm_bindgen::from_value(definition.into())?;
        Ok(self)
    }

    #[wasm_bindgen(js_name = "setThumbnail")]
    pub fn set_thumbnail(
        mut self,
        source: Uint8Array,
        format: &str,
    ) -> Result<C2paBuilder, JsError> {
        let mut source = Cursor::new(source.to_vec());
        self.0.set_thumbnail(format, &mut source)?;
        Ok(self)
    }

    pub async fn sign(
        mut self,
        key: &PrivateEd25519,
        certificates: Vec<Uint8Array>,
        source: Uint8Array,
        format: &str,
    ) -> Result<C2paSignatureResult, JsError> {
        let mut source = Cursor::new(source.to_vec());
        let mut dest = Cursor::new(Vec::new());

        let signer = Ed25519Signer::new(
            key.0.inner().clone(),
            certificates.into_iter().map(|val| val.to_vec()).collect(),
        );

        let manifest = self.0.sign(&signer, format, &mut source, &mut dest)?;

        Ok(C2paSignatureResult(dest.into_inner(), manifest))
    }
}

impl Default for C2paBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// C2PA validation error.
///
/// @category C2PA
#[derive(Clone)]
#[wasm_bindgen(js_name = "C2PAValidationError")]
pub struct C2paValidationError(ValidationStatus);

#[wasm_bindgen(js_class = "C2PAValidationError")]
impl C2paValidationError {
    /// Validation error code.
    #[wasm_bindgen(getter)]
    pub fn code(&self) -> String {
        self.0.code().to_owned()
    }

    /// Related resource URL.
    #[wasm_bindgen(getter)]
    pub fn url(&self) -> Option<String> {
        self.0.url().map(ToOwned::to_owned)
    }

    /// Human-readable error explanation.
    #[wasm_bindgen(getter)]
    pub fn explanation(&self) -> Option<String> {
        self.0.explanation().map(ToOwned::to_owned)
    }

    /// Serialize the current error as an object.
    #[wasm_bindgen(js_name = "toJSON")]
    pub fn to_json(&self) -> Result<Object, JsError> {
        Ok(self.0.serialize(&OBJECT_SERIALIZER)?.into())
    }
}

/// C2PA signature verification result.
///
/// @category C2PA
#[wasm_bindgen(js_name = "C2PAVerificationResult")]
pub struct C2paVerificationResult {
    manifests: Vec<Object>,
    validation_errors: Vec<C2paValidationError>,
}

#[wasm_bindgen(js_class = "C2PAVerificationResult")]
impl C2paVerificationResult {
    /// Embedded C2PA manifests.
    #[wasm_bindgen(getter)]
    pub fn manifests(&self) -> Vec<Object> {
        self.manifests.clone()
    }

    /// Validation error code.
    #[wasm_bindgen(getter, js_name = "validationErrors")]
    pub fn validation_errors(&self) -> Vec<C2paValidationError> {
        self.validation_errors.clone()
    }
}

/// Verify C2PA signatures within a file.
///
/// @category C2PA
#[wasm_bindgen(js_name = "verifyC2PA")]
pub async fn verify_c2pa(
    source: Uint8Array,
    format: &str,
) -> Result<C2paVerificationResult, JsError> {
    let source = Cursor::new(source.to_vec());
    let reader = Reader::from_stream(format, source)?;

    let validation_errors = reader
        .validation_status()
        .unwrap_or(&[])
        .iter()
        .filter(|v| !v.passed())
        .map(|v| C2paValidationError(v.clone()))
        .collect();

    let manifests = reader
        .iter_manifests()
        .map(|manifest| manifest.serialize(&OBJECT_SERIALIZER))
        .map_ok(Into::into)
        .try_collect()?;

    Ok(C2paVerificationResult {
        manifests,
        validation_errors,
    })
}
