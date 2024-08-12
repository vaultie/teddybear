// FIXME: https://github.com/rustwasm/wasm-bindgen/issues/3945
#![allow(clippy::empty_docs)]

extern crate alloc;

use std::{collections::HashMap, io::Cursor, str::FromStr};

use itertools::Itertools;
use js_sys::{Object, Uint8Array};
use serde::Serialize;
use serde_wasm_bindgen::Serializer;
use ssi_status::bitstring_status_list::{
    BitstringStatusList, StatusList, StatusPurpose, StatusSize, TimeToLive,
};
use teddybear_c2pa::{Builder, Ed25519Signer, Reader};
use teddybear_crypto::{
    DIDURLBuf, Ed25519VerificationKey2020, IriBuf, JwkVerificationMethod, UriBuf,
    X25519KeyAgreementKey2020,
};
use teddybear_jwe::{A256Gcm, XC20P};
use wasm_bindgen::prelude::*;

use teddybear_vc::{
    issue_vc, present_vp, verify, ContextLoader as InnerContextLoader, JsonCredential,
    JsonPresentation, DI,
};

const OBJECT_SERIALIZER: Serializer = Serializer::new().serialize_maps_as_objects(true);

#[wasm_bindgen(typescript_custom_section)]
const TYPESCRIPT_SECTION: &'static str = r#"
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

export type JWE = {
    protected: string;
    recipients: JWERecipient[];
    iv: string;
    ciphertext: string;
    tag: string;
};

export type VerificationMethod =
    | "assertionMethod"
    | "authentication"
    | "capabilityInvocation"
    | "capabilityDelegation"
    | "keyAgreement";

export type VerificationMethods = {
    [K in VerificationMethod]?: string[];
};
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "JWERecipient")]
    pub type JweRecipient;

    #[wasm_bindgen(typescript_type = "JWE")]
    pub type Jwe;

    #[wasm_bindgen(typescript_type = "VerificationMethods")]
    pub type VerificationMethods;
}

#[wasm_bindgen]
pub struct Document(teddybear_crypto::Document);

#[wasm_bindgen]
impl Document {
    pub async fn resolve(did: &str) -> Result<Document, JsError> {
        Ok(Document(
            teddybear_crypto::Document::resolve(&IriBuf::from_str(did)?).await?,
        ))
    }

    #[wasm_bindgen(js_name = "verificationMethods")]
    pub fn verification_methods(&self) -> Result<VerificationMethods, JsError> {
        let grouped = self.0.verification_methods().into_group_map();
        Ok(grouped.serialize(&OBJECT_SERIALIZER)?.into())
    }

    #[wasm_bindgen(js_name = "getEd25519VerificationMethod")]
    pub fn get_ed25519_verification_method(&self, id: &str) -> Result<PublicEd25519, JsError> {
        Ok(PublicEd25519(
            self.0
                .get_verification_method::<Ed25519VerificationKey2020, _>(&DIDURLBuf::from_str(
                    id,
                )?)?,
        ))
    }

    #[wasm_bindgen(js_name = "getX25519VerificationMethod")]
    pub fn get_x25519_verification_method(&self, id: &str) -> Result<PublicX25519, JsError> {
        Ok(PublicX25519(
            self.0
                .get_verification_method::<X25519KeyAgreementKey2020, _>(&DIDURLBuf::from_str(
                    id,
                )?)?,
        ))
    }

    /// Serialize the current document as an object.
    #[wasm_bindgen(js_name = "toJSON")]
    pub fn to_json(&self) -> Result<Object, JsError> {
        Ok(self.0.serialize(&OBJECT_SERIALIZER)?.into())
    }
}

/// A private Ed25519 keypair.
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

    /// Get the did:key DID value of the Ed25519 key.
    #[wasm_bindgen(js_name = "toDIDKey")]
    pub fn to_did_key(&self) -> String {
        self.0.to_did_key().into_string()
    }

    /// Convert private key to verification method object.
    #[wasm_bindgen(js_name = "toVerificationMethod")]
    pub fn to_verification_method(&self, id: &str, controller: &str) -> Result<Object, JsError> {
        let verification_method = self
            .0
            .to_verification_method(IriBuf::from_str(id)?, UriBuf::from_str(controller)?);

        Ok(verification_method.serialize(&OBJECT_SERIALIZER)?.into())
    }

    /// Sign the provided payload using the Ed25519 key.
    #[wasm_bindgen(js_name = "signJWS")]
    pub fn sign_jws(&self, payload: &str, embed_signing_key: bool) -> Result<String, JsError> {
        Ok(self.0.sign(payload, embed_signing_key)?)
    }

    /// Create a new verifiable credential.
    #[wasm_bindgen(js_name = "issueVC")]
    pub async fn issue_vc(
        &self,
        verification_method: &str,
        vc: Object,
        context_loader: &mut ContextLoader,
    ) -> Result<Object, JsError> {
        let credential = serde_wasm_bindgen::from_value(vc.into())?;
        let vm = IriBuf::from_str(verification_method)?;

        Ok(issue_vc(
            self.0.inner().clone(),
            vm,
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
        verification_method: &str,
        vp: Object,
        context_loader: &mut ContextLoader,
        domain: Option<String>,
        challenge: Option<String>,
    ) -> Result<Object, JsError> {
        let presentation = serde_wasm_bindgen::from_value(vp.into())?;
        let vm = IriBuf::from_str(verification_method)?;

        Ok(present_vp(
            self.0.inner().clone(),
            vm,
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

    /// Convert private key to verification method object.
    #[wasm_bindgen(js_name = "toVerificationMethod")]
    pub fn to_verification_method(&self, id: &str, controller: &str) -> Result<Object, JsError> {
        let verification_method = self
            .0
            .to_verification_method(IriBuf::from_str(id)?, UriBuf::from_str(controller)?);

        Ok(serde_wasm_bindgen::to_value(&verification_method)?.into())
    }

    /// Decrypt the provided JWE object using the X25519 key and the A256GCM algorithm.
    #[wasm_bindgen(js_name = "decryptAES")]
    pub fn decrypt_aes(&self, jwe: Jwe) -> Result<Uint8Array, JsError> {
        let jwe = serde_wasm_bindgen::from_value(jwe.into())?;
        let payload = &*teddybear_jwe::decrypt::<A256Gcm>(&jwe, self.0.inner())?;
        Ok(payload.into())
    }

    /// Decrypt the provided JWE object using the X25519 key and the XC20P algorithm.
    #[wasm_bindgen(js_name = "decryptChaCha20")]
    pub fn decrypt_chacha20(&self, jwe: Jwe) -> Result<Uint8Array, JsError> {
        let jwe = serde_wasm_bindgen::from_value(jwe.into())?;
        let payload = &*teddybear_jwe::decrypt::<XC20P>(&jwe, self.0.inner())?;
        Ok(payload.into())
    }

    #[wasm_bindgen(js_name = "addAESRecipient")]
    pub fn add_aes_recipient(
        &self,
        jwe: Jwe,
        recipient: PublicX25519,
    ) -> Result<JweRecipient, JsError> {
        let jwe = serde_wasm_bindgen::from_value(jwe.into())?;
        let recipient = teddybear_jwe::add_recipient::<A256Gcm>(
            &jwe,
            self.0.inner(),
            recipient.0.public_key.decoded(),
        )?;
        Ok(recipient.serialize(&OBJECT_SERIALIZER)?.into())
    }

    #[wasm_bindgen(js_name = "addChaCha20Recipient")]
    pub fn add_chacha20_recipient(
        &self,
        jwe: Jwe,
        recipient: PublicX25519,
    ) -> Result<JweRecipient, JsError> {
        let jwe = serde_wasm_bindgen::from_value(jwe.into())?;
        let recipient = teddybear_jwe::add_recipient::<XC20P>(
            &jwe,
            self.0.inner(),
            recipient.0.public_key.decoded(),
        )?;
        Ok(recipient.serialize(&OBJECT_SERIALIZER)?.into())
    }
}

/// A public Ed25519 keypair.
#[wasm_bindgen]
pub struct PublicEd25519(Ed25519VerificationKey2020);

#[wasm_bindgen]
impl PublicEd25519 {
    /// Get the JWK value (without the private key) of the Ed25519 key within the current keypair.
    #[wasm_bindgen(js_name = "toJWK")]
    pub fn to_jwk(&self) -> JWK {
        JWK(self.0.to_jwk().into_owned())
    }
}

/// A public X25519 keypair.
#[wasm_bindgen]
pub struct PublicX25519(X25519KeyAgreementKey2020);

#[wasm_bindgen]
impl PublicX25519 {
    /// Get the JWK value (without the private key) of the X25519 key within the current keypair.
    #[wasm_bindgen(js_name = "toJWK")]
    pub fn to_jwk(&self) -> JWK {
        JWK(self.0.to_jwk().into_owned())
    }
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
pub struct VerificationResult {
    key: PublicEd25519,
    challenge: Option<String>,
}

#[wasm_bindgen]
impl VerificationResult {
    pub fn key(self) -> PublicEd25519 {
        self.key
    }

    pub fn challenge(self) -> Option<String> {
        self.challenge
    }
}

/// Verify the provided verifiable credential.
#[wasm_bindgen(js_name = "verifyCredential")]
pub async fn js_verify_credential(
    document: Object,
    context_loader: &mut ContextLoader,
) -> Result<VerificationResult, JsError> {
    let credential: DI<JsonCredential> = serde_wasm_bindgen::from_value(document.into())?;

    let (key, challenge) = verify(&credential, &mut context_loader.0).await?;

    Ok(VerificationResult {
        key: PublicEd25519(key.clone()),
        challenge: challenge.map(ToString::to_string),
    })
}

/// Verify the provided verifiable presentation.
#[wasm_bindgen(js_name = "verifyPresentation")]
pub async fn js_verify_presentation(
    document: Object,
    context_loader: &mut ContextLoader,
) -> Result<VerificationResult, JsError> {
    let presentation: DI<JsonPresentation> = serde_wasm_bindgen::from_value(document.into())?;

    let (key, challenge) = verify(&presentation, &mut context_loader.0).await?;

    Ok(VerificationResult {
        key: PublicEd25519(key.clone()),
        challenge: challenge.map(ToString::to_string),
    })
}

/// Wrapped JWK value.
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
#[wasm_bindgen(js_name = "encryptAES")]
pub fn encrypt_aes(payload: Uint8Array, recipients: Vec<PublicX25519>) -> Result<Jwe, JsError> {
    let jwe = teddybear_jwe::encrypt::<A256Gcm, _>(
        &payload.to_vec(),
        recipients.iter().map(|val| val.0.public_key.decoded()),
    )?;

    Ok(jwe.serialize(&OBJECT_SERIALIZER)?.into())
}

/// Encrypt the provided payload for the provided recipient array using XC20P algorithm.
#[wasm_bindgen(js_name = "encryptChaCha20")]
pub fn encrypt_chacha20(
    payload: Uint8Array,
    recipients: Vec<PublicX25519>,
) -> Result<Jwe, JsError> {
    let jwe = teddybear_jwe::encrypt::<XC20P, _>(
        &payload.to_vec(),
        recipients.iter().map(|val| val.0.public_key.decoded()),
    )?;

    Ok(jwe.serialize(&OBJECT_SERIALIZER)?.into())
}

/// JWS verification result.
#[wasm_bindgen(js_name = "JWSVerificationResult")]
pub struct JwsVerificationResult(Option<teddybear_crypto::JWK>, Uint8Array);

#[wasm_bindgen(js_class = "JWSVerificationResult")]
impl JwsVerificationResult {
    /// Embedded JWK key.
    ///
    /// Corresponds to the `jwk` field within the JWS header.
    ///
    /// [`None`] if the JWS verification process was not using the embedded key.
    #[wasm_bindgen(getter)]
    pub fn jwk(&self) -> Option<JWK> {
        self.0.clone().map(JWK)
    }

    /// JWS payload.
    #[wasm_bindgen(getter)]
    pub fn payload(&self) -> Uint8Array {
        self.1.clone()
    }
}

/// Verify JWS signature against the embedded JWK key.
///
/// Returns both the signed payload and the embedded JWK key used to sign the payload.
#[wasm_bindgen(js_name = "verifyJWS")]
pub fn verify_jws(jws: &str, key: Option<JWK>) -> Result<JwsVerificationResult, JsError> {
    let (jwk, payload) = if let Some(key) = key {
        (None, teddybear_crypto::verify_jws(jws, &key.0)?)
    } else {
        let (jwk, payload) = teddybear_crypto::verify_jws_with_embedded_jwk(jws)?;
        (Some(jwk), payload)
    };

    Ok(JwsVerificationResult(jwk, payload.as_slice().into()))
}

/// Encoded W3C-compatible status list credential.
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

    #[wasm_bindgen(js_name = "addResource")]
    pub fn add_resource(mut self, source: Uint8Array, id: &str) -> Result<C2paBuilder, JsError> {
        let mut source = Cursor::new(source.to_vec());
        self.0.add_resource(id, &mut source)?;
        Ok(self)
    }

    pub fn sign(
        mut self,
        key: &PrivateEd25519,
        certificate: Uint8Array,
        source: Uint8Array,
        format: &str,
    ) -> Result<C2paSignatureResult, JsError> {
        let mut source = Cursor::new(source.to_vec());
        let mut dest = Cursor::new(Vec::new());

        let signer = Ed25519Signer::new(key.0.inner().clone(), certificate.to_vec());

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
#[derive(Clone)]
#[wasm_bindgen(js_name = "C2PAValidationError")]
pub struct C2paValidationError {
    code: String,
    url: Option<String>,
}

#[wasm_bindgen(js_class = "C2PAValidationError")]
impl C2paValidationError {
    /// Validation error code.
    #[wasm_bindgen(getter)]
    pub fn code(&self) -> String {
        self.code.clone()
    }

    /// Related resource URL.
    #[wasm_bindgen(getter)]
    pub fn url(&self) -> Option<String> {
        self.url.clone()
    }
}

/// C2PA verification result.
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

#[wasm_bindgen(js_name = "verifyC2PA")]
pub fn verify_c2pa(source: Uint8Array, format: &str) -> Result<C2paVerificationResult, JsError> {
    let source = Cursor::new(source.to_vec());
    let reader = Reader::from_stream(format, source)?;

    let validation_errors = reader
        .validation_status()
        .unwrap_or(&[])
        .iter()
        .filter(|v| !v.passed())
        .map(|v| C2paValidationError {
            code: v.code().to_owned(),
            url: v.url().map(ToOwned::to_owned),
        })
        .collect();

    let manifests = reader
        .iter_manifests()
        .map(serde_wasm_bindgen::to_value)
        .map_ok(Into::into)
        .try_collect()?;

    Ok(C2paVerificationResult {
        manifests,
        validation_errors,
    })
}
