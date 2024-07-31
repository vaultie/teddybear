// FIXME: https://github.com/rustwasm/wasm-bindgen/issues/3945
#![allow(clippy::empty_docs)]

extern crate alloc;

use std::{collections::HashMap, io::Cursor};

use js_sys::{Object, Uint8Array};
use serde::Serialize;
use serde_wasm_bindgen::Serializer;
use teddybear_c2pa::{Ed25519Signer, ManifestDefinition};
use teddybear_crypto::{Ed25519, Private, Public, JWK as InnerJWK};
use teddybear_jwe::{add_recipient, decrypt, A256Gcm, XC20P};
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
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "JWERecipient")]
    pub type JweRecipient;

    #[wasm_bindgen(typescript_type = "JWE")]
    pub type Jwe;
}

#[wasm_bindgen]
pub struct C2PASignatureResult(Vec<u8>, Vec<u8>);

#[wasm_bindgen(js_class = "C2PASignatureResult")]
impl C2PASignatureResult {
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

    /// Convert private key bytes into a public/private Ed25519 keypair.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub async fn from_bytes(value: Uint8Array) -> Result<PrivateEd25519, JsError> {
        let mut dst = [0; 32];
        value.copy_to(&mut dst);
        Ok(PrivateEd25519(Ed25519::from_bytes(dst).await?))
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
    pub fn decrypt_aes(&self, jwe: Jwe) -> Result<Uint8Array, JsError> {
        let jwe = serde_wasm_bindgen::from_value(jwe.into())?;
        let payload = &*decrypt::<A256Gcm>(&jwe, self.0.as_x25519_private_jwk())?;
        Ok(payload.into())
    }

    /// Decrypt the provided JWE object using the X25519 key and the XC20P algorithm.
    #[wasm_bindgen(js_name = "decryptChaCha20")]
    pub fn decrypt_chacha20(&self, jwe: Jwe) -> Result<Uint8Array, JsError> {
        let jwe = serde_wasm_bindgen::from_value(jwe.into())?;
        let payload = &*decrypt::<XC20P>(&jwe, self.0.as_x25519_private_jwk())?;
        Ok(payload.into())
    }

    #[wasm_bindgen(js_name = "addAESRecipient")]
    pub fn add_aes_recipient(&self, jwe: Jwe, recipient: JWK) -> Result<JweRecipient, JsError> {
        let jwe = serde_wasm_bindgen::from_value(jwe.into())?;
        let recipient =
            add_recipient::<A256Gcm>(&jwe, self.0.as_x25519_private_jwk(), &recipient.0)?;
        Ok(recipient.serialize(&OBJECT_SERIALIZER)?.into())
    }

    #[wasm_bindgen(js_name = "addChaCha20Recipient")]
    pub fn add_chacha20_recipient(
        &self,
        jwe: Jwe,
        recipient: JWK,
    ) -> Result<JweRecipient, JsError> {
        let jwe = serde_wasm_bindgen::from_value(jwe.into())?;
        let recipient = add_recipient::<XC20P>(&jwe, self.0.as_x25519_private_jwk(), &recipient.0)?;
        Ok(recipient.serialize(&OBJECT_SERIALIZER)?.into())
    }

    /// Sign the provided payload using the Ed25519 key.
    #[wasm_bindgen(js_name = "signJWS")]
    pub fn sign_jws(&self, payload: &str, embed_signing_key: bool) -> Result<String, JsError> {
        Ok(self.0.sign(payload, embed_signing_key)?)
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
        let credential = serde_wasm_bindgen::from_value(vc.into())?;
        Ok(issue_vc(&self.0, &credential, &mut context_loader.0)
            .await?
            .serialize(&OBJECT_SERIALIZER)?
            .into())
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
        let presentation = serde_wasm_bindgen::from_value(vp.into())?;
        Ok(present_vp(
            &self.0,
            &presentation,
            domain,
            challenge,
            &mut context_loader.0,
        )
        .await?
        .serialize(&OBJECT_SERIALIZER)?
        .into())
    }

    #[wasm_bindgen(js_name = "embedC2PAManifest")]
    pub fn embed_c2pa_manifest(
        &self,
        certificate: Uint8Array,
        source: Uint8Array,
        format: &str,
        manifest_definition: Object,
    ) -> Result<C2PASignatureResult, JsError> {
        let manifest_definition: ManifestDefinition =
            serde_wasm_bindgen::from_value(manifest_definition.into())?;

        let mut source = Cursor::new(source.to_vec());
        let mut dest = source.clone();

        let signer = Ed25519Signer::new(self.0.raw_signing_key().clone(), certificate.to_vec());

        let manifest = teddybear_c2pa::embed_manifest(
            &mut source,
            &mut dest,
            format,
            manifest_definition,
            &signer,
        )?;

        Ok(C2PASignatureResult(dest.into_inner(), manifest))
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
        key: PublicEd25519(key),
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

/// Encrypt the provided payload for the provided recipient array using A256GCM algorithm.
///
/// The provided recipients array must contain only wrapped X25519 JWK values.
///
/// You may acquire X25519 JWK values using the `toX25519PublicJWK` method on the keypair structs.
#[wasm_bindgen(js_name = "encryptAES")]
pub fn encrypt_aes(payload: Uint8Array, recipients: Vec<JWK>) -> Result<Jwe, JsError> {
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
pub fn encrypt_chacha20(payload: Uint8Array, recipients: Vec<JWK>) -> Result<Jwe, JsError> {
    let jwe = teddybear_jwe::encrypt::<XC20P>(
        &payload.to_vec(),
        &recipients.iter().map(|val| &val.0).collect::<Vec<_>>(),
    )?;

    Ok(jwe.serialize(&OBJECT_SERIALIZER)?.into())
}

/// JWS verification result.
#[wasm_bindgen(js_name = "JWSVerificationResult")]
pub struct JwsVerificationResult(Option<InnerJWK>, Uint8Array);

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
