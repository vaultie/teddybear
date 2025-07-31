use std::str::FromStr;

use js_sys::{Object, Uint8Array};
use serde::Serialize;
use teddybear_crypto::{DIDBuf, DIDURLBuf, ECParams, JwkVerificationMethod, Params, SignOptions};
use teddybear_jwe::{A256Gcm, P256KeyPair, XC20P};
use teddybear_vc::{
    IssueOptions, PresentOptions, issue_vc, present_vp,
    ssi_claims::data_integrity::suites::EcdsaRdfc2019,
    ssi_crypto::algorithm::ES256,
    ssi_vc::v2::{SpecializedJsonCredential, syntax::JsonPresentation},
    ssi_verification_methods::EcdsaSecp256r1VerificationKey2019,
};
use wasm_bindgen::prelude::*;
use wasm_bindgen_derive::{TryFromJsValue, try_from_js_array};

use crate::{
    OBJECT_SERIALIZER,
    document::{DID, DIDURL},
    jwe::{Jwe, JweRecipient},
    jwk::JWK,
    jws::JwsOptions,
    multikey::PublicMultikey,
    w3c::{ContextLoader, W3CIssueOptions, W3CPresentOptions},
};

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "PublicSecp256r1[]")]
    pub type PublicSecp256r1Array;
}

/// Private Secp256r1 key.
///
/// @category Keys
#[wasm_bindgen]
pub struct PrivateSecp256r1(pub(crate) teddybear_crypto::PrivateSecp256r1);

#[wasm_bindgen]
impl PrivateSecp256r1 {
    /// Create a new random keypair.
    pub fn generate() -> PrivateSecp256r1 {
        PrivateSecp256r1(teddybear_crypto::PrivateSecp256r1::generate())
    }

    /// Convert private key bytes into a public/private Secp256r1 keypair.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(value: Uint8Array) -> Result<PrivateSecp256r1, JsError> {
        let mut dst = [0; 32];
        value.copy_to(&mut dst);
        Ok(PrivateSecp256r1(
            teddybear_crypto::PrivateSecp256r1::from_bytes(&dst)?,
        ))
    }

    /// Convert private key PKCS#8 PEM value into a public/private Secp256r1 keypair.
    #[wasm_bindgen(js_name = "fromPKCS8PEM")]
    pub fn from_pkcs8_pem(value: &str) -> Result<PrivateSecp256r1, JsError> {
        Ok(PrivateSecp256r1(
            teddybear_crypto::PrivateSecp256r1::from_pkcs8_pem(value)?,
        ))
    }

    /// Get Secp256r1 private key bytes.
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Uint8Array {
        self.0.inner().to_bytes().as_slice().into()
    }

    /// Get the JWK value (without the private key) of the Secp256r1 key.
    #[wasm_bindgen(js_name = "toPublicJWK")]
    pub fn to_public_jwk(&self) -> JWK {
        JWK(self.0.to_public_jwk())
    }

    /// Get the JWK value (with the private key) of the Secp256r1 key.
    #[wasm_bindgen(js_name = "toPrivateJWK")]
    pub fn to_private_jwk(&self) -> JWK {
        JWK(self.0.to_private_jwk())
    }

    /// Get the did:key document DID value of the Secp256r1 key.
    #[wasm_bindgen(js_name = "toDIDKey")]
    pub fn to_did_key(&self) -> DID {
        DID(self.0.to_did_key())
    }

    /// Get the did:key DID URL fragment value of the Secp256r1 key.
    #[wasm_bindgen(js_name = "toDIDKeyURLFragment")]
    pub fn to_did_key_url_fragment(&self) -> String {
        self.0.to_did_key_url_fragment().to_string()
    }

    /// Derive a Secp256r1 public key from the private key.
    #[wasm_bindgen(js_name = "toPublicKey")]
    pub fn to_public_key(&self, id: &DIDURL, controller: &DID) -> Result<PublicSecp256r1, JsError> {
        let verification_method = self
            .0
            .to_verification_method(id.0.as_iri().to_owned(), controller.0.as_uri().to_owned());

        Ok(PublicSecp256r1(verification_method))
    }

    /// Derive a Multikey public key from the private key.
    #[wasm_bindgen(js_name = "toPublicMultikey")]
    pub fn to_public_multikey(
        &self,
        id: &DIDURL,
        controller: &DID,
    ) -> Result<PublicMultikey, JsError> {
        let verification_method = self
            .0
            .to_multikey(id.0.as_iri().to_owned(), controller.0.as_uri().to_owned());

        Ok(PublicMultikey(verification_method))
    }

    /// Sign the provided payload using the Secp256r1 key.
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
        options: Option<W3CIssueOptions>,
    ) -> Result<Object, JsError> {
        let credential: SpecializedJsonCredential = serde_wasm_bindgen::from_value(vc.into())?;

        let options: IssueOptions = options
            .map(Into::into)
            .map(serde_wasm_bindgen::from_value)
            .transpose()?
            .unwrap_or_default();

        let params = ECParams::from(self.0.inner());

        Ok(issue_vc::<ES256, EcdsaRdfc2019, _, _>(
            teddybear_crypto::JWK::from(Params::EC(params)),
            verification_method.0.as_iri().to_owned(),
            &credential,
            &mut context_loader.0,
            options.cached_documents,
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
        options: Option<W3CPresentOptions>,
    ) -> Result<Object, JsError> {
        let presentation: JsonPresentation<SpecializedJsonCredential> =
            serde_wasm_bindgen::from_value(vp.into())?;

        let options: PresentOptions = options
            .map(Into::into)
            .map(serde_wasm_bindgen::from_value)
            .transpose()?
            .unwrap_or_default();

        let params = ECParams::from(self.0.inner());

        Ok(present_vp::<ES256, EcdsaRdfc2019, _, _>(
            teddybear_crypto::JWK::from(Params::EC(params)),
            verification_method.0.as_iri().to_owned(),
            &presentation,
            domain,
            challenge,
            &mut context_loader.0,
            options.cached_documents,
        )
        .await?
        .serialize(&OBJECT_SERIALIZER)?
        .into())
    }

    /// Decrypt the provided JWE object using the X25519 key and the A256GCM algorithm.
    #[wasm_bindgen(js_name = "decryptAES")]
    pub fn decrypt_aes(
        &self,
        verification_method: &DIDURL,
        jwe: &Jwe,
    ) -> Result<Uint8Array, JsError> {
        let jwe = serde_wasm_bindgen::from_value(jwe.into())?;
        let payload = &*teddybear_jwe::decrypt::<A256Gcm, P256KeyPair>(
            &jwe,
            &verification_method.0,
            self.0.inner(),
        )?;
        Ok(payload.into())
    }

    /// Decrypt the provided JWE object using the X25519 key and the XC20P algorithm.
    #[wasm_bindgen(js_name = "decryptChaCha20")]
    pub fn decrypt_chacha20(
        &self,
        verification_method: &DIDURL,
        jwe: &Jwe,
    ) -> Result<Uint8Array, JsError> {
        let jwe = serde_wasm_bindgen::from_value(jwe.into())?;
        let payload = &*teddybear_jwe::decrypt::<XC20P, P256KeyPair>(
            &jwe,
            &verification_method.0,
            self.0.inner(),
        )?;
        Ok(payload.into())
    }

    #[wasm_bindgen(js_name = "addAESRecipient")]
    pub fn add_aes_recipient(
        &self,
        verification_method: &DIDURL,
        jwe: &Jwe,
        recipient: &PublicSecp256r1,
    ) -> Result<JweRecipient, JsError> {
        let jwe = serde_wasm_bindgen::from_value(jwe.into())?;
        let recipient = teddybear_jwe::add_recipient::<A256Gcm, P256KeyPair>(
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
        jwe: &Jwe,
        recipient: &PublicSecp256r1,
    ) -> Result<JweRecipient, JsError> {
        let jwe = serde_wasm_bindgen::from_value(jwe.into())?;
        let recipient = teddybear_jwe::add_recipient::<XC20P, P256KeyPair>(
            &jwe,
            &verification_method.0,
            self.0.inner(),
            recipient.0.id.as_str().to_owned(),
            recipient.0.public_key.decoded(),
        )?;
        Ok(recipient.serialize(&OBJECT_SERIALIZER)?.into())
    }
}

/// Public Secp256r1 key.
///
/// @category Keys
#[derive(TryFromJsValue)]
#[wasm_bindgen]
#[derive(Clone)]
pub struct PublicSecp256r1(pub(crate) EcdsaSecp256r1VerificationKey2019);

#[wasm_bindgen]
impl PublicSecp256r1 {
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

    /// Get the JWK value (without the private key) of the Secp256r1 key within the current keypair.
    #[wasm_bindgen(js_name = "toJWK")]
    pub fn to_jwk(&self) -> JWK {
        JWK(self.0.to_jwk().into_owned())
    }

    /// Serialize the current public key as a verification method object.
    #[wasm_bindgen(js_name = "toJSON")]
    pub fn to_json(&self) -> Result<Object, JsError> {
        Ok(self.0.serialize(&OBJECT_SERIALIZER)?.into())
    }

    /// Encrypt the provided payload for the provided recipient array using A256GCM algorithm.
    #[wasm_bindgen(js_name = "encryptAES")]
    pub fn encrypt_aes(
        payload: Uint8Array,
        recipients: &PublicSecp256r1Array,
    ) -> Result<Jwe, JsError> {
        let recipients = try_from_js_array::<PublicSecp256r1>(recipients).unwrap();

        let jwe = teddybear_jwe::encrypt::<A256Gcm, P256KeyPair, _>(
            &payload.to_vec(),
            recipients
                .iter()
                .map(|val| (val.0.id.as_str().to_owned(), val.0.public_key.decoded())),
        )?;

        Ok(jwe.serialize(&OBJECT_SERIALIZER)?.into())
    }

    /// Encrypt the provided payload for the provided recipient array using XC20P algorithm.
    #[wasm_bindgen(js_name = "encryptChaCha20")]
    pub fn encrypt_chacha20(
        payload: Uint8Array,
        recipients: &PublicSecp256r1Array,
    ) -> Result<Jwe, JsError> {
        let recipients = try_from_js_array::<PublicSecp256r1>(recipients).unwrap();

        let jwe = teddybear_jwe::encrypt::<XC20P, P256KeyPair, _>(
            &payload.to_vec(),
            recipients
                .iter()
                .map(|val| (val.0.id.as_str().to_owned(), val.0.public_key.decoded())),
        )?;

        Ok(jwe.serialize(&OBJECT_SERIALIZER)?.into())
    }
}
