use js_sys::Object;
use serde::Serialize;
use teddybear_crypto::{DIDBuf, DIDURLBuf, ValueOrReference};
use wasm_bindgen::prelude::*;

use crate::{
    ed25519::PublicEd25519, p256::PublicSecp256r1, x25519::PublicX25519, OBJECT_SERIALIZER,
};

/// DID value.
///
/// @category DID
#[wasm_bindgen]
pub struct DID(pub(crate) DIDBuf);

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
pub struct DIDURL(pub(crate) DIDURLBuf);

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

    #[wasm_bindgen(js_name = "getSecp256r1VerificationMethod")]
    pub fn get_secp256r1_verification_method(
        &self,
        id: &DIDURL,
    ) -> Result<PublicSecp256r1, JsError> {
        Ok(PublicSecp256r1(self.0.get_verification_method(&id.0)?))
    }

    /// Serialize the current document as an object.
    #[wasm_bindgen(js_name = "toJSON")]
    pub fn to_json(&self) -> Result<Object, JsError> {
        Ok(self.0.serialize(&OBJECT_SERIALIZER)?.into())
    }
}
