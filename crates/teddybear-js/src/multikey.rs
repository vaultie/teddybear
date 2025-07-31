use std::str::FromStr;

use js_sys::Object;
use serde::Serialize;
use teddybear_crypto::{DIDBuf, DIDURLBuf};
use teddybear_vc::ssi_verification_methods::Multikey;
use wasm_bindgen::{JsError, prelude::wasm_bindgen};
use wasm_bindgen_derive::TryFromJsValue;

use crate::{
    OBJECT_SERIALIZER,
    document::{DID, DIDURL},
};

/// Public Multikey key.
///
/// @category Keys
#[derive(TryFromJsValue)]
#[wasm_bindgen]
#[derive(Clone)]
pub struct PublicMultikey(pub(crate) Multikey);

#[wasm_bindgen]
impl PublicMultikey {
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

    /// Serialize the current public key as a verification method object.
    #[wasm_bindgen(js_name = "toJSON")]
    pub fn to_json(&self) -> Result<Object, JsError> {
        Ok(self.0.serialize(&OBJECT_SERIALIZER)?.into())
    }
}
