use js_sys::{Object, Uint8Array};
use wasm_bindgen::prelude::*;

use crate::p256::{PrivateSecp256r1, PublicSecp256r1};

#[wasm_bindgen]
pub struct MDocBuilder(teddybear_mdoc::MDocBuilder);

#[wasm_bindgen]
impl MDocBuilder {
    #[wasm_bindgen(constructor)]
    pub fn new() -> MDocBuilder {
        Self(teddybear_mdoc::MDocBuilder::default())
    }

    #[wasm_bindgen(js_name = "setValidityInfo")]
    // `time` exposes the `From<js_sys::Date>` impl only when the target_family is wasm
    #[cfg(target_family = "wasm")]
    pub fn set_validity_info(
        self,
        signed: js_sys::Date,
        valid_from: js_sys::Date,
        valid_until: js_sys::Date,
        expected_update: Option<js_sys::Date>,
    ) -> Self {
        Self(self.0.set_validity_info(
            signed.into(),
            valid_from.into(),
            valid_until.into(),
            expected_update.map(Into::into),
        ))
    }

    #[wasm_bindgen(js_name = "setDoctype")]
    pub fn set_doctype(self, doc_type: String) -> Self {
        Self(self.0.set_doctype(doc_type))
    }

    #[wasm_bindgen(js_name = "setNamespaces")]
    pub fn set_namespaces(self, namespaces: Object) -> Result<Self, JsError> {
        let namespaces = serde_wasm_bindgen::from_value(namespaces.into())?;
        Ok(Self(self.0.set_namespaces(namespaces)))
    }

    #[wasm_bindgen(js_name = "setDeviceInfo")]
    pub fn set_device_info(self, key: &PublicSecp256r1) -> Result<Self, JsError> {
        Ok(Self(self.0.set_device_info(&key.0)?))
    }

    pub fn issue(
        self,
        key: &PrivateSecp256r1,
        certificates: Vec<Uint8Array>,
    ) -> Result<Uint8Array, JsError> {
        Ok(self
            .0
            .issue(&key.0, certificates.into_iter().map(|val| val.to_vec()))?
            .as_slice()
            .into())
    }
}
