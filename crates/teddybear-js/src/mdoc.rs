use js_sys::{Array, JsString, Object, Uint8Array};
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

#[wasm_bindgen(js_name = "presentMDoc")]
pub fn present(
    device_key: &PrivateSecp256r1,
    verifier_key: &PublicSecp256r1,
    documents: Object,
    requests: Object,
    permits: Object,
) -> Result<Uint8Array, JsError> {
    let documents = Object::entries(&documents).into_iter().map(|val| {
        let array: Array = val.into();

        let name = JsString::from(array.get(0)).into();
        let value = Uint8Array::from(array.get(1)).to_vec();

        (name, value)
    });

    let requests = Object::entries(&requests)
        .into_iter()
        .map(|val| {
            let array: Array = val.into();

            let name = JsString::from(array.get(0)).into();
            let value = serde_wasm_bindgen::from_value(array.get(1))?;

            Ok((name, value))
        })
        .collect::<Result<Vec<_>, JsError>>()?;

    let permits = serde_wasm_bindgen::from_value(permits.into())?;

    let presented =
        teddybear_mdoc::present(&device_key.0, &verifier_key.0, documents, requests, permits)?
            .as_slice()
            .into();

    Ok(presented)
}
