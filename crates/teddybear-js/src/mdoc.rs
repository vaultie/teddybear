use js_sys::{Array, JsString, Object, Uint8Array};
use serde::Serialize;
use wasm_bindgen::prelude::*;
use wasm_bindgen_derive::{TryFromJsValue, try_from_js_array};

use crate::{
    OBJECT_SERIALIZER,
    p256::{PrivateSecp256r1, PublicSecp256r1},
};

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "DeviceInternalMDoc[]")]
    pub type DeviceInternalMDocArray;
}

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

#[wasm_bindgen]
pub struct MDocValidityInfo(#[allow(dead_code)] teddybear_mdoc::ValidityInfo);

#[wasm_bindgen]
impl MDocValidityInfo {
    #[cfg(target_family = "wasm")]
    pub fn signed(&self) -> js_sys::Date {
        self.0.signed.into()
    }

    #[cfg(target_family = "wasm")]
    #[wasm_bindgen(js_name = "validFrom")]
    pub fn valid_from(&self) -> js_sys::Date {
        self.0.valid_from.into()
    }

    #[cfg(target_family = "wasm")]
    #[wasm_bindgen(js_name = "validUntil")]
    pub fn valid_until(&self) -> js_sys::Date {
        self.0.valid_until.into()
    }

    #[cfg(target_family = "wasm")]
    #[wasm_bindgen(js_name = "expectedUpdate")]
    pub fn expected_update(&self) -> Option<js_sys::Date> {
        self.0.expected_update.map(Into::into)
    }
}

#[wasm_bindgen]
pub struct MDocStatusList(teddybear_mdoc::MsoStatusList);

#[wasm_bindgen]
impl MDocStatusList {
    pub fn uri(&self) -> String {
        self.0.uri.as_str().to_owned()
    }

    pub fn idx(&self) -> u32 {
        self.0.idx
    }
}

#[derive(TryFromJsValue)]
#[wasm_bindgen]
#[derive(Clone)]
pub struct DeviceInternalMDoc(teddybear_mdoc::DeviceInternalMDoc);

#[wasm_bindgen]
impl DeviceInternalMDoc {
    #[wasm_bindgen(constructor)]
    pub fn new(value: Uint8Array) -> Result<DeviceInternalMDoc, JsError> {
        Ok(Self(teddybear_mdoc::DeviceInternalMDoc::from_bytes(
            &value.to_vec(),
        )?))
    }

    #[wasm_bindgen(js_name = "fromIssuedBytes")]
    pub fn from_issued_bytes(value: Uint8Array) -> Result<DeviceInternalMDoc, JsError> {
        Ok(Self(teddybear_mdoc::DeviceInternalMDoc::from_issued_bytes(
            &value.to_vec(),
        )?))
    }

    #[wasm_bindgen(js_name = "docType")]
    pub fn doc_type(&self) -> String {
        self.0.doc_type().into()
    }

    pub fn namespaces(&self) -> Result<Object, JsError> {
        Ok(self.0.namespaces().serialize(&OBJECT_SERIALIZER)?.into())
    }

    #[wasm_bindgen(js_name = "validityInfo")]
    pub fn validity_info(&self) -> MDocValidityInfo {
        MDocValidityInfo(self.0.validity_info().clone())
    }

    pub fn status(&self) -> Option<MDocStatusList> {
        self.0.status().cloned().map(MDocStatusList)
    }

    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Result<Uint8Array, JsError> {
        Ok(self.0.to_bytes()?.as_slice().into())
    }
}

#[wasm_bindgen]
pub struct PresentedDocument(teddybear_mdoc::PresentedDocument);

#[wasm_bindgen]
impl PresentedDocument {
    #[wasm_bindgen(js_name = "docType")]
    pub fn doc_type(&self) -> String {
        self.0.doc_type().to_string()
    }

    pub fn namespaces(&self) -> Result<Object, JsError> {
        Ok(self.0.namespaces().serialize(&OBJECT_SERIALIZER)?.into())
    }
}

#[wasm_bindgen]
pub struct PresentedMDoc(teddybear_mdoc::PresentedMDoc);

#[wasm_bindgen]
impl PresentedMDoc {
    #[wasm_bindgen(constructor)]
    pub fn new(value: Uint8Array) -> Result<PresentedMDoc, JsError> {
        Ok(Self(teddybear_mdoc::PresentedMDoc::from_bytes(
            &value.to_vec(),
        )?))
    }

    pub fn documents(self) -> Vec<PresentedDocument> {
        self.0
            .into_documents()
            .into_iter()
            .map(PresentedDocument)
            .collect()
    }
}

#[wasm_bindgen]
pub struct PendingMDocPresentation(teddybear_mdoc::PendingPresentation);

#[wasm_bindgen]
impl PendingMDocPresentation {
    #[wasm_bindgen(constructor)]
    pub fn new(
        verifier_key: &PublicSecp256r1,
        documents: &DeviceInternalMDocArray,
    ) -> Result<PendingMDocPresentation, JsError> {
        let documents = try_from_js_array::<DeviceInternalMDoc>(documents).unwrap();

        let initialized = teddybear_mdoc::PendingPresentation::start(
            &verifier_key.0,
            Default::default(),
            documents.into_iter().map(|d| d.0),
        )?;

        Ok(Self(initialized))
    }

    pub fn consent(
        self,
        device_key: &PrivateSecp256r1,
        requests: Object,
        permits: Object,
    ) -> Result<Uint8Array, JsError> {
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

        Ok(self
            .0
            .consent(&device_key.0, requests, permits)?
            .as_slice()
            .into())
    }
}
