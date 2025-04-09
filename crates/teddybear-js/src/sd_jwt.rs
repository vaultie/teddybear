use js_sys::Object;
use serde::Serialize;
use wasm_bindgen::prelude::*;

use crate::{OBJECT_SERIALIZER, jwk::JWK};

#[wasm_bindgen(js_name = "SDJWT")]
pub struct SdJwt(teddybear_sd_jwt::SdJwt);

#[wasm_bindgen(js_class = "SDJWT")]
impl SdJwt {
    #[wasm_bindgen(constructor)]
    pub fn new(jwt: &str) -> Result<Self, JsError> {
        Ok(Self(teddybear_sd_jwt::SdJwt::new(jwt)?))
    }

    #[wasm_bindgen(js_name = "parseUntrusted")]
    pub fn parse_untrusted(&self) -> Result<Object, JsError> {
        Ok(self
            .0
            .parse_untrusted()?
            .serialize(&OBJECT_SERIALIZER)?
            .into())
    }

    pub async fn verify(&self, jwk: &JWK) -> Result<(), JsError> {
        self.0.verify(&jwk.0).await.map_err(Into::into)
    }

    pub fn disclose(&self, pointers: Vec<String>) -> Result<SdJwt, JsError> {
        Ok(Self(self.0.disclose(pointers.iter().map(|v| &**v))?))
    }

    #[wasm_bindgen(js_name = "toString")]
    pub fn to_string(&self) -> String {
        self.0.as_ref().to_owned()
    }
}
