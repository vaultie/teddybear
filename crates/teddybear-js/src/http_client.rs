use js_sys::Promise;
use serde::de::DeserializeOwned;
use teddybear_common::HttpClient;
use wasm_bindgen::JsValue;

#[derive(thiserror::Error, Debug)]
pub enum DelegateHttpClientError {
    #[error(
        "fetcher returned unexpected value: {}",
        .0.as_string().as_deref().unwrap_or("unknown")
    )]
    FunctionCall(JsValue),

    #[error("invalid result value: {0}")]
    Value(serde_wasm_bindgen::Error),
}

pub struct DelegateHttpClient(js_sys::Function);

impl DelegateHttpClient {
    /// Create new [`DelegateHttpClient`] from the provided JS function.
    ///
    /// The provided function must accept exactly one argument - the request URL,
    /// and return the value expected by the usage context.
    #[inline]
    pub fn new(f: js_sys::Function) -> Self {
        Self(f)
    }
}

impl<T: DeserializeOwned> HttpClient<T> for DelegateHttpClient {
    type Error = DelegateHttpClientError;

    async fn get(&self, url: &str) -> Result<T, Self::Error> {
        let this = JsValue::null();

        let promise = self
            .0
            .call1(&this, &JsValue::from_str(url))
            .map(Promise::from)
            .map_err(DelegateHttpClientError::FunctionCall)?;

        let result = wasm_bindgen_futures::JsFuture::from(promise)
            .await
            .map_err(DelegateHttpClientError::FunctionCall)?;

        serde_wasm_bindgen::from_value(result).map_err(DelegateHttpClientError::Value)
    }
}
