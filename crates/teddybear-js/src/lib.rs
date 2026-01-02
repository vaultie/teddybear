#![allow(
    // This crate is not meant to be used in Rust at all,
    // so some Rust-specific lints are disabled.
    clippy::inherent_to_string,
    clippy::new_without_default,
    clippy::upper_case_acronyms,
)]

extern crate alloc;

use std::str::FromStr;

use futures_util::{StreamExt, stream::FuturesUnordered};
use js_sys::Uint8Array;
use serde::{Deserialize, Serialize};
use teddybear_w3c::{
    data::RecognizedW3CCredential,
    status_lists::{BitstringStatusListCredential, StatusListFetcher},
};
use tsify::Tsify;
use wasm_bindgen::prelude::*;

#[derive(thiserror::Error, Debug)]
pub enum VerificationError {
    #[error("unknown format: {0}")]
    UnknownFormat(String),

    #[error("invalid credential: {0}")]
    InvalidCredential(#[from] serde_wasm_bindgen::Error),

    #[error("credential recognition error: {0}")]
    RecognitionError(#[from] teddybear_w3c::Error),

    #[error("C2PA failure: {0}")]
    C2PA(#[from] teddybear_c2pa::Error),
}

impl From<VerificationError> for wasm_bindgen::JsValue {
    #[inline]
    fn from(value: VerificationError) -> Self {
        value.to_string().into()
    }
}

#[derive(Deserialize, Tsify)]
#[tsify(from_wasm_abi)]
pub struct TrustAnchors {
    #[serde(default)]
    c2pa: Vec<String>,

    #[serde(default)]
    w3c: Vec<String>,
}

#[derive(Deserialize, Tsify)]
#[serde(rename_all = "camelCase")]
#[tsify(from_wasm_abi)]
pub struct VerificationConfiguration {
    trust_anchors: TrustAnchors,

    #[serde(with = "serde_wasm_bindgen::preserve")]
    #[serde(default = "JsValue::null")]
    status_list_fetcher: JsValue,
}

#[derive(Serialize, Tsify)]
#[serde(tag = "status", rename_all = "camelCase")]
#[tsify(into_wasm_abi)]
pub enum CredentialVerificationOutcome {
    Success {
        credential: teddybear_w3c::data::RecognizedW3CCredential,
    },

    Failure {
        error: String,
    },
}

#[derive(Serialize, Tsify)]
#[tsify(into_wasm_abi)]
pub struct C2PAVerificationOutcome {
    c2pa: teddybear_c2pa::VerificationOutcome,
    w3c: Vec<CredentialVerificationOutcome>,
}

#[wasm_bindgen(js_name = "verifyC2PA")]
pub async fn verify_c2pa(
    format: &str,
    asset: Uint8Array,
    configuration: VerificationConfiguration,
) -> Result<C2PAVerificationOutcome, VerificationError> {
    console_error_panic_hook::set_once();

    let format = teddybear_c2pa::SupportedFormat::from_str(format)
        .map_err(|_| VerificationError::UnknownFormat(format.to_owned()))?;

    let asset = asset.to_vec();

    let c2pa_outcome = teddybear_c2pa::verify(format, &asset, &configuration.trust_anchors.c2pa)?;

    let fetcher = if configuration.status_list_fetcher.is_function() {
        Some(JSStatusListFetcher(
            configuration.status_list_fetcher.into(),
        ))
    } else {
        None
    };

    let credentials = c2pa_outcome
        .manifests
        .iter()
        .flat_map(|manifest| manifest.credentials.iter())
        .filter_map(|value| serde_json::from_value(value.clone()).ok())
        .map(async |credential| {
            let outcome = teddybear_w3c::verify_credential(
                &credential,
                &configuration.trust_anchors.w3c,
                fetcher.as_ref(),
            )
            .await;

            match outcome {
                Ok(credential) => CredentialVerificationOutcome::Success { credential },
                Err(err) => CredentialVerificationOutcome::Failure {
                    error: err.to_string(),
                },
            }
        });

    let resolved_credentials = FuturesUnordered::from_iter(credentials).collect().await;

    Ok(C2PAVerificationOutcome {
        c2pa: c2pa_outcome,
        w3c: resolved_credentials,
    })
}

#[wasm_bindgen(js_name = "verifyW3C")]
pub async fn verify_w3c(
    asset: JsValue,
    configuration: VerificationConfiguration,
) -> Result<RecognizedW3CCredential, VerificationError> {
    console_error_panic_hook::set_once();

    let fetcher = if configuration.status_list_fetcher.is_function() {
        Some(JSStatusListFetcher(
            configuration.status_list_fetcher.into(),
        ))
    } else {
        None
    };

    let credential =
        serde_wasm_bindgen::from_value(asset).map_err(VerificationError::InvalidCredential)?;

    let credential = teddybear_w3c::verify_credential(
        &credential,
        &configuration.trust_anchors.w3c,
        fetcher.as_ref(),
    )
    .await?;

    Ok(credential)
}

#[derive(thiserror::Error, Debug)]
enum JSStatusListFetcherError {
    #[error(
        "status list fetcher returned unexpected value: {}",
        .0.as_string().as_deref().unwrap_or("unknown")
    )]
    FunctionCall(JsValue),

    #[error("invalid status list object value: {0}")]
    Value(serde_wasm_bindgen::Error),
}

struct JSStatusListFetcher(js_sys::Function);

impl StatusListFetcher for JSStatusListFetcher {
    type Error = JSStatusListFetcherError;

    async fn fetch(&self, url: &str) -> Result<BitstringStatusListCredential, Self::Error> {
        let this = JsValue::null();

        let res = self
            .0
            .call1(&this, &JsValue::from_str(url))
            .map_err(JSStatusListFetcherError::FunctionCall)?;

        serde_wasm_bindgen::from_value(res).map_err(JSStatusListFetcherError::Value)
    }
}
