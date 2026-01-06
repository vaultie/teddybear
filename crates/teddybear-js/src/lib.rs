#![allow(
    // This crate is not meant to be used in Rust at all,
    // so some Rust-specific lints are disabled.
    clippy::inherent_to_string,
    clippy::new_without_default,
    clippy::upper_case_acronyms,
)]

extern crate alloc;

mod http_client;

use std::str::FromStr;

use futures_util::{StreamExt, stream::FuturesUnordered};
use js_sys::Uint8Array;
use serde::{Deserialize, Serialize};
use teddybear_w3c::data::RecognizedW3CCredential;
use tsify::Tsify;
use wasm_bindgen::prelude::*;

use crate::http_client::DelegateHttpClient;

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
    status_list_fetcher: JsValue,

    #[serde(with = "serde_wasm_bindgen::preserve")]
    remote_context_fetcher: JsValue,

    #[serde(with = "serde_wasm_bindgen::preserve")]
    did_web_client: JsValue,
}

#[derive(Serialize, Tsify)]
#[serde(tag = "status", rename_all = "camelCase")]
#[tsify(into_wasm_abi, hashmap_as_object)]
pub enum CredentialVerificationOutcome {
    Success {
        credential: teddybear_w3c::data::RecognizedW3CCredential,
    },

    Failure {
        error: String,
    },
}

#[derive(Serialize, Tsify)]
#[tsify(into_wasm_abi, hashmap_as_object)]
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

    let status_list_fetcher = DelegateHttpClient::new(configuration.status_list_fetcher.into());
    let remote_context_fetcher =
        DelegateHttpClient::new(configuration.remote_context_fetcher.into());
    let did_web_client = DelegateHttpClient::new(configuration.did_web_client.into());

    let credentials = c2pa_outcome
        .manifests
        .iter()
        .flat_map(|manifest| manifest.credentials.iter())
        .filter_map(|value| serde_json::from_value(value.clone()).ok())
        .map(async |credential| {
            let outcome = teddybear_w3c::verify_credential(
                &credential,
                &configuration.trust_anchors.w3c,
                &status_list_fetcher,
                &remote_context_fetcher,
                &did_web_client,
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

    let status_list_fetcher = DelegateHttpClient::new(configuration.status_list_fetcher.into());
    let remote_context_fetcher =
        DelegateHttpClient::new(configuration.remote_context_fetcher.into());
    let did_web_client = DelegateHttpClient::new(configuration.did_web_client.into());

    let credential =
        serde_wasm_bindgen::from_value(asset).map_err(VerificationError::InvalidCredential)?;

    let credential = teddybear_w3c::verify_credential(
        &credential,
        &configuration.trust_anchors.w3c,
        &status_list_fetcher,
        &remote_context_fetcher,
        &did_web_client,
    )
    .await?;

    Ok(credential)
}
