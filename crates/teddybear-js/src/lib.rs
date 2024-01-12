extern crate alloc;

use js_sys::Object;
use serde::Serialize;
use serde_wasm_bindgen::Serializer;
use teddybear_crypto::{Ed25519, JWK};
use wasm_bindgen::prelude::*;

const OBJECT_SERIALIZER: Serializer = Serializer::new().serialize_maps_as_objects(true);

#[wasm_bindgen]
pub struct WrappedEd25519(Ed25519);

#[wasm_bindgen]
impl WrappedEd25519 {
    pub async fn generate() -> WrappedEd25519 {
        WrappedEd25519(Ed25519::generate().await.unwrap())
    }

    pub async fn from_did(did: &str) -> WrappedEd25519 {
        WrappedEd25519(Ed25519::from_did(did).await.unwrap())
    }

    pub fn to_ed25519_public_jwk(&self) -> WrappedJWK {
        WrappedJWK(self.0.to_ed25519_public_jwk())
    }

    pub fn to_x25519_public_jwk(&self) -> WrappedJWK {
        WrappedJWK(self.0.to_x25519_public_jwk())
    }

    pub fn ed25519_did(&self) -> String {
        self.0.ed25519_did().to_string()
    }

    pub fn x25519_did(&self) -> String {
        self.0.x25519_did().to_string()
    }
}

#[wasm_bindgen]
pub struct WrappedJWK(JWK);

#[wasm_bindgen]
impl WrappedJWK {
    pub fn as_object(&self) -> Object {
        self.0.serialize(&OBJECT_SERIALIZER).unwrap().into()
    }
}
