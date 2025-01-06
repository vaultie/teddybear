use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "JWERecipient")]
    pub type JweRecipient;

    #[wasm_bindgen(typescript_type = "JWE")]
    pub type Jwe;
}
