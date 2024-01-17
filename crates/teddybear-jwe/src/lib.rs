use askar_crypto::{
    alg::{
        aes::{A256Gcm, A256Kw, AesKey},
        x25519::X25519KeyPair,
        KeyAlg,
    },
    encrypt::{KeyAeadInPlace, KeyAeadMeta},
    jwk::{FromJwk, ToJwk},
    kdf::{ecdh_es::EcdhEs, FromKeyDerivation},
    repr::{KeyGen, ToPublicBytes, ToSecretBytes},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Serialize;
use ssi_jwk::{Base64urlUInt, JWK};

const A256GCM_SHARED_PROTECTED_HEADER_BASE64: &str = "eyJlbmMiOiJBMjU2R0NNIn0";

#[derive(Serialize, Debug)]
pub struct Recipient {
    pub header: Header,
    pub encrypted_key: Base64urlUInt,
}

#[derive(Serialize, Debug)]
pub struct Header {
    #[serde(rename = "kid")]
    pub key_id: String,

    #[serde(rename = "alg")]
    pub algorithm: String,

    #[serde(rename = "epk")]
    pub ephemeral_key_pair: JWK,

    #[serde(rename = "apu")]
    pub producer_info: Base64urlUInt,

    #[serde(rename = "apv")]
    pub consumer_info: Base64urlUInt,
}

#[derive(Serialize, Debug)]
pub struct SharedProtectedHeader {
    enc: String,
}

#[derive(Serialize, Debug)]
pub struct GeneralJWE {
    protected: &'static str,
    recipients: Vec<Recipient>,
    iv: String,
    ciphertext: String,
    tag: String,
}

pub fn encrypt(payload: &mut Vec<u8>, recipients: &[&JWK]) -> GeneralJWE {
    let cek = AesKey::<A256Gcm>::random().unwrap();
    let ephemeral_key_pair = X25519KeyPair::random().unwrap();

    let recipients = recipients
        .iter()
        .map(|recipient| {
            let static_peer =
                X25519KeyPair::from_jwk(&serde_json::to_string(recipient).unwrap()).unwrap();

            let (kek, producer_info, consumer_info) =
                kek_from_static_peer(&ephemeral_key_pair, &static_peer);

            let mut cek_buffer = cek.to_secret_bytes().unwrap();
            kek.encrypt_in_place(&mut cek_buffer, &[], &[]).unwrap();

            Recipient {
                header: Header {
                    key_id: recipient.key_id.clone().unwrap(),
                    algorithm: "ECDH-ES+A256KW".to_string(),
                    ephemeral_key_pair: serde_json::from_str(
                        &ephemeral_key_pair
                            .to_jwk_public(Some(KeyAlg::X25519))
                            .unwrap(),
                    )
                    .unwrap(),
                    producer_info: Base64urlUInt(producer_info),
                    consumer_info: Base64urlUInt(consumer_info),
                },
                encrypted_key: Base64urlUInt(cek_buffer.to_vec()),
            }
        })
        .collect::<Vec<_>>();

    let (iv, ciphertext, tag) = compose_encrypted_value(
        &cek,
        payload,
        A256GCM_SHARED_PROTECTED_HEADER_BASE64.as_bytes(),
    );

    GeneralJWE {
        protected: A256GCM_SHARED_PROTECTED_HEADER_BASE64,
        recipients,
        iv: URL_SAFE_NO_PAD.encode(iv),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        tag: URL_SAFE_NO_PAD.encode(tag),
    }
}

pub fn compose_encrypted_value<'a>(
    cek: &AesKey<A256Gcm>,
    payload: &'a mut Vec<u8>,
    aad: &[u8],
) -> ([u8; 12], &'a [u8], &'a [u8]) {
    let iv = AesKey::<A256Gcm>::random_nonce();
    let ciphertext_len = cek.encrypt_in_place(payload, &iv, aad).unwrap();
    let (ciphertext, tag) = payload.split_at(ciphertext_len);
    (iv.into(), ciphertext, tag)
}

fn kek_from_static_peer(
    ephemeral_key_pair: &X25519KeyPair,
    static_peer: &X25519KeyPair,
) -> (AesKey<A256Kw>, Vec<u8>, Vec<u8>) {
    let producer_info = ephemeral_key_pair.to_public_bytes().unwrap();
    let consumer_info = b"todo";

    let key_info = EcdhEs::new(
        ephemeral_key_pair,
        static_peer,
        b"ECDH-ES+A256KW",
        &producer_info,
        consumer_info,
        false,
    );

    let kek = AesKey::<A256Kw>::from_key_derivation(key_info).unwrap();

    (kek, producer_info.to_vec(), consumer_info.to_vec())
}
