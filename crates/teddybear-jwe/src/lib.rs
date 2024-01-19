use std::borrow::Cow;

use askar_crypto::{
    alg::{
        aes::{A256Gcm, A256Kw, AesKey},
        x25519::X25519KeyPair,
        KeyAlg,
    },
    encrypt::{KeyAeadInPlace, KeyAeadMeta},
    jwk::{FromJwk, ToJwk},
    kdf::{ecdh_es::EcdhEs, FromKeyDerivation},
    repr::{KeyGen, KeyPublicBytes, KeySecretBytes, ToPublicBytes, ToSecretBytes},
    Error, ErrorKind,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use ssi_jwk::{Base64urlUInt, JWK};

const A256GCM_SHARED_PROTECTED_HEADER_BASE64: &str = "eyJlbmMiOiJBMjU2R0NNIn0";

#[derive(Serialize, Deserialize, Debug)]
pub struct Recipient {
    pub header: Header,
    pub encrypted_key: Base64urlUInt,
}

#[derive(Serialize, Deserialize, Debug)]
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

#[derive(Serialize, Deserialize, Debug)]
pub struct GeneralJWE<'a> {
    protected: Cow<'a, str>,
    recipients: Vec<Recipient>,
    iv: String,
    ciphertext: String,
    tag: String,
}

pub fn encrypt(payload: &[u8], recipients: &[&JWK]) -> Result<GeneralJWE<'static>, Error> {
    let cek = AesKey::<A256Gcm>::random()?;

    let ephemeral_key_pair = X25519KeyPair::random()?;

    let recipients = recipients
        .iter()
        .map(|recipient| {
            // FIXME: Remove unnecessary JWK conversion.
            let static_peer = X25519KeyPair::from_jwk(
                &serde_json::to_string(recipient).expect("JWK serialization should always succeed"),
            )?;

            let (kek, producer_info, consumer_info) =
                create_kek(&ephemeral_key_pair, &static_peer, false)?;

            let mut cek_buffer = cek.to_secret_bytes()?;

            kek.encrypt_in_place(&mut cek_buffer, &[], &[])?;

            Ok(Recipient {
                header: Header {
                    key_id: recipient
                        .key_id
                        .clone()
                        .expect("recipient JWK values should always contain a key id"),
                    algorithm: "ECDH-ES+A256KW".to_string(),
                    ephemeral_key_pair: serde_json::from_str(
                        &ephemeral_key_pair.to_jwk_public(Some(KeyAlg::X25519))?,
                    )
                    .expect("JWK serialization should always succeed"),
                    producer_info: Base64urlUInt(producer_info),
                    consumer_info: Base64urlUInt(consumer_info),
                },
                encrypted_key: Base64urlUInt(cek_buffer.to_vec()),
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;

    let mut payload_buf = payload.to_vec();

    let (iv, ciphertext, tag) = encrypt_with_cek(
        &cek,
        &mut payload_buf,
        A256GCM_SHARED_PROTECTED_HEADER_BASE64.as_bytes(),
    )?;

    Ok(GeneralJWE {
        protected: Cow::Borrowed(A256GCM_SHARED_PROTECTED_HEADER_BASE64),
        recipients,
        iv: URL_SAFE_NO_PAD.encode(iv),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        tag: URL_SAFE_NO_PAD.encode(tag),
    })
}

pub fn decrypt(jwe: &GeneralJWE<'_>, recipient: &JWK) -> Result<Vec<u8>, Error> {
    if jwe.protected != A256GCM_SHARED_PROTECTED_HEADER_BASE64 {
        return Err(Error::from_msg(
            ErrorKind::Encryption,
            "Invalid shared protected header value.",
        ));
    }

    // FIXME: Remove unnecessary JWK conversion.
    let recipient = X25519KeyPair::from_jwk(
        &serde_json::to_string(recipient).expect("JWK serialization should always succeed"),
    )?;

    let matching_recipient = jwe
        .recipients
        .iter()
        .find(|key| {
            key.header.algorithm == "ECDH-ES+A256KW"
                && recipient.with_public_bytes(|val| val == key.header.consumer_info.0)
        })
        .ok_or_else(|| Error::from_msg(ErrorKind::Encryption, "Recipient not found."))?;

    let ephemeral_key_pair = X25519KeyPair::from_jwk(
        &serde_json::to_string(&matching_recipient.header.ephemeral_key_pair)
            .expect("JWK serialization should always succeed"),
    )?;

    let (kek, _, _) = create_kek(&ephemeral_key_pair, &recipient, true)?;

    let mut cek_buffer = matching_recipient.encrypted_key.0.clone();
    kek.decrypt_in_place(&mut cek_buffer, &[], &[])?;

    let cek = AesKey::<A256Gcm>::from_secret_bytes(&cek_buffer)?;

    let mut ciphertext_buf = URL_SAFE_NO_PAD
        .decode(&jwe.ciphertext)
        .map_err(|_| Error::from_msg(ErrorKind::Invalid, "Unable to deserialize ciphertext."))?;

    decrypt_with_cek(
        &cek,
        &mut ciphertext_buf,
        &URL_SAFE_NO_PAD
            .decode(&jwe.iv)
            .map_err(|_| Error::from_msg(ErrorKind::Invalid, "Unable to deserialize IV."))?,
        &URL_SAFE_NO_PAD
            .decode(&jwe.tag)
            .map_err(|_| Error::from_msg(ErrorKind::Invalid, "Unable to deserialize tag."))?,
        A256GCM_SHARED_PROTECTED_HEADER_BASE64.as_bytes(),
    )?;

    Ok(ciphertext_buf)
}

#[allow(clippy::type_complexity)]
pub fn encrypt_with_cek<'a>(
    cek: &AesKey<A256Gcm>,
    payload: &'a mut Vec<u8>,
    aad: &[u8],
) -> Result<([u8; 12], &'a [u8], &'a [u8]), Error> {
    let iv = AesKey::<A256Gcm>::random_nonce();
    let ciphertext_len = cek.encrypt_in_place(payload, &iv, aad)?;
    let (ciphertext, tag) = payload.split_at(ciphertext_len);

    Ok((iv.into(), ciphertext, tag))
}

pub fn decrypt_with_cek(
    cek: &AesKey<A256Gcm>,
    ciphertext: &mut Vec<u8>,
    iv: &[u8],
    tag: &[u8],
    aad: &[u8],
) -> Result<(), Error> {
    ciphertext.extend_from_slice(tag);
    cek.decrypt_in_place(ciphertext, iv, aad)?;

    Ok(())
}

#[allow(clippy::type_complexity)]
fn create_kek(
    ephemeral_key_pair: &X25519KeyPair,
    recipient: &X25519KeyPair,
    receive: bool,
) -> Result<(AesKey<A256Kw>, Vec<u8>, Vec<u8>), Error> {
    let producer_info = ephemeral_key_pair.to_public_bytes()?;
    let consumer_info = recipient.to_public_bytes()?;

    let key_info = EcdhEs::new(
        ephemeral_key_pair,
        recipient,
        b"ECDH-ES+A256KW",
        &producer_info,
        &consumer_info,
        receive,
    );

    let kek = AesKey::<A256Kw>::from_key_derivation(key_info)?;

    Ok((kek, producer_info.to_vec(), consumer_info.to_vec()))
}

#[cfg(test)]
mod tests {
    use teddybear_crypto::Ed25519;

    use crate::{decrypt, encrypt};

    #[tokio::test]
    async fn single_recipient() {
        let value = b"Hello, world";
        let key = Ed25519::generate().await.unwrap();
        let jwe = encrypt(value, &[&key.to_x25519_public_jwk()]).unwrap();
        let decrypted = decrypt(&jwe, key.as_x25519_private_jwk()).unwrap();
        assert_eq!(decrypted, value);
    }

    #[tokio::test]
    async fn multiple_recipients() {
        let value = b"Hello, world";

        let key = Ed25519::generate().await.unwrap();
        let key2 = Ed25519::generate().await.unwrap();
        let key3 = Ed25519::generate().await.unwrap();

        let jwe = encrypt(
            value,
            &[
                &key.to_x25519_public_jwk(),
                &key2.to_x25519_public_jwk(),
                &key3.to_x25519_public_jwk(),
            ],
        )
        .unwrap();

        let decrypted = decrypt(&jwe, key2.as_x25519_private_jwk()).unwrap();

        assert_eq!(decrypted, value);
    }

    #[tokio::test]
    async fn unknown_key() {
        let value = b"Hello, world";
        let key = Ed25519::generate().await.unwrap();
        let jwe = encrypt(value, &[&key.to_x25519_public_jwk()]).unwrap();
        assert!(decrypt(
            &jwe,
            Ed25519::generate().await.unwrap().as_x25519_private_jwk()
        )
        .is_err());
    }

    #[tokio::test]
    async fn large_payload() {
        let value = vec![0; 4096];
        let key = Ed25519::generate().await.unwrap();
        let jwe = encrypt(&value, &[&key.to_x25519_public_jwk()]).unwrap();
        let decrypted = decrypt(&jwe, key.as_x25519_private_jwk()).unwrap();
        assert_eq!(decrypted, value);
    }
}
