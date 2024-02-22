use std::borrow::Cow;

use askar_crypto::{
    alg::{
        aes::{A256Kw, AesKey},
        chacha20::Chacha20Key,
        x25519::X25519KeyPair,
        KeyAlg,
    },
    encrypt::{KeyAeadInPlace, KeyAeadMeta},
    generic_array::GenericArray,
    jwk::{FromJwk, ToJwk},
    kdf::{ecdh_es::EcdhEs, FromKeyDerivation},
    repr::{KeyGen, KeySecretBytes, ToPublicBytes, ToSecretBytes},
    Error, ErrorKind,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use ssi_jwk::{Base64urlUInt, JWK};

pub use askar_crypto::alg::{aes::A256Gcm, chacha20::XC20P};

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

pub trait SymmetricEncryptionAlgorithm {
    const SHARED_PROTECTED_HEADER_BASE64: &'static str;

    type ContentEncryptionKey: KeyAeadInPlace + KeyAeadMeta + KeySecretBytes + KeyGen;
}

impl SymmetricEncryptionAlgorithm for A256Gcm {
    const SHARED_PROTECTED_HEADER_BASE64: &'static str = "eyJlbmMiOiJBMjU2R0NNIn0";

    type ContentEncryptionKey = AesKey<A256Gcm>;
}

impl SymmetricEncryptionAlgorithm for XC20P {
    const SHARED_PROTECTED_HEADER_BASE64: &'static str = "eyJlbmMiOiJYQzIwUCJ9";

    type ContentEncryptionKey = Chacha20Key<XC20P>;
}

pub fn encrypt<T: SymmetricEncryptionAlgorithm>(
    payload: &[u8],
    recipients: &[&JWK],
) -> Result<GeneralJWE<'static>, Error> {
    let cek = <T::ContentEncryptionKey>::random()?;

    let ephemeral_key_pair = X25519KeyPair::random()?;
    let producer_info = ephemeral_key_pair.to_public_bytes()?;

    let recipients = recipients
        .iter()
        .map(|recipient| {
            let (consumer_info, askar_recipient) = extract_jwk_data(recipient)?;

            let kek = create_kek(&ephemeral_key_pair, &askar_recipient, consumer_info, false)?;

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
                    producer_info: Base64urlUInt(producer_info.to_vec()),
                    consumer_info: Base64urlUInt(consumer_info.to_vec()),
                },
                encrypted_key: Base64urlUInt(cek_buffer.to_vec()),
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;

    let mut payload_buf = payload.to_vec();

    let (iv, ciphertext, tag) = encrypt_with_cek::<T>(&cek, &mut payload_buf)?;

    Ok(GeneralJWE {
        protected: Cow::Borrowed(T::SHARED_PROTECTED_HEADER_BASE64),
        recipients,
        iv: URL_SAFE_NO_PAD.encode(iv),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        tag: URL_SAFE_NO_PAD.encode(tag),
    })
}

pub fn decrypt<T: SymmetricEncryptionAlgorithm>(
    jwe: &GeneralJWE<'_>,
    recipient: &JWK,
) -> Result<Vec<u8>, Error> {
    if jwe.protected != T::SHARED_PROTECTED_HEADER_BASE64 {
        return Err(Error::from_msg(
            ErrorKind::Encryption,
            "Invalid shared protected header value.",
        ));
    }

    let (consumer_info, askar_recipient) = extract_jwk_data(recipient)?;

    let matching_recipient = jwe
        .recipients
        .iter()
        .find(|key| {
            key.header.algorithm == "ECDH-ES+A256KW" && consumer_info == key.header.consumer_info.0
        })
        .ok_or_else(|| Error::from_msg(ErrorKind::Encryption, "Recipient not found."))?;

    let ephemeral_key_pair = X25519KeyPair::from_jwk(
        &serde_json::to_string(&matching_recipient.header.ephemeral_key_pair)
            .expect("JWK serialization should always succeed"),
    )?;

    let kek = create_kek(&ephemeral_key_pair, &askar_recipient, consumer_info, true)?;

    let mut cek_buffer = matching_recipient.encrypted_key.0.clone();
    kek.decrypt_in_place(&mut cek_buffer, &[], &[])?;

    let cek = T::ContentEncryptionKey::from_secret_bytes(&cek_buffer)?;

    let mut ciphertext_buf = URL_SAFE_NO_PAD
        .decode(&jwe.ciphertext)
        .map_err(|_| Error::from_msg(ErrorKind::Invalid, "Unable to deserialize ciphertext."))?;

    decrypt_with_cek::<T>(
        &cek,
        &mut ciphertext_buf,
        &URL_SAFE_NO_PAD
            .decode(&jwe.iv)
            .map_err(|_| Error::from_msg(ErrorKind::Invalid, "Unable to deserialize IV."))?,
        &URL_SAFE_NO_PAD
            .decode(&jwe.tag)
            .map_err(|_| Error::from_msg(ErrorKind::Invalid, "Unable to deserialize tag."))?,
    )?;

    Ok(ciphertext_buf)
}

pub fn add_recipient<T: SymmetricEncryptionAlgorithm>(
    jwe: &GeneralJWE<'_>,
    existing_recipient: &JWK,
    new_recipient: &JWK,
) -> Result<Recipient, Error> {
    if jwe.protected != T::SHARED_PROTECTED_HEADER_BASE64 {
        return Err(Error::from_msg(
            ErrorKind::Encryption,
            "Invalid shared protected header value.",
        ));
    }

    let (existing_consumer_info, existing_askar_recipient) = extract_jwk_data(existing_recipient)?;
    let (new_consumer_info, new_askar_recipient) = extract_jwk_data(new_recipient)?;

    let matching_recipient = jwe
        .recipients
        .iter()
        .find(|key| {
            key.header.algorithm == "ECDH-ES+A256KW"
                && existing_consumer_info == key.header.consumer_info.0
        })
        .ok_or_else(|| Error::from_msg(ErrorKind::Encryption, "Recipient not found."))?;

    let existing_ephemeral_key_pair = X25519KeyPair::from_jwk(
        &serde_json::to_string(&matching_recipient.header.ephemeral_key_pair)
            .expect("JWK serialization should always succeed"),
    )?;

    let existing_kek = create_kek(
        &existing_ephemeral_key_pair,
        &existing_askar_recipient,
        existing_consumer_info,
        true,
    )?;

    let mut cek_buffer = matching_recipient.encrypted_key.0.clone();
    existing_kek.decrypt_in_place(&mut cek_buffer, &[], &[])?;

    let new_ephemeral_key_pair = X25519KeyPair::random()?;
    let new_producer_info = new_ephemeral_key_pair.to_public_bytes()?;

    let kek = create_kek(
        &new_ephemeral_key_pair,
        &new_askar_recipient,
        new_consumer_info,
        false,
    )?;
    kek.encrypt_in_place(&mut cek_buffer, &[], &[])?;

    Ok(Recipient {
        header: Header {
            key_id: new_recipient
                .key_id
                .clone()
                .expect("recipient JWK values should always contain a key id"),
            algorithm: "ECDH-ES+A256KW".to_string(),
            ephemeral_key_pair: serde_json::from_str(
                &new_ephemeral_key_pair.to_jwk_public(Some(KeyAlg::X25519))?,
            )
            .expect("JWK serialization should always succeed"),
            producer_info: Base64urlUInt(new_producer_info.to_vec()),
            consumer_info: Base64urlUInt(new_consumer_info.to_vec()),
        },
        encrypted_key: Base64urlUInt(cek_buffer.to_vec()),
    })
}

#[allow(clippy::type_complexity)]
fn encrypt_with_cek<'a, T: SymmetricEncryptionAlgorithm>(
    cek: &T::ContentEncryptionKey,
    payload: &'a mut Vec<u8>,
) -> Result<
    (
        GenericArray<u8, <T::ContentEncryptionKey as KeyAeadMeta>::NonceSize>,
        &'a [u8],
        &'a [u8],
    ),
    Error,
> {
    let iv = T::ContentEncryptionKey::random_nonce();
    let ciphertext_len =
        cek.encrypt_in_place(payload, &iv, T::SHARED_PROTECTED_HEADER_BASE64.as_bytes())?;
    let (ciphertext, tag) = payload.split_at(ciphertext_len);

    Ok((iv, ciphertext, tag))
}

fn decrypt_with_cek<T: SymmetricEncryptionAlgorithm>(
    cek: &T::ContentEncryptionKey,
    ciphertext: &mut Vec<u8>,
    iv: &[u8],
    tag: &[u8],
) -> Result<(), Error> {
    ciphertext.extend_from_slice(tag);
    cek.decrypt_in_place(ciphertext, iv, T::SHARED_PROTECTED_HEADER_BASE64.as_bytes())?;

    Ok(())
}

fn create_kek(
    ephemeral_key_pair: &X25519KeyPair,
    recipient: &X25519KeyPair,
    consumer_info: &[u8],
    receive: bool,
) -> Result<AesKey<A256Kw>, Error> {
    let producer_info = ephemeral_key_pair.to_public_bytes()?;

    let key_info = EcdhEs::new(
        ephemeral_key_pair,
        recipient,
        b"ECDH-ES+A256KW",
        &producer_info,
        consumer_info,
        receive,
    );

    let kek = AesKey::<A256Kw>::from_key_derivation(key_info)?;

    Ok(kek)
}

fn extract_jwk_data(jwk: &JWK) -> Result<(&[u8], X25519KeyPair), Error> {
    let consumer_info = jwk.key_id.as_deref().map(str::as_bytes).ok_or_else(|| {
        Error::from_msg(
            ErrorKind::InvalidKeyData,
            "Key identifier (consumer info) is not present.",
        )
    })?;

    // FIXME: Remove unnecessary JWK conversion.
    let askar_recipient = X25519KeyPair::from_jwk(
        &serde_json::to_string(jwk).expect("JWK serialization should always succeed"),
    )?;

    Ok((consumer_info, askar_recipient))
}

#[cfg(test)]
mod tests {
    use askar_crypto::alg::{aes::A256Gcm, chacha20::XC20P};
    use teddybear_crypto::Ed25519;

    use crate::{add_recipient, decrypt, encrypt};

    macro_rules! generate_tests {
        ($name:ident, $symmetric_algorithm:ty) => {
            ::paste::paste! {
                #[tokio::test]
                async fn [<single_recipient_ $name>]() {
                    let value = b"Hello, world";
                    let key = Ed25519::generate().await.unwrap();
                    let jwe = encrypt::<$symmetric_algorithm>(value, &[&key.to_x25519_public_jwk()]).unwrap();
                    let decrypted = decrypt::<$symmetric_algorithm>(&jwe, key.as_x25519_private_jwk()).unwrap();
                    assert_eq!(decrypted, value);
                }

                #[tokio::test]
                async fn [<multiple_recipients_ $name>]() {
                    let value = b"Hello, world";

                    let key = Ed25519::generate().await.unwrap();
                    let key2 = Ed25519::generate().await.unwrap();
                    let key3 = Ed25519::generate().await.unwrap();

                    let jwe = encrypt::<$symmetric_algorithm>(
                        value,
                        &[
                            &key.to_x25519_public_jwk(),
                            &key2.to_x25519_public_jwk(),
                            &key3.to_x25519_public_jwk(),
                        ],
                    )
                    .unwrap();

                    let decrypted = decrypt::<$symmetric_algorithm>(&jwe, key2.as_x25519_private_jwk()).unwrap();

                    assert_eq!(decrypted, value);
                }

                #[tokio::test]
                async fn [<unknown_key_ $name>]() {
                    let value = b"Hello, world";
                    let key = Ed25519::generate().await.unwrap();
                    let jwe = encrypt::<$symmetric_algorithm>(value, &[&key.to_x25519_public_jwk()]).unwrap();
                    assert!(decrypt::<$symmetric_algorithm>(
                        &jwe,
                        Ed25519::generate().await.unwrap().as_x25519_private_jwk()
                    )
                    .is_err());
                }

                #[tokio::test]
                async fn [<large_payload_ $name>]() {
                    let value = vec![0; 4096];
                    let key = Ed25519::generate().await.unwrap();
                    let jwe = encrypt::<$symmetric_algorithm>(&value, &[&key.to_x25519_public_jwk()]).unwrap();
                    let decrypted = decrypt::<$symmetric_algorithm>(&jwe, key.as_x25519_private_jwk()).unwrap();
                    assert_eq!(decrypted, value);
                }

                #[tokio::test]
                async fn [<add_recipient_ $name>]() {
                    let value = b"Hello, world";

                    let key = Ed25519::generate().await.unwrap();
                    let key2 = Ed25519::generate().await.unwrap();

                    let mut jwe = encrypt::<$symmetric_algorithm>(
                        value,
                        &[
                            &key.to_x25519_public_jwk(),
                            &key2.to_x25519_public_jwk(),
                        ],
                    )
                    .unwrap();

                    let key3 = Ed25519::generate().await.unwrap();

                    let recipient = add_recipient::<$symmetric_algorithm>(&mut jwe, key.as_x25519_private_jwk(), &key3.to_x25519_public_jwk())
                        .unwrap();

                    jwe.recipients.push(recipient);

                    let decrypted_one = decrypt::<$symmetric_algorithm>(&jwe, key2.as_x25519_private_jwk()).unwrap();
                    let decrypted_two = decrypt::<$symmetric_algorithm>(&jwe, key3.as_x25519_private_jwk()).unwrap();

                    assert_eq!(decrypted_one, decrypted_two);
                }
            }
        };
    }

    generate_tests!(aes, A256Gcm);
    generate_tests!(chacha, XC20P);
}
