use std::borrow::Cow;

use askar_crypto::{
    Error, ErrorKind,
    alg::{
        HasKeyAlg, KeyAlg,
        aes::{A256Kw, AesKey},
        chacha20::Chacha20Key,
    },
    encrypt::{KeyAeadInPlace, KeyAeadMeta},
    generic_array::GenericArray,
    jwk::{FromJwk, ToJwk},
    kdf::{FromKeyDerivation, KeyExchange, ecdh_es::EcdhEs},
    repr::{KeyGen, KeyPublicBytes, KeySecretBytes, ToPublicBytes, ToSecretBytes},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use ssi_jwk::{Base64urlUInt, JWK};

pub use askar_crypto::alg::{
    aes::{A128Gcm, A256Gcm},
    chacha20::XC20P,
    p256::P256KeyPair,
    x25519::X25519KeyPair,
};

pub trait ToBytesRepresentation {
    type Bytes<'a>: AsRef<[u8]>
    where
        Self: 'a;

    fn as_bytes(&self) -> Self::Bytes<'_>;
}

impl ToBytesRepresentation for x25519_dalek::PublicKey {
    type Bytes<'a> = &'a [u8; 32];

    fn as_bytes(&self) -> Self::Bytes<'_> {
        self.as_bytes()
    }
}

impl ToBytesRepresentation for x25519_dalek::StaticSecret {
    type Bytes<'a> = &'a [u8; 32];

    fn as_bytes(&self) -> Self::Bytes<'_> {
        self.as_bytes()
    }
}

impl ToBytesRepresentation for p256::PublicKey {
    type Bytes<'a> = Box<[u8]>;

    fn as_bytes(&self) -> Self::Bytes<'_> {
        self.to_sec1_bytes()
    }
}

impl ToBytesRepresentation for p256::SecretKey {
    type Bytes<'a> = [u8; 32];

    fn as_bytes(&self) -> Self::Bytes<'_> {
        self.to_bytes().into()
    }
}

pub trait KeyExchangeAlgorithm:
    KeyExchange + KeyGen + KeySecretBytes + KeyPublicBytes + FromJwk + ToJwk + HasKeyAlg
{
    type Public: ToBytesRepresentation;
    type Private: ToBytesRepresentation;
}

impl KeyExchangeAlgorithm for X25519KeyPair {
    type Public = x25519_dalek::PublicKey;
    type Private = x25519_dalek::StaticSecret;
}

impl KeyExchangeAlgorithm for P256KeyPair {
    type Public = p256::PublicKey;
    type Private = p256::SecretKey;
}

pub trait SymmetricEncryptionAlgorithm {
    const SHARED_PROTECTED_HEADER_BASE64: &'static str;

    type ContentEncryptionKey: KeyAeadInPlace + KeyAeadMeta + KeySecretBytes + KeyGen;
}

impl SymmetricEncryptionAlgorithm for A128Gcm {
    const SHARED_PROTECTED_HEADER_BASE64: &'static str = "eyJlbmMiOiJBMTI4R0NNIn0";

    type ContentEncryptionKey = AesKey<A128Gcm>;
}

impl SymmetricEncryptionAlgorithm for A256Gcm {
    const SHARED_PROTECTED_HEADER_BASE64: &'static str = "eyJlbmMiOiJBMjU2R0NNIn0";

    type ContentEncryptionKey = AesKey<A256Gcm>;
}

impl SymmetricEncryptionAlgorithm for XC20P {
    const SHARED_PROTECTED_HEADER_BASE64: &'static str = "eyJlbmMiOiJYQzIwUCJ9";

    type ContentEncryptionKey = Chacha20Key<XC20P>;
}

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

pub fn encrypt<
    'a,
    T: SymmetricEncryptionAlgorithm,
    R: KeyExchangeAlgorithm + 'a,
    I: IntoIterator<Item = (String, &'a R::Public)>,
>(
    payload: &[u8],
    recipients: I,
) -> Result<GeneralJWE<'static>, Error> {
    let cek = <T::ContentEncryptionKey>::random()?;

    let recipients = recipients
        .into_iter()
        .map(|(consumer_info, recipient)| {
            let ephemeral_key_pair = R::random()?;
            let producer_info = ephemeral_key_pair.to_public_bytes()?;

            let askar_recipient = R::from_public_bytes(recipient.as_bytes().as_ref())?;

            let kek = create_kek(
                &ephemeral_key_pair,
                &askar_recipient,
                consumer_info.as_bytes(),
                false,
            )?;

            let mut cek_buffer = cek.to_secret_bytes()?;
            kek.encrypt_in_place(&mut cek_buffer, &[], &[])?;

            Ok(Recipient {
                header: Header {
                    key_id: consumer_info.clone(),
                    algorithm: "ECDH-ES+A256KW".to_string(),
                    ephemeral_key_pair: serde_json::from_str(
                        &ephemeral_key_pair.to_jwk_public(Some(ephemeral_key_pair.algorithm()))?,
                    )
                    .expect("JWK serialization should always succeed"),
                    producer_info: Base64urlUInt(producer_info.to_vec()),
                    consumer_info: Base64urlUInt(consumer_info.into_bytes()),
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

pub fn decrypt<T: SymmetricEncryptionAlgorithm, R: KeyExchangeAlgorithm>(
    jwe: &GeneralJWE<'_>,
    consumer_info: &str,
    recipient: &R::Private,
) -> Result<Vec<u8>, Error> {
    if jwe.protected != T::SHARED_PROTECTED_HEADER_BASE64 {
        return Err(Error::from_msg(
            ErrorKind::Encryption,
            "Invalid shared protected header value.",
        ));
    }

    let askar_recipient = R::from_secret_bytes(recipient.as_bytes().as_ref())?;

    let matching_recipient = jwe
        .recipients
        .iter()
        .find(|key| {
            key.header.algorithm == "ECDH-ES+A256KW"
                && consumer_info.as_bytes() == key.header.consumer_info.0
        })
        .ok_or_else(|| Error::from_msg(ErrorKind::Encryption, "Recipient not found."))?;

    let ephemeral_key_pair = R::from_jwk(
        &serde_json::to_string(&matching_recipient.header.ephemeral_key_pair)
            .expect("JWK serialization should always succeed"),
    )?;

    let kek = create_kek(
        &ephemeral_key_pair,
        &askar_recipient,
        consumer_info.as_bytes(),
        true,
    )?;

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

pub fn add_recipient<T: SymmetricEncryptionAlgorithm, R: KeyExchangeAlgorithm>(
    jwe: &GeneralJWE<'_>,
    existing_consumer_info: &str,
    existing_recipient: &R::Private,
    new_consumer_info: String,
    new_recipient: &R::Public,
) -> Result<Recipient, Error> {
    if jwe.protected != T::SHARED_PROTECTED_HEADER_BASE64 {
        return Err(Error::from_msg(
            ErrorKind::Encryption,
            "Invalid shared protected header value.",
        ));
    }

    let existing_askar_recipient = R::from_secret_bytes(existing_recipient.as_bytes().as_ref())?;
    let new_askar_recipient = R::from_public_bytes(new_recipient.as_bytes().as_ref())?;

    let matching_recipient = jwe
        .recipients
        .iter()
        .find(|key| {
            key.header.algorithm == "ECDH-ES+A256KW"
                && existing_consumer_info.as_bytes() == key.header.consumer_info.0
        })
        .ok_or_else(|| Error::from_msg(ErrorKind::Encryption, "Recipient not found."))?;

    let existing_ephemeral_key_pair = R::from_jwk(
        &serde_json::to_string(&matching_recipient.header.ephemeral_key_pair)
            .expect("JWK serialization should always succeed"),
    )?;

    let existing_kek = create_kek(
        &existing_ephemeral_key_pair,
        &existing_askar_recipient,
        existing_consumer_info.as_bytes(),
        true,
    )?;

    let mut cek_buffer = matching_recipient.encrypted_key.0.clone();
    existing_kek.decrypt_in_place(&mut cek_buffer, &[], &[])?;

    let new_ephemeral_key_pair = R::random()?;
    let new_producer_info = new_ephemeral_key_pair.to_public_bytes()?;

    let kek = create_kek(
        &new_ephemeral_key_pair,
        &new_askar_recipient,
        new_consumer_info.as_bytes(),
        false,
    )?;
    kek.encrypt_in_place(&mut cek_buffer, &[], &[])?;

    Ok(Recipient {
        header: Header {
            key_id: new_consumer_info.clone(),
            algorithm: "ECDH-ES+A256KW".to_string(),
            ephemeral_key_pair: serde_json::from_str(
                &new_ephemeral_key_pair.to_jwk_public(Some(KeyAlg::X25519))?,
            )
            .expect("JWK serialization should always succeed"),
            producer_info: Base64urlUInt(new_producer_info.to_vec()),
            consumer_info: Base64urlUInt(new_consumer_info.into_bytes()),
        },
        encrypted_key: Base64urlUInt(cek_buffer.clone()),
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

fn create_kek<R: KeyExchangeAlgorithm>(
    ephemeral_key_pair: &R,
    recipient: &R,
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

#[cfg(test)]
mod tests {
    use askar_crypto::alg::{aes::A256Gcm, chacha20::XC20P, x25519::X25519KeyPair};
    use teddybear_crypto::PrivateEd25519;
    use x25519_dalek::PublicKey;

    use crate::{add_recipient, decrypt, encrypt};

    macro_rules! generate_tests {
        ($name:ident, $symmetric_algorithm:ty) => {
            ::paste::paste! {
                #[tokio::test]
                async fn [<single_recipient_ $name>]() {
                    let value = b"Hello, world";
                    let key = PrivateEd25519::generate();
                    let jwe = encrypt::<$symmetric_algorithm, X25519KeyPair, _>(value, [
                        (String::from("key1"), &PublicKey::from(key.to_x25519_private_key().inner()))
                    ]).unwrap();
                    let decrypted = decrypt::<$symmetric_algorithm, X25519KeyPair>(&jwe, "key1", key.to_x25519_private_key().inner()).unwrap();
                    assert_eq!(decrypted, value);
                }

                #[tokio::test]
                async fn [<multiple_recipients_ $name>]() {
                    let value = b"Hello, world";

                    let key = PrivateEd25519::generate();
                    let key2 = PrivateEd25519::generate();
                    let key3 = PrivateEd25519::generate();

                    let jwe = encrypt::<$symmetric_algorithm, X25519KeyPair, _>(
                        value,
                        [
                            (String::from("key1"), &PublicKey::from(key.to_x25519_private_key().inner())),
                            (String::from("key2"), &PublicKey::from(key2.to_x25519_private_key().inner())),
                            (String::from("key3"), &PublicKey::from(key3.to_x25519_private_key().inner()))
                        ],
                    )
                    .unwrap();

                    let decrypted = decrypt::<$symmetric_algorithm, X25519KeyPair>(&jwe, "key2", key2.to_x25519_private_key().inner()).unwrap();

                    assert_eq!(decrypted, value);
                }

                #[tokio::test]
                async fn [<unknown_key_ $name>]() {
                    let value = b"Hello, world";
                    let key = PrivateEd25519::generate();
                    let jwe = encrypt::<$symmetric_algorithm, X25519KeyPair, _>(value, [
                        (String::from("key1"), &PublicKey::from(key.to_x25519_private_key().inner()))
                    ]).unwrap();
                    assert!(decrypt::<$symmetric_algorithm, X25519KeyPair>(
                        &jwe,
                        "key1",
                        PrivateEd25519::generate().to_x25519_private_key().inner()
                    )
                    .is_err());
                }

                #[tokio::test]
                async fn [<large_payload_ $name>]() {
                    let value = vec![0; 4096];
                    let key = PrivateEd25519::generate();
                    let jwe = encrypt::<$symmetric_algorithm, X25519KeyPair, _>(&value, [
                        (String::from("key1"), &PublicKey::from(key.to_x25519_private_key().inner()))
                    ]).unwrap();
                    let decrypted = decrypt::<$symmetric_algorithm, X25519KeyPair>(&jwe, "key1", key.to_x25519_private_key().inner()).unwrap();
                    assert_eq!(decrypted, value);
                }

                #[tokio::test]
                async fn [<add_recipient_ $name>]() {
                    let value = b"Hello, world";

                    let key = PrivateEd25519::generate();
                    let key2 = PrivateEd25519::generate();

                    let mut jwe = encrypt::<$symmetric_algorithm, X25519KeyPair, _>(
                        value,
                        [
                            (String::from("key1"), &PublicKey::from(key.to_x25519_private_key().inner())),
                            (String::from("key2"), &PublicKey::from(key2.to_x25519_private_key().inner())),
                        ],
                    )
                    .unwrap();

                    let key3 = PrivateEd25519::generate();

                    let recipient = add_recipient::<$symmetric_algorithm, X25519KeyPair>(
                        &mut jwe,
                        "key1",
                        key.to_x25519_private_key().inner(),
                        String::from("key3"),
                        &PublicKey::from(key3.to_x25519_private_key().inner())
                    )
                    .unwrap();

                    jwe.recipients.push(recipient);

                    let decrypted_one = decrypt::<$symmetric_algorithm, X25519KeyPair>(&jwe, "key2", key2.to_x25519_private_key().inner()).unwrap();
                    let decrypted_two = decrypt::<$symmetric_algorithm, X25519KeyPair>(&jwe, "key3", key3.to_x25519_private_key().inner()).unwrap();

                    assert_eq!(decrypted_one, decrypted_two);
                }
            }
        };
    }

    generate_tests!(aes, A256Gcm);
    generate_tests!(chacha, XC20P);
}
