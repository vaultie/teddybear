use std::{array::TryFromSliceError, collections::BTreeMap};

use ed25519_dalek::VerifyingKey;
use iref::IriRef;
use serde_json::Value;
use ssi_dids_core::{
    document::{
        self,
        representation::{self, json_ld},
        verification_method::ValueOrReference,
        DIDVerificationMethod,
    },
    resolution::{self, Error},
    DIDBuf, DIDMethod, DIDMethodResolver, DIDURLBuf, Document,
};
use ssi_multicodec::{MultiEncoded, MultiEncodedBuf};
use ssi_security::{multibase::Base, Multibase, MultibaseBuf};
use static_iref::iri_ref;

// https://www.w3.org/community/reports/credentials/CG-FINAL-di-eddsa-2020-20220724/#ed25519verificationkey2020
const ED25519_CONTEXT: &IriRef = iri_ref!("https://w3id.org/security/suites/ed25519-2020/v1");
const ED25519_TYPE: &str = "Ed25519VerificationKey2020";

const X25519_CONTEXT: &IriRef = iri_ref!("https://w3id.org/security/suites/x25519-2020/v1");
const X25519_TYPE: &str = "X25519KeyAgreementKey2020";

pub struct DIDKey;

impl DIDKey {
    pub fn generate(&self, source: &ed25519_dalek::VerifyingKey) -> DIDBuf {
        DIDBuf::from_string(format!(
            "did:key:{}",
            self.generate_ed25519_fragment(source)
        ))
        .expect("DIDKey is expected to generate a valid DID")
    }

    pub fn generate_ed25519_fragment(&self, source: &ed25519_dalek::VerifyingKey) -> MultibaseBuf {
        let multi_encoded =
            MultiEncodedBuf::encode_bytes(ssi_multicodec::ED25519_PUB, &source.to_bytes());

        MultibaseBuf::encode(Base::Base58Btc, multi_encoded.as_bytes())
    }

    pub fn generate_x25519_fragment(&self, source: &x25519_dalek::PublicKey) -> MultibaseBuf {
        let multi_encoded =
            MultiEncodedBuf::encode_bytes(ssi_multicodec::X25519_PUB, &source.to_bytes());

        MultibaseBuf::encode(Base::Base58Btc, multi_encoded.as_bytes())
    }
}

impl DIDMethod for DIDKey {
    const DID_METHOD_NAME: &'static str = "key";
}

impl DIDMethodResolver for DIDKey {
    async fn resolve_method_representation<'a>(
        &'a self,
        key: &'a str,
        options: resolution::Options,
    ) -> Result<resolution::Output<Vec<u8>>, Error> {
        let (_, data) = Multibase::new(key)
            .decode()
            .map_err(|e| Error::InvalidMethodSpecificId(e.to_string()))?;

        if data.len() < 2 {
            return Err(Error::NotFound);
        }

        let (codec, value) = MultiEncoded::new(&data)
            .map_err(|_| Error::NotFound)?
            .parts();

        if codec != ssi_multicodec::ED25519_PUB {
            return Err(Error::NotFound);
        }

        let bytes = value
            .try_into()
            .map_err(|e: TryFromSliceError| Error::InvalidMethodSpecificId(e.to_string()))?;

        let public_key = VerifyingKey::from_bytes(bytes)
            .map_err(|e| Error::InvalidMethodSpecificId(e.to_string()))?;

        let x25519_key = x25519_dalek::PublicKey::from(public_key.to_montgomery().to_bytes());
        let encoded_x25519 = DIDKey.generate_x25519_fragment(&x25519_key).to_string();

        let document_did = DIDBuf::from_string(format!("did:key:{key}"))
            .expect("the provided document did:key string is expected to always be valid");

        let ed25519_did = DIDURLBuf::from_string(format!("did:key:{key}#{key}"))
            .expect("the provided ed25519 did:key string is expected to always be valid");

        let x25519_did = DIDURLBuf::from_string(format!("did:key:{key}#{encoded_x25519}"))
            .expect("the provided x25519 did:key string is expected to always be valid");

        let mut doc = Document::new(document_did.clone());

        doc.verification_method = vec![
            DIDVerificationMethod::new(
                ed25519_did.clone(),
                ED25519_TYPE.to_string(),
                document_did.clone(),
                BTreeMap::from_iter([(
                    String::from("publicKeyMultibase"),
                    Value::String(key.to_string()),
                )]),
            ),
            DIDVerificationMethod::new(
                x25519_did.clone(),
                X25519_TYPE.to_string(),
                document_did,
                BTreeMap::from_iter([(
                    String::from("publicKeyMultibase"),
                    Value::String(encoded_x25519),
                )]),
            ),
        ];

        doc.verification_relationships
            .authentication
            .push(ValueOrReference::Reference(ed25519_did.clone().into()));

        doc.verification_relationships
            .assertion_method
            .push(ValueOrReference::Reference(ed25519_did.into()));

        doc.verification_relationships
            .key_agreement
            .push(ValueOrReference::Reference(x25519_did.into()));

        let content_type = options.accept.unwrap_or(representation::MediaType::JsonLd);
        let representation = doc.into_representation(representation::Options::from_media_type(
            content_type,
            move || json_ld::Options {
                context: json_ld::Context::array(
                    json_ld::DIDContext::V1,
                    vec![
                        json_ld::ContextEntry::IriRef(ED25519_CONTEXT.to_owned()),
                        json_ld::ContextEntry::IriRef(X25519_CONTEXT.to_owned()),
                    ],
                ),
            },
        ));

        Ok(resolution::Output::new(
            representation.to_bytes(),
            document::Metadata::default(),
            resolution::Metadata::from_content_type(Some(content_type.to_string())),
        ))
    }
}
