use std::collections::BTreeMap;

use iref::IriRef;
use serde_json::Value;
use ssi_dids_core::{
    DIDBuf, DIDURLBuf, Document,
    document::{
        self, DIDVerificationMethod,
        representation::{self, json_ld},
        verification_method::ValueOrReference,
    },
    resolution::{self, Error},
};
use ssi_multicodec::MultiEncodedBuf;
use ssi_security::{MultibaseBuf, multibase::Base};
use static_iref::iri_ref;
use x25519_dalek::PublicKey;

use crate::KeyType;

pub const X25519_CONTEXT: &IriRef = iri_ref!("https://w3id.org/security/suites/x25519-2020/v1");
pub const X25519_TYPE: &str = "X25519KeyAgreementKey2020";

pub struct X25519;

impl KeyType for X25519 {
    type PublicKey = PublicKey;

    const CODEC: u64 = ssi_multicodec::X25519_PUB;

    fn fragment(source: &Self::PublicKey) -> MultibaseBuf {
        let multi_encoded = MultiEncodedBuf::encode_bytes(Self::CODEC, &source.to_bytes());
        MultibaseBuf::encode(Base::Base58Btc, multi_encoded.as_bytes())
    }

    fn resolve(
        raw: &str,
        value: &[u8],
        options: ssi_dids_core::resolution::Options,
    ) -> Result<ssi_dids_core::resolution::Output<Vec<u8>>, ssi_dids_core::resolution::Error> {
        if value.len() != 32 {
            return Err(Error::InvalidMethodSpecificId(
                "Invalid value length".into(),
            ));
        }

        let document_did = DIDBuf::from_string(format!("did:key:{raw}"))
            .expect("the provided document did:key string is expected to always be valid");

        let x25519_did = DIDURLBuf::from_string(format!("did:key:{raw}#{raw}"))
            .expect("the provided x25519 did:key string is expected to always be valid");

        let mut doc = Document::new(document_did.clone());

        doc.verification_method = vec![DIDVerificationMethod::new(
            x25519_did.clone(),
            X25519_TYPE.to_string(),
            document_did,
            BTreeMap::from_iter([(
                String::from("publicKeyMultibase"),
                Value::String(raw.to_string()),
            )]),
        )];

        doc.verification_relationships
            .key_agreement
            .push(ValueOrReference::Reference(x25519_did.into()));

        let content_type = options.accept.unwrap_or(representation::MediaType::JsonLd);
        let representation = doc.into_representation(representation::Options::from_media_type(
            content_type,
            move || json_ld::Options {
                context: json_ld::Context::array(
                    json_ld::DIDContext::V1,
                    vec![json_ld::ContextEntry::IriRef(X25519_CONTEXT.to_owned())],
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
