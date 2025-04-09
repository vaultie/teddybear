use std::collections::BTreeMap;

use iref::IriRef;
use p256::{CompressedPoint, PublicKey};
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

use crate::KeyType;

const P256_CONTEXT: &IriRef = iri_ref!("https://w3id.org/security/multikey/v1");
const P256_TYPE: &str = "Multikey";

pub struct P256;

impl KeyType for P256 {
    type PublicKey = PublicKey;

    const CODEC: u64 = ssi_multicodec::P256_PUB;

    fn fragment(source: &Self::PublicKey) -> MultibaseBuf {
        let multi_encoded =
            MultiEncodedBuf::encode_bytes(Self::CODEC, &CompressedPoint::from(source));
        MultibaseBuf::encode(Base::Base58Btc, multi_encoded.as_bytes())
    }

    fn resolve(
        raw: &str,
        value: &[u8],
        options: resolution::Options,
    ) -> Result<resolution::Output<Vec<u8>>, resolution::Error> {
        PublicKey::from_sec1_bytes(value)
            .map_err(|e| Error::InvalidMethodSpecificId(e.to_string()))?;

        let document_did = DIDBuf::from_string(format!("did:key:{raw}"))
            .expect("the provided document did:key string is expected to always be valid");

        let p256_did = DIDURLBuf::from_string(format!("did:key:{raw}#{raw}"))
            .expect("the provided p256 did:key string is expected to always be valid");

        let mut doc = Document::new(document_did.clone());

        doc.verification_method = vec![DIDVerificationMethod::new(
            p256_did.clone(),
            P256_TYPE.to_string(),
            document_did.clone(),
            BTreeMap::from_iter([(
                String::from("publicKeyMultibase"),
                Value::String(raw.to_string()),
            )]),
        )];

        doc.verification_relationships
            .authentication
            .push(ValueOrReference::Reference(p256_did.clone().into()));

        doc.verification_relationships
            .assertion_method
            .push(ValueOrReference::Reference(p256_did.clone().into()));

        doc.verification_relationships
            .key_agreement
            .push(ValueOrReference::Reference(p256_did.into()));

        let content_type = options.accept.unwrap_or(representation::MediaType::JsonLd);
        let representation = doc.into_representation(representation::Options::from_media_type(
            content_type,
            move || json_ld::Options {
                context: json_ld::Context::array(
                    json_ld::DIDContext::V1,
                    vec![json_ld::ContextEntry::IriRef(P256_CONTEXT.to_owned())],
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
