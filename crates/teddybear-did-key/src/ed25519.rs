use std::{array::TryFromSliceError, collections::BTreeMap};

use ed25519_dalek::VerifyingKey;
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

use crate::{
    KeyType,
    x25519::{X25519, X25519_CONTEXT, X25519_TYPE},
};

// https://www.w3.org/community/reports/credentials/CG-FINAL-di-eddsa-2020-20220724/#ed25519verificationkey2020
const ED25519_CONTEXT: &IriRef = iri_ref!("https://w3id.org/security/suites/ed25519-2020/v1");
const ED25519_TYPE: &str = "Ed25519VerificationKey2020";

pub struct Ed25519;

impl KeyType for Ed25519 {
    type PublicKey = VerifyingKey;

    const CODEC: u64 = ssi_multicodec::ED25519_PUB;

    fn fragment(source: &Self::PublicKey) -> MultibaseBuf {
        let multi_encoded = MultiEncodedBuf::encode_bytes(Self::CODEC, &source.to_bytes());
        MultibaseBuf::encode(Base::Base58Btc, multi_encoded.as_bytes())
    }

    fn resolve(
        raw: &str,
        value: &[u8],
        options: resolution::Options,
    ) -> Result<resolution::Output<Vec<u8>>, Error> {
        let bytes = value
            .try_into()
            .map_err(|e: TryFromSliceError| Error::InvalidMethodSpecificId(e.to_string()))?;

        let public_key = VerifyingKey::from_bytes(bytes)
            .map_err(|e| Error::InvalidMethodSpecificId(e.to_string()))?;

        let x25519_key = PublicKey::from(public_key.to_montgomery().to_bytes());
        let encoded_x25519 = X25519::fragment(&x25519_key).to_string();

        let document_did = DIDBuf::from_string(format!("did:key:{raw}"))
            .expect("the provided document did:key string is expected to always be valid");

        let ed25519_did = DIDURLBuf::from_string(format!("did:key:{raw}#{raw}"))
            .expect("the provided ed25519 did:key string is expected to always be valid");

        let x25519_did = DIDURLBuf::from_string(format!("did:key:{raw}#{encoded_x25519}"))
            .expect("the provided x25519 did:key string is expected to always be valid");

        let mut doc = Document::new(document_did.clone());

        doc.verification_method = vec![
            DIDVerificationMethod::new(
                ed25519_did.clone(),
                ED25519_TYPE.to_string(),
                document_did.clone(),
                BTreeMap::from_iter([(
                    String::from("publicKeyMultibase"),
                    Value::String(raw.to_string()),
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
