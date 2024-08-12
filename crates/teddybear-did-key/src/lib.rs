use std::{array::TryFromSliceError, collections::BTreeMap};

use ed25519_dalek::VerifyingKey;
use iref::IriRef;
use multibase::Base;
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
use static_iref::iri_ref;

// https://www.w3.org/community/reports/credentials/CG-FINAL-di-eddsa-2020-20220724/#ed25519verificationkey2020
const ED25519_CONTEXT: &IriRef = iri_ref!("https://w3id.org/security/suites/ed25519-2020/v1");
const ED25519_TYPE: &str = "Ed25519VerificationKey2020";
const ED25519_PREFIX: &[u8] = &[0xed, 0x01];

const X25519_CONTEXT: &IriRef = iri_ref!("https://w3id.org/security/suites/x25519-2020/v1");
const X25519_TYPE: &str = "X25519KeyAgreementKey2020";
const X25519_PREFIX: &[u8] = &[0xec, 0x01];

pub struct DidKey;

impl DidKey {
    pub fn generate(&self, source: &ed25519_dalek::VerifyingKey) -> DIDBuf {
        DIDBuf::from_string(
            [
                "did:key:",
                &multibase::encode(
                    Base::Base58Btc,
                    [ED25519_PREFIX, source.as_bytes()].concat(),
                ),
            ]
            .concat(),
        )
        .expect("DidKey is expected to generate a valid did")
    }
}

impl DIDMethod for DidKey {
    const DID_METHOD_NAME: &'static str = "key";
}

impl DIDMethodResolver for DidKey {
    async fn resolve_method_representation<'a>(
        &'a self,
        key: &'a str,
        options: resolution::Options,
    ) -> Result<resolution::Output<Vec<u8>>, Error> {
        let (_, data) =
            multibase::decode(key).map_err(|e| Error::InvalidMethodSpecificId(e.to_string()))?;

        if data.len() < 2 {
            return Err(Error::NotFound);
        }

        let (ED25519_PREFIX, value) = data.split_at(2) else {
            return Err(Error::NotFound);
        };

        let bytes = value
            .try_into()
            .map_err(|e: TryFromSliceError| Error::InvalidMethodSpecificId(e.to_string()))?;

        let public_key = VerifyingKey::from_bytes(bytes)
            .map_err(|e| Error::InvalidMethodSpecificId(e.to_string()))?;

        let x25519_key = public_key.to_montgomery();
        let encoded_x25519 = multibase::encode(
            Base::Base58Btc,
            [X25519_PREFIX, x25519_key.as_bytes()].concat(),
        );

        let document_did = DIDBuf::from_string(format!("did:key:{}", key))
            .expect("the provided document did:key string is expected to always be valid");

        let ed25519_did = DIDURLBuf::from_string(format!("did:key:{}#{}", key, key))
            .expect("the provided ed25519 did:key string is expected to always be valid");

        let x25519_did = DIDURLBuf::from_string(format!("did:key:{}#{}", key, encoded_x25519))
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
