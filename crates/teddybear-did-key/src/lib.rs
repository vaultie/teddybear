use std::collections::BTreeMap;

use async_trait::async_trait;
use ed25519_dalek::VerifyingKey;
use iref::Iri;
use multibase::Base;
use serde_json::Value;
use ssi_dids::{
    did_resolve::{
        DIDResolver, DocumentMetadata, ResolutionInputMetadata, ResolutionMetadata,
        ERROR_INVALID_DID, ERROR_NOT_FOUND,
    },
    Context, Contexts, DIDMethod, Document, Source, VerificationMethod, VerificationMethodMap,
    DEFAULT_CONTEXT, DIDURL,
};
use ssi_jwk::Params;
use static_iref::iri;

// https://www.w3.org/community/reports/credentials/CG-FINAL-di-eddsa-2020-20220724/#ed25519verificationkey2020
const ED25519_CONTEXT: Iri = iri!("https://w3id.org/security/suites/ed25519-2020/v1");
const ED25519_TYPE: &str = "Ed25519VerificationKey2020";
const ED25519_PREFIX: &[u8] = &[0xed, 0x01];

const X25519_CONTEXT: Iri = iri!("https://w3id.org/security/suites/x25519-2020/v1");
const X25519_TYPE: &str = "X25519KeyAgreementKey2020";
const X25519_PREFIX: &[u8] = &[0xec, 0x01];

macro_rules! bail {
    ($error:expr) => {
        return (ResolutionMetadata::from_error($error), None, None)
    };
}

pub struct DidKey;

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl DIDResolver for DidKey {
    async fn resolve(
        &self,
        did: &str,
        _: &ResolutionInputMetadata,
    ) -> (
        ResolutionMetadata,
        Option<Document>,
        Option<DocumentMetadata>,
    ) {
        let Some(key) = did.strip_prefix("did:key:") else {
            bail!(ERROR_INVALID_DID);
        };

        let Ok((_, data)) = multibase::decode(key) else {
            bail!(ERROR_INVALID_DID);
        };

        let (ED25519_PREFIX, value) = data.split_at(2) else {
            bail!(ERROR_NOT_FOUND);
        };

        let Ok(bytes) = value.try_into() else {
            bail!(ERROR_INVALID_DID);
        };

        let Ok(public_key) = VerifyingKey::from_bytes(bytes) else {
            bail!(ERROR_INVALID_DID)
        };

        let x25519_key = public_key.to_montgomery();
        let encoded_x25519 = multibase::encode(
            Base::Base58Btc,
            [X25519_PREFIX, x25519_key.as_bytes()].concat(),
        );

        let ed25519_url = DIDURL {
            did: did.to_string(),
            fragment: Some(key.to_string()),
            ..Default::default()
        };

        let ed25519_url_ref = VerificationMethod::DIDURL(ed25519_url.clone());

        let x25519_url = DIDURL {
            did: did.to_string(),
            fragment: Some(encoded_x25519.clone()),
            ..Default::default()
        };

        let doc = Document {
            context: Contexts::Many(vec![
                Context::URI(DEFAULT_CONTEXT.into()),
                Context::URI(ED25519_CONTEXT.into()),
                Context::URI(X25519_CONTEXT.into()),
            ]),
            id: did.to_string(),
            verification_method: Some(vec![VerificationMethod::Map(VerificationMethodMap {
                id: ed25519_url.to_string(),
                type_: ED25519_TYPE.to_string(),
                controller: did.to_string(),
                property_set: Some(BTreeMap::from_iter([(
                    String::from("publicKeyMultibase"),
                    Value::String(key.to_string()),
                )])),
                ..Default::default()
            })]),
            authentication: Some(vec![ed25519_url_ref.clone()]),
            assertion_method: Some(vec![ed25519_url_ref.clone()]),
            capability_delegation: Some(vec![ed25519_url_ref.clone()]),
            capability_invocation: Some(vec![ed25519_url_ref]),
            key_agreement: Some(vec![VerificationMethod::Map(VerificationMethodMap {
                id: x25519_url.to_string(),
                type_: X25519_TYPE.to_string(),
                controller: did.to_string(),
                property_set: Some(BTreeMap::from_iter([(
                    String::from("publicKeyMultibase"),
                    Value::String(encoded_x25519),
                )])),
                ..Default::default()
            })]),
            ..Default::default()
        };

        (
            ResolutionMetadata::default(),
            Some(doc),
            Some(DocumentMetadata::default()),
        )
    }
}

#[async_trait]
impl DIDMethod for DidKey {
    fn name(&self) -> &'static str {
        "key"
    }

    fn to_resolver(&self) -> &dyn DIDResolver {
        self
    }

    fn generate(&self, source: &Source) -> Option<String> {
        let jwk = match source {
            Source::Key(jwk) => jwk,
            Source::KeyAndPattern(jwk, "") => jwk,
            _ => return None,
        };

        match &jwk.params {
            Params::OKP(params) if params.curve == "Ed25519" => Some(
                [
                    "did:key:",
                    &multibase::encode(
                        Base::Base58Btc,
                        [ED25519_PREFIX, &params.public_key.0].concat(),
                    ),
                ]
                .concat(),
            ),
            _ => None,
        }
    }
}
