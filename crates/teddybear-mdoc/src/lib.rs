use std::collections::BTreeMap;

use isomdl::{
    definitions::{
        device_request::{self, ItemsRequest},
        helpers::{ByteStr, Tag24},
        x509::{trust_anchor::TrustAnchorRegistry, X5Chain},
        CoseKey, DeviceKeyInfo, DigestAlgorithm, EC2Curve, SessionEstablishment, EC2Y,
    },
    issuance::{self, Mdoc, Namespaces},
    presentation::device::{self, DeviceSession, Document, SessionManager, SessionManagerInit},
};
use p256::ecdsa::{signature::Signer, Signature};
use teddybear_crypto::{EcdsaSecp256r1VerificationKey2019, PrivateSecp256r1, ToEncodedPoint};
use thiserror::Error;
use time::OffsetDateTime;

pub use isomdl::definitions::ValidityInfo;

#[derive(Error, Debug)]
pub enum Error {
    #[error("the provided key is missing the x coordinate")]
    MissingXCoordinate,

    #[error("the provided key is missing the y coordinate")]
    MissingYCoordinate,

    #[error(transparent)]
    Cbor(#[from] isomdl::cbor::CborError),

    #[error(transparent)]
    Presentation(#[from] device::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub struct MDocBuilder(issuance::mdoc::Builder);

impl MDocBuilder {
    pub fn new() -> Self {
        Self(issuance::mdoc::Builder::default().digest_algorithm(DigestAlgorithm::SHA256))
    }

    pub fn set_validity_info(
        mut self,
        signed: OffsetDateTime,
        valid_from: OffsetDateTime,
        valid_until: OffsetDateTime,
        expected_update: Option<OffsetDateTime>,
    ) -> Self {
        self.0 = self.0.validity_info(ValidityInfo {
            signed,
            valid_from,
            valid_until,
            expected_update,
        });
        self
    }

    pub fn set_doctype(mut self, doc_type: String) -> Self {
        self.0 = self.0.doc_type(doc_type);
        self
    }

    pub fn set_namespaces(mut self, namespaces: Namespaces) -> Self {
        self.0 = self.0.namespaces(namespaces);
        self
    }

    pub fn set_device_info(
        mut self,
        device_key: &EcdsaSecp256r1VerificationKey2019,
    ) -> Result<Self, Error> {
        let encoded_point = device_key.public_key.decoded().to_encoded_point(false);

        let x = encoded_point.x().ok_or(Error::MissingXCoordinate)?.to_vec();
        let y = encoded_point.y().ok_or(Error::MissingYCoordinate)?.to_vec();

        self.0 = self.0.device_key_info(DeviceKeyInfo {
            device_key: CoseKey::EC2 {
                crv: EC2Curve::P256,
                x,
                y: EC2Y::Value(y),
            },
            key_authorizations: None,
            key_info: None,
        });

        Ok(self)
    }

    pub fn issue<C: AsRef<[u8]>, I: IntoIterator<Item = C>>(
        self,
        key: &PrivateSecp256r1,
        certificates: I,
    ) -> Result<Vec<u8>, Error> {
        let mut x5chain_builder = X5Chain::builder();

        for certificate in certificates {
            x5chain_builder = x5chain_builder.with_der_certificate(certificate.as_ref())?;
        }

        let x5chain = x5chain_builder.build()?;

        let mdoc = self
            .0
            .issue::<_, p256::ecdsa::Signature>(x5chain, key.ecdsa_signing_key())?;

        Ok(isomdl::cbor::to_vec(&mdoc)?)
    }
}

impl Default for MDocBuilder {
    fn default() -> Self {
        Self::new()
    }
}

pub struct DeviceInternalMDoc(Document);

impl DeviceInternalMDoc {
    pub fn from_bytes(value: &[u8]) -> Result<Self, Error> {
        let document = isomdl::cbor::from_slice(value)?;
        Ok(Self(document))
    }

    pub fn from_issued_bytes(value: &[u8]) -> Result<Self, Error> {
        let mdoc: Mdoc = isomdl::cbor::from_slice(value)?;
        Ok(Self(mdoc.into()))
    }

    pub fn doc_type(&self) -> &str {
        &self.0.mso.doc_type
    }

    pub fn namespaces(&self) -> BTreeMap<String, BTreeMap<String, ciborium::Value>> {
        self.0
            .namespaces
            .iter()
            .map(|(namespace, entries)| {
                let value = entries
                    .iter()
                    .map(|(_, value)| {
                        let value = value.clone().into_inner();
                        (value.element_identifier, value.element_value)
                    })
                    .collect();

                (namespace.clone(), value)
            })
            .collect()
    }

    pub fn validity_info(&self) -> &ValidityInfo {
        &self.0.mso.validity_info
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        Ok(isomdl::cbor::to_vec(&self.0)?)
    }
}

pub struct PendingPresentation {
    session: SessionManager,
}

impl PendingPresentation {
    pub fn start<D>(
        verifier_key: &EcdsaSecp256r1VerificationKey2019,
        trust_anchor_registry: TrustAnchorRegistry,
        documents: D,
    ) -> Result<Self, Error>
    where
        D: IntoIterator<Item = DeviceInternalMDoc>,
    {
        let verifier_key_point = verifier_key.public_key.decoded().to_encoded_point(false);

        let x = verifier_key_point
            .x()
            .ok_or(Error::MissingXCoordinate)?
            .to_vec();

        let y = verifier_key_point
            .y()
            .ok_or(Error::MissingYCoordinate)?
            .to_vec();

        let documents = documents
            .into_iter()
            .map(|document| (document.doc_type().to_owned(), document.0))
            .collect::<BTreeMap<_, _>>();

        let (session, _) =
            SessionManagerInit::initialise(documents.try_into().unwrap(), None, None)?
                .qr_engagement()?
                .0
                .process_session_establishment(
                    SessionEstablishment {
                        e_reader_key: Tag24::new(CoseKey::EC2 {
                            crv: EC2Curve::P256,
                            x,
                            y: EC2Y::Value(y),
                        })
                        .unwrap(),
                        data: ByteStr::from(vec![]),
                    },
                    trust_anchor_registry,
                )?;

        Ok(Self { session })
    }

    pub fn consent<R>(
        self,
        device_key: &PrivateSecp256r1,
        requests: R,
        permits: BTreeMap<String, BTreeMap<String, Vec<String>>>,
    ) -> Result<Vec<u8>, Error>
    where
        R: IntoIterator<Item = (String, device_request::Namespaces)>,
    {
        let mut device_response = self.session.prepare_response(
            &requests
                .into_iter()
                .map(|(doc_type, namespaces)| ItemsRequest {
                    doc_type,
                    namespaces,
                    request_info: None,
                })
                .collect(),
            permits,
        );

        while let Some((_, payload)) = device_response.get_next_signature_payload() {
            let signature: Signature = device_key.ecdsa_signing_key().sign(payload);
            device_response.submit_next_signature(signature.to_bytes().to_vec());
        }

        let finalized_response = device_response.finalize_response();

        Ok(isomdl::cbor::to_vec(&finalized_response)?)
    }
}
