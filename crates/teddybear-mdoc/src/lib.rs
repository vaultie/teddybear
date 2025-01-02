use isomdl::{
    definitions::{CoseKey, DeviceKeyInfo, DigestAlgorithm, EC2Curve, ValidityInfo, EC2Y, x509::X5Chain},
    issuance::{self, Namespaces},
};
use teddybear_crypto::{EcdsaSecp256r1VerificationKey2019, PrivateSecp256r1, ToEncodedPoint};
use thiserror::Error;
use time::OffsetDateTime;

#[derive(Error, Debug)]
pub enum Error {
    #[error("the provided key is missing the x coordinate")]
    MissingXCoordinate,

    #[error("the provided key is missing the y coordinate")]
    MissingYCoordinate,

    #[error(transparent)]
    Cbor(#[from] isomdl::cbor::CborError),

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
