use itertools::Either;
use ssi_dids_core::{
    DIDMethod, DIDMethodResolver,
    document::{self, representation::MediaType},
    resolution,
};
use teddybear_common::HttpClient;

use std::{fmt::Write, iter, str::FromStr};

pub struct DIDWeb<T>(pub T);

impl<T> DIDMethod for DIDWeb<T> {
    const DID_METHOD_NAME: &'static str = "web";
}

impl<T> DIDMethodResolver for DIDWeb<T>
where
    T: HttpClient<serde_bytes::ByteBuf>,
{
    async fn resolve_method_representation<'a>(
        &'a self,
        method_specific_id: &'a str,
        _: ssi_dids_core::resolution::Options,
    ) -> Result<ssi_dids_core::resolution::Output<Vec<u8>>, ssi_dids_core::resolution::Error> {
        let (domain, path) = method_specific_id
            .split_once(':')
            .unwrap_or((method_specific_id, ""));

        let mut url = String::with_capacity(128);

        // Percent-encoded colon.
        let (domain, port) = domain
            .split_once("%3A")
            .map(|(domain, port)| (domain, u16::from_str(port).ok()))
            .unwrap_or((domain, None));

        let segments = if path.is_empty() {
            Either::Left(iter::once(".well-known"))
        } else {
            Either::Right(path.split(':'))
        };

        write!(&mut url, "https://{domain}").map_err(|_| {
            resolution::Error::InvalidMethodSpecificId(method_specific_id.to_string())
        })?;

        if let Some(port) = port {
            write!(&mut url, ":{port}").map_err(|_| {
                resolution::Error::InvalidMethodSpecificId(method_specific_id.to_string())
            })?;
        }

        for segment in segments {
            write!(&mut url, "/{segment}").map_err(|_| {
                resolution::Error::InvalidMethodSpecificId(method_specific_id.to_string())
            })?;
        }

        write!(&mut url, "/did.json").map_err(|_| {
            resolution::Error::InvalidMethodSpecificId(method_specific_id.to_string())
        })?;

        let document = self
            .0
            .get(&url)
            .await
            .map_err(resolution::Error::internal)?;

        Ok(resolution::Output {
            document: document.into_vec(),
            document_metadata: document::Metadata::default(),
            metadata: resolution::Metadata::from_content_type(Some(MediaType::JsonLd.to_string())),
        })
    }
}
