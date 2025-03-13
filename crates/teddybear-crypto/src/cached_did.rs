use std::collections::HashMap;

use ssi_dids_core::{
    document::{self, representation::Options},
    resolution, DIDBuf, DIDResolver, DID,
};

use crate::Document;

pub struct CachedDIDResolver<I> {
    inner: I,
    documents: HashMap<DIDBuf, Document>,
}

impl<I> CachedDIDResolver<I> {
    pub fn new(inner: I, documents: HashMap<DIDBuf, Document>) -> Self {
        Self { inner, documents }
    }
}

impl<I: DIDResolver> DIDResolver for CachedDIDResolver<I> {
    async fn resolve_representation<'a>(
        &'a self,
        did: &'a DID,
        options: resolution::Options,
    ) -> Result<resolution::Output<Vec<u8>>, resolution::Error> {
        if let Some(document) = self.documents.get(did) {
            let represented = document.inner.clone().into_representation(Options::Json);

            Ok(resolution::Output::new(
                represented.to_bytes(),
                document::Metadata::default(),
                resolution::Metadata::from_content_type(Some(represented.media_type().to_string())),
            ))
        } else {
            self.inner.resolve_representation(did, options).await
        }
    }
}
