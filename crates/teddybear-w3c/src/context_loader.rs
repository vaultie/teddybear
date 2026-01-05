use std::fmt;

use ssi_json_ld::{
    ChainLoader, ContextLoader, Iri, IriBuf, LoadError, Loader, RemoteDocument, syntax::Parse,
};
use teddybear_common::HttpClient;

pub fn new<T>(remote_context_loader: T) -> impl Loader
where
    T: HttpClient<serde_bytes::ByteBuf>,
{
    ChainLoader::new(
        ContextLoader::default().with_static_loader(),
        HttpLoader(remote_context_loader),
    )
}

struct HttpLoader<T>(T);

impl<T> Loader for HttpLoader<T>
where
    T: HttpClient<serde_bytes::ByteBuf>,
{
    async fn load(&self, url: &Iri) -> Result<RemoteDocument<IriBuf>, LoadError> {
        #[derive(Debug)]
        #[repr(transparent)]
        struct DummyError(String);

        impl fmt::Display for DummyError {
            #[inline]
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }

        impl std::error::Error for DummyError {}

        let url = url.to_owned();

        let response = self
            .0
            .get(url.as_str())
            .await
            .map_err(|e| LoadError::new(url.clone(), DummyError(e.to_string())))?;

        let (document, _) = ssi_json_ld::syntax::Value::parse_slice(&response)
            .map_err(|e| LoadError::new(url.clone(), e))?;

        Ok(RemoteDocument::new(Some(url), None, document))
    }
}
