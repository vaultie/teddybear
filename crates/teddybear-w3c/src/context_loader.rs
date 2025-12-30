use reqwest::header;
use ssi_json_ld::{
    ChainLoader, ContextLoader, Iri, IriBuf, LoadError, Loader, RemoteDocument, syntax::Parse,
};

pub fn new() -> impl Loader {
    let client = reqwest::Client::builder()
        .build()
        .expect("HTTP client should be available");

    ChainLoader::new(
        ContextLoader::default().with_static_loader(),
        HttpLoader(client),
    )
}

struct HttpLoader(reqwest::Client);

impl Loader for HttpLoader {
    async fn load(&self, url: &Iri) -> Result<RemoteDocument<IriBuf>, LoadError> {
        let url = url.to_owned();

        let response = self
            .0
            .get(url.as_str())
            .header(header::ACCEPT, "application/ld+json")
            .send()
            .await
            .map_err(|e| LoadError::new(url.clone(), e))?;

        match response.error_for_status() {
            Ok(response) => {
                let bytes = response
                    .bytes()
                    .await
                    .map_err(|e| LoadError::new(url.clone(), e))?;

                let (document, _) = ssi_json_ld::syntax::Value::parse_slice(&bytes)
                    .map_err(|e| LoadError::new(url.clone(), e))?;

                Ok(RemoteDocument::new(Some(url), None, document))
            }
            Err(e) => Err(LoadError::new(url, e)),
        }
    }
}
