use std::collections::HashMap;

use iref::Iri;
use rdf_types::{TermRef, Triple};
use ssi_json_ld::rdf::DataSet;
use static_iref::iri;

pub struct ValidationRequest<'a> {
    credential_id: Iri<'a>,
    request: Vec<(Iri<'a>, Iri<'a>, TermRef<'a>)>,
}

impl<'a> ValidationRequest<'a> {
    pub fn new(credential_id: Iri<'a>) -> Self {
        Self {
            credential_id,
            request: Vec::new(),
        }
    }

    pub fn validate_custom(
        mut self,
        subject: Iri<'a>,
        predicate: Iri<'a>,
        term: TermRef<'a>,
    ) -> Self {
        self.request.push((subject, predicate, term));
        self
    }

    pub fn validate_issuer(self, issuer: Iri<'a>) -> Self {
        let subject = self.credential_id;
        self.validate_custom(
            subject,
            iri!("https://www.w3.org/2018/credentials#issuer"),
            TermRef::Iri(issuer),
        )
    }

    pub fn validate_type(self, type_: Iri<'a>) -> Self {
        let subject = self.credential_id;
        self.validate_custom(
            subject,
            iri!("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"),
            TermRef::Iri(type_),
        )
    }

    pub fn validate<'b>(
        &self,
        dataset: &QueryableDataset<'b>,
    ) -> Result<(), (Iri<'a>, Iri<'a>, TermRef<'a>, Option<TermRef<'b>>)> {
        for (subject, predicate, expected) in &self.request {
            if let Err(actual) = dataset.validate(*subject, *predicate, *expected) {
                return Err((*subject, *predicate, *expected, actual));
            }
        }

        Ok(())
    }
}

pub struct QueryableDataset<'a> {
    default_graph_triples: HashMap<(Iri<'a>, Iri<'a>), TermRef<'a>>,
}

impl<'a> QueryableDataset<'a> {
    pub fn query(&self, subject: Iri<'_>, predicate: Iri<'_>) -> Option<TermRef<'a>> {
        self.default_graph_triples
            .get(&(subject, predicate))
            .copied()
    }

    pub fn validate(
        &self,
        subject: Iri<'_>,
        predicate: Iri<'_>,
        expected: TermRef<'_>,
    ) -> Result<(), Option<TermRef<'a>>> {
        let Some(current_entry) = self.query(subject, predicate) else {
            return Err(None);
        };

        if current_entry == expected {
            Ok(())
        } else {
            Err(Some(current_entry))
        }
    }
}

impl<'a> From<&'a DataSet> for QueryableDataset<'a> {
    fn from(dataset: &'a DataSet) -> Self {
        // Only one graph is supported.
        let default_graph = dataset.default_graph();

        Self {
            default_graph_triples: default_graph
                .triples()
                .filter_map(|Triple(subject, predicate, object)| {
                    let subject = subject.as_iri()?.as_iri();
                    let predicate = predicate.as_iri();
                    let object = object.as_term_ref();

                    Some(((subject, predicate), object))
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use iref::Iri;
    use rdf_types::{Literal, StringLiteral, Term};
    use serde_json::json;
    use ssi_json_ld::ContextLoader;
    use ssi_ldp::LinkedDataDocument;
    use ssi_vc::Credential;
    use static_iref::iri;

    use crate::query::{QueryableDataset, ValidationRequest};

    #[tokio::test]
    async fn basic_validation() {
        let credential: Credential = serde_json::from_value(json!({
            "@context": [
              "https://www.w3.org/ns/credentials/v2",
              "https://www.w3.org/ns/credentials/examples/v2"
            ],
            "id": "http://university.example/credentials/3732",
            "type": ["VerifiableCredential"],
            "issuer": "https://example.com/issuer/123",
            "validFrom": "2010-01-01T00:00:00Z",
            "credentialSubject": [{
              "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
              "name": "Jayden Doe",
              "spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
            }, {
              "id": "did:example:c276e12ec21ebfeb1f712ebc6f1",
              "name": "Morgan Doe",
              "spouse": "did:example:ebfeb1f712ebc6f1c276e12ec21"
            }]
        }))
        .unwrap();

        let dataset = credential
            .to_dataset_for_signing(None, &mut ContextLoader::default())
            .await
            .unwrap();

        let queryable_dataset = QueryableDataset::try_from(&dataset).unwrap();

        ValidationRequest::new(iri!("http://university.example/credentials/3732"))
            .validate_issuer(Iri::from_str("https://example.com/issuer/123").unwrap())
            .validate_type(
                Iri::from_str("https://www.w3.org/2018/credentials#VerifiableCredential").unwrap(),
            )
            .validate_custom(
                Iri::from_str("did:example:ebfeb1f712ebc6f1c276e12ec21").unwrap(),
                Iri::from_str("https://www.w3.org/ns/credentials/examples#spouse").unwrap(),
                Term::Literal(&Literal::String(StringLiteral::from(String::from(
                    "did:example:c276e12ec21ebfeb1f712ebc6f1",
                )))),
            )
            .validate_custom(
                Iri::from_str("did:example:c276e12ec21ebfeb1f712ebc6f1").unwrap(),
                Iri::from_str("https://www.w3.org/ns/credentials/examples#spouse").unwrap(),
                Term::Literal(&Literal::String(StringLiteral::from(String::from(
                    "did:example:ebfeb1f712ebc6f1c276e12ec21",
                )))),
            )
            .validate(&queryable_dataset)
            .unwrap();
    }
}
