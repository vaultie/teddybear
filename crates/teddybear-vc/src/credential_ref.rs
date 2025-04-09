use std::{borrow::Cow, hash::Hash};

use serde::Serialize;
use ssi_json_ld::{
    Expandable, JsonLdNodeObject, JsonLdObject, JsonLdTypes, Loader,
    json_ld::rdf_types::{Interpretation, VocabularyMut},
    syntax::Context,
};
use ssi_rdf::{LdEnvironment, LinkedDataResource, LinkedDataSubject};

#[repr(transparent)]
#[derive(Serialize)]
pub struct CredentialRef<'a, T>(pub &'a T);

impl<T> JsonLdObject for CredentialRef<'_, T>
where
    T: JsonLdObject,
{
    fn json_ld_context(&self) -> Option<Cow<Context>> {
        self.0.json_ld_context()
    }
}

impl<T> JsonLdNodeObject for CredentialRef<'_, T>
where
    T: JsonLdNodeObject,
{
    fn json_ld_type(&self) -> JsonLdTypes {
        self.0.json_ld_type()
    }
}

impl<T> Expandable for CredentialRef<'_, T>
where
    T: Expandable,
{
    type Error = T::Error;

    type Expanded<I: Interpretation, V: VocabularyMut>
        = T::Expanded<I, V>
    where
        V::Iri: LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
        V::BlankId: LinkedDataResource<I, V> + LinkedDataSubject<I, V>;

    async fn expand_with<I, V>(
        &self,
        ld: &mut LdEnvironment<V, I>,
        loader: &impl Loader,
    ) -> Result<Self::Expanded<I, V>, Self::Error>
    where
        I: Interpretation,
        V: VocabularyMut,
        V::Iri: Clone + Eq + Hash + LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
        V::BlankId: Clone + Eq + Hash + LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
    {
        self.0.expand_with(ld, loader).await
    }
}
