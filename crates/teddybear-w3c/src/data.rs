use std::collections::HashMap;

use itertools::Itertools;
use serde::Serialize;
use ssi_json_ld::{
    BlankIdBuf, ExpandedDocument, Iri, IriBuf, Node, Object, object::node::Properties, syntax,
};
use static_iref::iri;
use tsify::Tsify;

use crate::{
    W3CCredential,
    with_depth::{DepthLimiter, RecursionLimitReached, init_with_depth},
};

const ISSUER_PROPERTY: &Iri = iri!("https://www.w3.org/2018/credentials#issuer");
const CREDENTIAL_SUBJECT_PROPERTY: &Iri =
    iri!("https://www.w3.org/2018/credentials#credentialSubject");

#[derive(Serialize, Tsify)]
#[serde(rename_all = "camelCase")]
pub struct RecognizedCredentialSubject {
    pub id: Option<String>,
    pub types: Vec<String>,
    pub properties: HashMap<syntax::String, syntax::Value>,
}

#[derive(Serialize, Tsify)]
#[serde(rename_all = "camelCase")]
#[tsify(into_wasm_abi)]
pub struct RecognizedW3CCredential {
    pub id: Option<String>,
    pub issuer: String,
    pub types: Vec<String>,
    pub not_after_ts: Option<i64>,
    pub not_before_ts: Option<i64>,
    pub credential_subject: RecognizedCredentialSubject,
}

pub fn objects_to_fields(
    credential: &W3CCredential,
    document: ExpandedDocument,
) -> Option<RecognizedW3CCredential> {
    let main_node = document.main_node()?;

    let (id, types) = node_parts(main_node);

    let issuer = main_node
        .get(&ISSUER_PROPERTY)
        .exactly_one()
        .ok()?
        .as_str()?;

    let credential_subject_node = main_node
        .get(&CREDENTIAL_SUBJECT_PROPERTY)
        .exactly_one()
        .ok()?
        .as_node()?;

    let credential_subject = credential_subject_to_data(credential_subject_node)?;

    let not_before_ts = credential
        .valid_from
        .as_ref()
        .map(|c| c.as_inner().to_chrono_date_time().timestamp());

    let not_after_ts = credential
        .valid_until
        .as_ref()
        .map(|c| c.as_inner().to_chrono_date_time().timestamp());

    Some(RecognizedW3CCredential {
        id,
        not_before_ts,
        not_after_ts,
        issuer: issuer.to_owned(),
        types,
        credential_subject,
    })
}

fn credential_subject_to_data(credential_subject: &Node) -> Option<RecognizedCredentialSubject> {
    let (id, types) = node_parts(credential_subject);

    let properties = properties_to_object(&credential_subject.properties)?;

    Some(RecognizedCredentialSubject {
        id,
        types,
        properties,
    })
}

fn node_parts(node: &Node) -> (Option<String>, Vec<String>) {
    let id = node.id.as_ref().map(|id| id.as_str().to_owned());

    let types = node
        .types
        .iter()
        .flatten()
        .map(|ty| ty.as_str().to_owned())
        .collect();

    (id, types)
}

fn properties_to_object(
    properties: &Properties<IriBuf, BlankIdBuf>,
) -> Option<HashMap<syntax::String, syntax::Value>> {
    // This is a catch-all error type that is used to just stop the process on the first
    // encountered error.
    struct InvalidObject;

    impl From<RecursionLimitReached> for InvalidObject {
        #[inline]
        fn from(_: RecursionLimitReached) -> Self {
            Self
        }
    }

    fn convert_object(
        depth: &mut impl DepthLimiter<Error = InvalidObject>,
        object: &Object,
    ) -> Result<syntax::Value, InvalidObject> {
        depth.with_depth(|depth| {
            Ok(match object {
                Object::Value(value) => match value {
                    ssi_json_ld::Value::Literal(literal, _) => match literal {
                        ssi_json_ld::object::Literal::Null => syntax::Value::Null,
                        ssi_json_ld::object::Literal::Boolean(value) => {
                            syntax::Value::Boolean(*value)
                        }
                        ssi_json_ld::object::Literal::Number(number_buf) => {
                            syntax::Value::Number(number_buf.clone())
                        }
                        ssi_json_ld::object::Literal::String(str) => {
                            syntax::Value::String(str.clone())
                        }
                    },
                    ssi_json_ld::Value::LangString(lang_string) => {
                        let value = lang_string.as_str();
                        syntax::Value::String(value.into())
                    }
                    ssi_json_ld::Value::Json(value) => value.clone(),
                },
                Object::Node(node) => {
                    let properties = convert_properties(depth, &node.properties)?;
                    syntax::Value::Object(properties)
                }
                Object::List(list) => {
                    let values = list
                        .iter()
                        .map(|object| convert_object(depth, object))
                        .try_collect()?;

                    syntax::Value::Array(values)
                }
            })
        })
    }

    fn convert_properties<T: FromIterator<(syntax::String, syntax::Value)>>(
        depth: &mut impl DepthLimiter<Error = InvalidObject>,
        properties: &Properties<IriBuf, BlankIdBuf>,
    ) -> Result<T, InvalidObject> {
        depth.with_depth(|depth| {
            properties
                .iter()
                .map(|(key, value)| {
                    let id = key.as_str().into();

                    let value = if let [object] = value {
                        convert_object(depth, object)?
                    } else {
                        let values = value
                            .iter()
                            .map(|object| convert_object(depth, object))
                            .try_collect()?;

                        syntax::Value::Array(values)
                    };

                    Ok((id, value))
                })
                .try_collect()
        })
    }

    let mut depth = init_with_depth(16);

    convert_properties(&mut depth, properties).ok()
}
