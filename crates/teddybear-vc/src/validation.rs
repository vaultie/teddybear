use jsonschema::JSONSchema;
use serde::{de, Deserialize, Deserializer};
use serde_json::Value;
use serde_json_path::JsonPath;

#[derive(Deserialize)]
pub enum ProofType {
    Ed25519Signature2020,
}

#[derive(Deserialize)]
pub enum Format {
    #[serde(rename = "ldp_vc")]
    VerifiableCredential { proof_type: Vec<ProofType> },

    #[serde(rename = "ldp_vp")]
    VerifiablePresentation { proof_type: Vec<ProofType> },
}

#[derive(Deserialize)]
pub struct Constraint {
    pub path: [JsonPath; 1],

    #[serde(default)]
    pub filter: Option<WrappedJSONSchema>,
}

impl Constraint {
    pub fn validate(&self, object: &Value) -> bool {
        let Ok(query_result) = self.path[0].query(object).exactly_one() else {
            return false;
        };

        if let Some(filter) = self.filter.as_ref() {
            return filter.0.is_valid(query_result);
        }

        true
    }
}

#[derive(Deserialize)]
pub struct WrappedJSONSchema(#[serde(deserialize_with = "deserialize_json_schema")] JSONSchema);

fn deserialize_json_schema<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<JSONSchema, D::Error> {
    let raw_value = Value::deserialize(deserializer)?;

    JSONSchema::options()
        .should_ignore_unknown_formats(false)
        .should_validate_formats(true)
        .compile(&raw_value)
        .map_err(|_| de::Error::invalid_value(de::Unexpected::Other("JSON value"), &"JSON schema"))
}

#[derive(Deserialize)]
pub struct Constraints {
    pub fields: Vec<Constraint>,
}

#[derive(Deserialize)]
pub struct InputDescriptor {
    pub format: Format,
    pub constraints: Constraints,
}

#[derive(Deserialize)]
pub struct PresentationDefinition {
    pub id: String,
    pub input_descriptors: Vec<InputDescriptor>,
}

impl PresentationDefinition {
    pub fn validate(&self, object: &Value) -> bool {
        for constraint in self
            .input_descriptors
            .iter()
            .flat_map(|val| &val.constraints.fields)
        {
            if !constraint.validate(object) {
                return false;
            }
        }

        true
    }
}
