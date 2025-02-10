use std::{borrow::Cow, collections::BTreeMap};

use json_syntax::Value;
use serde::{Deserialize, Serialize};
use ssi_jwt::{Claim, ClaimSet, InfallibleClaimSet, InvalidClaimValue};

/// Any set of JWT claims.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AnyClaims(BTreeMap<String, Value>);

impl AnyClaims {
    pub fn contains(&self, key: &str) -> bool {
        self.0.contains_key(key)
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.0.get(key)
    }

    pub fn set(&mut self, key: String, value: Value) -> Option<Value> {
        self.0.insert(key, value)
    }

    pub fn remove(&mut self, key: &str) -> Option<Value> {
        self.0.remove(key)
    }
}

impl ClaimSet for AnyClaims {
    fn contains<C: Claim>(&self) -> bool {
        self.contains(C::JWT_CLAIM_NAME)
    }

    fn try_get<C: Claim>(&self) -> Result<Option<Cow<C>>, InvalidClaimValue> {
        self.get(C::JWT_CLAIM_NAME)
            .cloned()
            .map(json_syntax::from_value)
            .transpose()
            .map_err(InvalidClaimValue::new)
    }

    fn try_set<C: Claim>(&mut self, claim: C) -> Result<Result<(), C>, InvalidClaimValue> {
        self.set(
            C::JWT_CLAIM_NAME.to_owned(),
            json_syntax::to_value(claim).map_err(InvalidClaimValue::new)?,
        );
        Ok(Ok(()))
    }

    fn try_remove<C: Claim>(&mut self) -> Result<Option<C>, InvalidClaimValue> {
        self.remove(C::JWT_CLAIM_NAME)
            .map(json_syntax::from_value)
            .transpose()
            .map_err(InvalidClaimValue::new)
    }
}

impl InfallibleClaimSet for AnyClaims {}
