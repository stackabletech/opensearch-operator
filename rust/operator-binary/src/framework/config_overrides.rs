use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use stackable_operator::{config::merge::Merge, schemars};

/// Mergeable variant of [`stackable_operator::config_overrides::KeyValueConfigOverrides`]
#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, Merge, PartialEq, Serialize)]
pub struct KeyValueConfigOverrides {
    #[serde(flatten)]
    pub overrides: BTreeMap<String, Option<String>>,
}
