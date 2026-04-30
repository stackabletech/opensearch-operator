use std::{borrow::Cow, collections::BTreeMap};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use stackable_operator::{config::merge::Merge, schemars, utils::crds::raw_object_schema};

// Variant of [`stackable_operator::config_overrides::KeyValueConfigOverrides`] that implements
// Merge
/// Flat key-value overrides for `*.properties`, Hadoop XML, etc.
///
/// This is backwards-compatible with the existing flat key-value YAML format
/// used by `HashMap<String, String>`.
#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, Merge, PartialEq, Serialize)]
pub struct KeyValueConfigOverrides {
    #[serde(flatten)]
    pub overrides: BTreeMap<String, Option<String>>,
}

// Variant of [`stackable_operator::config_overrides::JsonConfigOverrides`] with the following
// changes:
// - It implements Merge.
// - The JsonPatches variant was removed because it could fail at build stage which is not allowed
//   in this operator. Additionally, it does not make sense for `opensearch.yml`.
// - The UserProvided variant also contains JSON value instead of a string.
/// ConfigOverrides that can be applied to a JSON file.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum JsonConfigOverrides {
    /// Can be set to arbitrary YAML content, which is converted to JSON and used as
    /// [RFC 7396](https://datatracker.ietf.org/doc/html/rfc7396) JSON merge patch.
    #[schemars(schema_with = "raw_object_schema")]
    JsonMergePatch(serde_json::Value),

    /// Override the entire config file with the specified JSON value.
    #[schemars(schema_with = "raw_object_schema")]
    UserProvided(serde_json::Value),
}

impl JsonConfigOverrides {
    // Infallible variant of [`stackable_operator::config_overrides::JsonConfigOverrides::apply`]
    pub fn apply(&self, base: &serde_json::Value) -> Cow<'_, serde_json::Value> {
        match self {
            Self::JsonMergePatch(patch) => {
                let mut doc = base.clone();
                json_patch::merge(&mut doc, patch);
                Cow::Owned(doc)
            }
            Self::UserProvided(content) => Cow::Borrowed(content),
        }
    }
}

impl Merge for JsonConfigOverrides {
    fn merge(&mut self, _defaults: &Self) {
        todo!()
    }
}

impl From<KeyValueConfigOverrides> for JsonConfigOverrides {
    fn from(value: KeyValueConfigOverrides) -> Self {
        JsonConfigOverrides::JsonMergePatch(
            value
                .overrides
                .into_iter()
                // .map(|(key, value)| (key.clone(), value.clone()))
                .collect(), // .collect::<serde_json::Map<_, _>>()
                            // .into(),
        )
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn json_config_overrides_from_key_value_config_overrides() {
        let key_value_config_overrides = KeyValueConfigOverrides {
            overrides: [("a".to_owned(), Some("b".to_owned()))].into(),
        };

        let actual_json_config_overrides: JsonConfigOverrides = key_value_config_overrides.into();

        let expected_json_config_overrides = JsonConfigOverrides::JsonMergePatch(json!({"a": "b"}));

        assert_eq!(expected_json_config_overrides, actual_json_config_overrides);
    }
}
