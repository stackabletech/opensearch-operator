use std::{borrow::Cow, collections::BTreeMap};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;
use stackable_operator::{
    config::merge::Merge, k8s_openapi::DeepMerge, schemars, utils::crds::raw_object_schema,
};

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
// - Implements Default
// - Implements Merge
// - The JsonPatches variant was removed because it could fail in the build stage.
// - The UserProvided variant also contains a JSON value instead of a string.
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
                let mut merged = base.clone();
                merged.merge_from(patch.clone());
                Cow::Owned(merged)
            }
            Self::UserProvided(content) => Cow::Borrowed(content),
        }
    }
}

impl Default for JsonConfigOverrides {
    fn default() -> Self {
        JsonConfigOverrides::JsonMergePatch(json!({}))
    }
}

impl Merge for JsonConfigOverrides {
    fn merge(&mut self, defaults: &Self) {
        match (&self, defaults) {
            (
                JsonConfigOverrides::JsonMergePatch(patch),
                JsonConfigOverrides::JsonMergePatch(base),
            ) => {
                let mut merged = base.clone();
                merged.merge_from(patch.clone());
                *self = JsonConfigOverrides::JsonMergePatch(merged);
            }
            (
                JsonConfigOverrides::JsonMergePatch(patch),
                JsonConfigOverrides::UserProvided(base),
            ) => {
                let mut merged = base.clone();
                merged.merge_from(patch.clone());
                *self = JsonConfigOverrides::UserProvided(merged);
            }
            (JsonConfigOverrides::UserProvided(patch), _) => {
                *self = JsonConfigOverrides::UserProvided(patch.clone());
            }
        }
    }
}

impl From<KeyValueConfigOverrides> for JsonConfigOverrides {
    fn from(value: KeyValueConfigOverrides) -> Self {
        JsonConfigOverrides::JsonMergePatch(value.overrides.into_iter().collect())
    }
}

/// Combination of [`JsonConfigOverrides`] and [`KeyValueConfigOverrides`]
///
/// Provides a backwards-compatible way to supply config overrides either as key-value pairs or as
/// a JSON value.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(untagged)]
#[schemars(schema_with = "raw_object_schema")]
pub enum JsonOrKeyValueConfigOverrides {
    Json(JsonConfigOverrides),
    KeyValue(KeyValueConfigOverrides),
}

impl Default for JsonOrKeyValueConfigOverrides {
    fn default() -> Self {
        Self::Json(JsonConfigOverrides::default())
    }
}

impl From<JsonOrKeyValueConfigOverrides> for JsonConfigOverrides {
    fn from(value: JsonOrKeyValueConfigOverrides) -> Self {
        match value {
            JsonOrKeyValueConfigOverrides::KeyValue(key_value_config_overrides) => {
                key_value_config_overrides.into()
            }
            JsonOrKeyValueConfigOverrides::Json(json_config_overrides) => json_config_overrides,
        }
    }
}

impl Merge for JsonOrKeyValueConfigOverrides {
    fn merge(&mut self, defaults: &Self) {
        let mut self_json_config_overrides: JsonConfigOverrides = self.clone().into();
        let defaults_json_config_overrides = defaults.clone().into();

        self_json_config_overrides.merge(&defaults_json_config_overrides);

        *self = Self::Json(self_json_config_overrides);
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use stackable_operator::config::merge;

    use super::*;

    #[test]
    fn test_json_config_overrides_apply() {
        let base = json!({
            "keyA": "valueA1",
            "keyB": "valueB1"
        });

        let json_merge_patch = JsonConfigOverrides::JsonMergePatch(json!({
            "keyA": "valueA2"
        }));

        assert_eq!(
            json!({
                "keyA": "valueA2",
                "keyB": "valueB1"
            }),
            json_merge_patch.apply(&base).into_owned()
        );

        let user_provided = JsonConfigOverrides::UserProvided(json!({
            "keyB": "valueB2"
        }));

        assert_eq!(
            json!({
                "keyB": "valueB2",
            }),
            user_provided.apply(&base).into_owned()
        );
    }

    #[test]
    fn test_json_config_overrides_merge() {
        let json_merge_patch = JsonConfigOverrides::JsonMergePatch(json!({
            "keyA": "base A",
            "keyB": "base B"
        }));

        let user_provided = JsonConfigOverrides::UserProvided(json!({
            "keyA": "base A",
            "keyB": "base B"
        }));

        assert_eq!(
            JsonConfigOverrides::JsonMergePatch(json!({
                "keyA": "base A",
                "keyB": "patch B",
                "keyC": "patch C"
            })),
            merge::merge(
                JsonConfigOverrides::JsonMergePatch(json!({
                "keyB": "patch B",
                "keyC": "patch C"
                })),
                &json_merge_patch
            )
        );

        assert_eq!(
            JsonConfigOverrides::UserProvided(json!({
                "keyA": "base A",
                "keyB": "patch B",
                "keyC": "patch C"
            })),
            merge::merge(
                JsonConfigOverrides::JsonMergePatch(json!({
                "keyB": "patch B",
                "keyC": "patch C"
                })),
                &user_provided
            )
        );

        assert_eq!(
            JsonConfigOverrides::UserProvided(json!({
                "keyB": "patch B",
                "keyC": "patch C"
            })),
            merge::merge(
                JsonConfigOverrides::UserProvided(json!({
                "keyB": "patch B",
                "keyC": "patch C"
                })),
                &json_merge_patch
            )
        );

        assert_eq!(
            JsonConfigOverrides::UserProvided(json!({
                "keyB": "patch B",
                "keyC": "patch C"
            })),
            merge::merge(
                JsonConfigOverrides::UserProvided(json!({
                "keyB": "patch B",
                "keyC": "patch C"
                })),
                &user_provided
            )
        );
    }

    #[test]
    fn test_json_config_overrides_from_key_value_config_overrides() {
        let key_value_config_overrides = KeyValueConfigOverrides {
            overrides: [("a".to_owned(), Some("b".to_owned()))].into(),
        };

        let actual_json_config_overrides: JsonConfigOverrides = key_value_config_overrides.into();

        let expected_json_config_overrides = JsonConfigOverrides::JsonMergePatch(json!({"a": "b"}));

        assert_eq!(expected_json_config_overrides, actual_json_config_overrides);
    }
}
