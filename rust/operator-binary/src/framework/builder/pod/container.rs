use std::collections::BTreeMap;

use stackable_operator::{
    builder::pod::container::FieldPathEnvVar,
    k8s_openapi::api::core::v1::{EnvVar, EnvVarSource, ObjectFieldSelector},
};

// TODO Use validated type
type EnvVarName = String;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct EnvVarSet(BTreeMap<EnvVarName, EnvVar>);

impl EnvVarSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_values<I, K, V>(self, env_vars: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<EnvVarName>,
        V: Into<String>,
    {
        env_vars
            .into_iter()
            .fold(self, |extended_env_vars, (name, value)| {
                extended_env_vars.with_value(name, value)
            })
    }

    pub fn with_value(mut self, name: impl Into<EnvVarName>, value: impl Into<String>) -> Self {
        let name: EnvVarName = name.into();

        self.0.insert(
            name.clone(),
            EnvVar {
                name,
                value: Some(value.into()),
                value_from: None,
            },
        );

        self
    }

    pub fn with_field_path(
        mut self,
        name: impl Into<EnvVarName>,
        field_path: FieldPathEnvVar,
    ) -> Self {
        let name: EnvVarName = name.into();

        self.0.insert(
            name.clone(),
            EnvVar {
                name,
                value: None,
                value_from: Some(EnvVarSource {
                    field_ref: Some(ObjectFieldSelector {
                        field_path: field_path.to_string(),
                        ..ObjectFieldSelector::default()
                    }),
                    ..EnvVarSource::default()
                }),
            },
        );

        self
    }
}

impl From<EnvVarSet> for Vec<EnvVar> {
    fn from(value: EnvVarSet) -> Self {
        value.0.values().cloned().collect()
    }
}
