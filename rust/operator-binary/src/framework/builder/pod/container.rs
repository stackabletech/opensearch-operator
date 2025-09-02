use std::{collections::BTreeMap, fmt::Display, str::FromStr};

use snafu::Snafu;
use stackable_operator::{
    builder::pod::container::FieldPathEnvVar,
    k8s_openapi::api::core::v1::{EnvVar, EnvVarSource, ObjectFieldSelector},
};
use strum::{EnumDiscriminants, IntoStaticStr};

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
pub enum Error {
    #[snafu(display(
        "invalid environment variable name: a valid environment variable name must consist only of printable ASCII characters other than '='"
    ))]
    ParseEnvVarName { env_var_name: String },
}

#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EnvVarName(String);

impl EnvVarName {
    pub fn from_str_unsafe(s: &str) -> Self {
        EnvVarName::from_str(s).expect("should be a valid environment variable name")
    }
}

impl Display for EnvVarName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for EnvVarName {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // The length of the environment variable names seems not to be restricted.

        if s.find(|c: char| !c.is_ascii_graphic() || c == '=')
            .is_none()
        {
            Ok(Self(s.to_owned()))
        } else {
            Err(Error::ParseEnvVarName {
                env_var_name: s.to_owned(),
            })
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct EnvVarSet(BTreeMap<EnvVarName, EnvVar>);

impl EnvVarSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, env_var_name: impl Into<EnvVarName>) -> Option<&EnvVar> {
        self.0.get(&env_var_name.into())
    }

    pub fn merge(mut self, mut env_var_set: EnvVarSet) -> Self {
        self.0.append(&mut env_var_set.0);

        self
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
                name: name.to_string(),
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
                name: name.to_string(),
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
