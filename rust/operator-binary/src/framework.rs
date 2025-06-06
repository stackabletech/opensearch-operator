// Type-safe wrappers that cannot throw errors
// The point is, to move the validation "upwards".

use std::{fmt::Display, str::FromStr};

use snafu::{ResultExt, Snafu, ensure};
use stackable_operator::kvp::LabelValue;
use strum::{EnumDiscriminants, IntoStaticStr};

pub mod kvp;

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
pub enum Error {
    #[snafu(display("maximum length exceeded"))]
    LengthExceeded { length: u32, max_length: u32 },

    #[snafu(display("object name not RFC 1123 compliant"))]
    InvalidObjectName {
        source: stackable_operator::validation::Errors,
    },

    #[snafu(display("failed to use as label"))]
    InvalidLabelValue {
        source: stackable_operator::kvp::LabelValueError,
    },
}

pub trait ToObjectName {
    fn to_object_name(&self) -> String;
}

pub trait ToLabelValue {
    fn to_label_value(&self) -> String;
}

macro_rules! object_name {
    ($name:ident, $max_length:literal) => {
        /// Bla
        #[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
        pub struct $name {
            value: String,
            // could be somehow static
            // type arithmetic would be better
            max_length: u32,
        }

        impl Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.value.fmt(f)
            }
        }

        impl ToObjectName for $name {
            fn to_object_name(&self) -> String {
                self.value.clone()
            }
        }

        impl ToLabelValue for $name {
            fn to_label_value(&self) -> String {
                self.value.clone()
            }
        }

        impl FromStr for $name {
            type Err = Error;

            fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
                let length = s.len() as u32;
                ensure!(
                    length < $max_length,
                    LengthExceededSnafu {
                        length,
                        max_length: $max_length
                    }
                );

                stackable_operator::validation::is_rfc_1123_subdomain(s)
                    .context(InvalidObjectNameSnafu)?;

                LabelValue::from_str(s).context(InvalidLabelValueSnafu)?;

                Ok(Self {
                    value: s.to_owned(),
                    max_length: $max_length,
                })
            }
        }
    };
}

object_name!(AppName, 63u32);
object_name!(AppVersion, 63u32);
object_name!(ClusterName, 63u32);
object_name!(ControllerName, 63u32);
object_name!(OperatorName, 63u32);
object_name!(RoleGroupName, 63u32);
object_name!(RoleName, 63u32);
object_name!(QualifiedRoleGroupName, 250u32);

pub fn qualified_role_group_name(
    cluster_name: &ClusterName,
    role_name: &RoleName,
    role_group_name: &RoleGroupName,
) -> QualifiedRoleGroupName {
    // This assertion is already checked when running the unit test below, so it is not expected to
    // fail at runtime of the operator.
    assert!(
        cluster_name.max_length + role_name.max_length + role_group_name.max_length < 250,
        "The maximum lengths of the cluster name, role name and role group name must be defined so that the combination of these names (including separators and the sequential pod number) is also a valid object name with a maximum of 263 characters (see RFC 1123)"
    );

    QualifiedRoleGroupName::from_str(&format!(
        "{}-{}-{}",
        cluster_name.to_object_name(),
        role_name.to_object_name(),
        role_group_name.to_object_name()
    ))
    .expect("")
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::{ClusterName, RoleGroupName, RoleName, qualified_role_group_name};
    use crate::framework::{AppName, ToObjectName};

    #[test]
    fn test_typed_string_constraints() {
        assert!(AppName::from_str("valid-role-group-name").is_ok());
        assert!(AppName::from_str("invalid-character: /").is_err());
        assert!(
            AppName::from_str(
                "too-long-123456789012345678901234567890123456789012345678901234567890"
            )
            .is_err()
        );
    }

    #[test]
    fn test_qualified_role_group_name() {
        let qualified_role_group_name = qualified_role_group_name(
            &ClusterName::from_str("test-cluster").expect("should be a valid cluster name"),
            &RoleName::from_str("data-nodes").expect("should be a valid role name"),
            &RoleGroupName::from_str("ssd-storage").expect("should be a valid role group name"),
        );

        assert_eq!(
            "test-cluster-data-nodes-ssd-storage",
            qualified_role_group_name.to_object_name()
        );
    }
}
