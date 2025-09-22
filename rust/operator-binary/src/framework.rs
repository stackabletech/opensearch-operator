// Type-safe wrappers that cannot throw errors
// The point is, to move the validation "upwards".
// The contents of this module will be moved to operator-rs when stabilized.

use std::{fmt::Display, str::FromStr};

use kvp::label::MAX_LABEL_VALUE_LENGTH;
use snafu::{ResultExt, Snafu, ensure};
use stackable_operator::kvp::LabelValue;
use strum::{EnumDiscriminants, IntoStaticStr};

pub mod builder;
pub mod cluster_resources;
pub mod kvp;
pub mod listener;
pub mod role_group_utils;
pub mod role_utils;

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
pub enum Error {
    #[snafu(display("maximum length exceeded"))]
    LengthExceeded { length: usize, max_length: usize },

    #[snafu(display("object name not RFC 1123 compliant"))]
    InvalidObjectName {
        source: stackable_operator::validation::Errors,
    },

    #[snafu(display("failed to use as label"))]
    InvalidLabelValue {
        source: stackable_operator::kvp::LabelValueError,
    },
}

/// Has a name that can be used as a DNS subdomain name as defined in RFC 1123.
/// Most resource types, e.g. a Pod, require such a compliant name.
pub trait HasObjectName {
    fn to_object_name(&self) -> String;
}

/// Has a namespace
pub trait HasNamespace {
    fn to_namespace(&self) -> String;
}

/// Has a Kubernetes UID
pub trait HasUid {
    fn to_uid(&self) -> String;
}

/// Is a valid label value as defined in RFC 1123.
pub trait IsLabelValue {
    fn to_label_value(&self) -> String;
}

/// Restricted string type with attributes like maximum length.
macro_rules! attributed_string_type {
    ($name:ident, $description:literal, $example:literal $(, $attribute:tt)*) => {
        #[doc = concat!($description, ", e.g. \"", $example, "\"")]
        #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }

        impl FromStr for $name {
            type Err = Error;

            fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {

                $(attributed_string_type!(@from_str $name, s, $attribute);)*

                Ok(Self(s.to_owned()))
            }
        }

        #[cfg(test)]
        impl $name {
            #[allow(dead_code)]
            pub fn from_str_unsafe(s: &str) -> Self {
                FromStr::from_str(s).expect("should be a valid {name}")
            }

            // A dead_code warning is emitted if there is no unit test that calls this function.
            pub fn test_example() {
                Self::from_str_unsafe($example);
            }
        }

        $(attributed_string_type!(@trait_impl $name, $attribute);)*
    };
    (@from_str $name:ident, $s:expr, (max_length = $max_length:expr)) => {
        let length = $s.len() as usize;
        ensure!(
            length <= $name::MAX_LENGTH,
            LengthExceededSnafu {
                length,
                max_length: $name::MAX_LENGTH,
            }
        );
    };
    (@from_str $name:ident, $s:expr, is_object_name) => {
        stackable_operator::validation::is_lowercase_rfc_1123_subdomain($s).context(InvalidObjectNameSnafu)?;
    };
    (@from_str $name:ident, $s:expr, is_valid_label_value) => {
        LabelValue::from_str($s).context(InvalidLabelValueSnafu)?;
    };
    (@trait_impl $name:ident, (max_length = $max_length:expr)) => {
        impl $name {
            // type arithmetic would be better
            pub const MAX_LENGTH: usize = $max_length;
        }
    };
    (@trait_impl $name:ident, is_object_name) => {
        impl HasObjectName for $name {
            fn to_object_name(&self) -> String {
                self.0.clone()
            }
        }
    };
    (@trait_impl $name:ident, is_valid_label_value) => {
        impl IsLabelValue for $name {
            fn to_label_value(&self) -> String {
                self.0.clone()
            }
        }
    };
}

attributed_string_type! {
    ProductName,
    "The name of a product",
    "opensearch",
    // A suffix is added to produce a label value. An according compile-time check ensures that
    // max_length cannot be set higher.
    (max_length = 54),
    is_valid_label_value
}
attributed_string_type! {
    ProductVersion,
    "The version of a product",
    "3.1.0",
    (max_length = MAX_LABEL_VALUE_LENGTH),
    is_valid_label_value
}
attributed_string_type! {
    ClusterName,
    "The name of a cluster/stacklet",
    "my-opensearch-cluster",
    // Suffixes are added to produce a resource names. According compile-time check ensures that
    // max_length cannot be set higher.
    (max_length = 24),
    is_object_name,
    is_valid_label_value
}
attributed_string_type! {
    ControllerName,
    "The name of a controller in an operator",
    "opensearchcluster",
    (max_length = MAX_LABEL_VALUE_LENGTH),
    is_valid_label_value
}
attributed_string_type! {
    OperatorName,
    "The name of an operator",
    "opensearch.stackable.tech",
    (max_length = MAX_LABEL_VALUE_LENGTH),
    is_valid_label_value
}
attributed_string_type! {
    RoleGroupName,
    "The name of a role-group name",
    "cluster-manager",
    (max_length = 16),
    is_object_name,
    is_valid_label_value
}
attributed_string_type! {
    RoleName,
    "The name of a role name",
    "nodes",
    (max_length = 10),
    is_object_name,
    is_valid_label_value
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::{
        ClusterName, ControllerName, OperatorName, ProductVersion, RoleGroupName, RoleName,
    };
    use crate::framework::{HasObjectName, IsLabelValue, ProductName};

    #[test]
    fn test_attributed_string_type_examples() {
        ProductName::test_example();
        ProductVersion::test_example();
        ClusterName::test_example();
        ControllerName::test_example();
        OperatorName::test_example();
        RoleGroupName::test_example();
        RoleName::test_example();
    }

    #[test]
    fn test_attributed_string_type_fmt() {
        assert_eq!(
            "my-cluster-name".to_owned(),
            format!("{}", ClusterName::from_str_unsafe("my-cluster-name"))
        );
    }

    #[test]
    fn test_attributed_string_type_max_length() {
        assert_eq!(24, ClusterName::MAX_LENGTH);

        assert!(ClusterName::from_str(&"a".repeat(ClusterName::MAX_LENGTH)).is_ok());
        assert!(ClusterName::from_str(&"a".repeat(ClusterName::MAX_LENGTH + 1)).is_err());
    }

    #[test]
    fn test_attributed_string_type_is_object_name() {
        assert_eq!(
            "valid-object.name.123",
            ClusterName::from_str_unsafe("valid-object.name.123").to_object_name()
        );
        // A valid object name contains only lowercase characters.
        assert!(ClusterName::from_str("InvalidObjectName").is_err());
    }

    #[test]
    fn test_attributed_string_type_is_valid_label_value() {
        // Use a struct implementing the trait `IsLabelValue` but not `HasObjectName` because
        // object names are proper subsets of label values and the test should not already fail on
        // the object check.

        assert_eq!(
            "valid-label_value.123",
            ProductName::from_str_unsafe("valid-label_value.123").to_label_value()
        );
        // A valid label value must end with an alphanumeric character.
        assert!(ProductName::from_str("invalid-label-value-").is_err());
    }
}
