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

// TODO The maximum length of objects differs.
/// Maximum length of a DNS subdomain name as defined in RFC 1123.
#[allow(dead_code)]
pub const MAX_OBJECT_NAME_LENGTH: usize = 253;

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
    ($name:ident, $description:literal $(, $attribute:tt)*) => {
        #[doc = $description]
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
        stackable_operator::validation::is_rfc_1123_subdomain($s).context(InvalidObjectNameSnafu)?;
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
    "The name of a product, e.g. \"opensearch\"",
    // A suffix is added to produce a label value. An according compile-time check ensures that
    // max_length cannot be set higher.
    (max_length = 54),
    is_valid_label_value
}
attributed_string_type! {
    ProductVersion,
    "The version of a product, e.g. \"3.0.0\"",
    (max_length = MAX_LABEL_VALUE_LENGTH),
    is_valid_label_value
}
attributed_string_type! {
    ClusterName,
    "The name of a cluster/stacklet, e.g. \"my-opensearch-cluster\"",
    // Suffixes are added to produce a resource names. According compile-time check ensures that
    // max_length cannot be set higher.
    (max_length = 24),
    is_object_name,
    is_valid_label_value
}
attributed_string_type! {
    ControllerName,
    "The name of a controller in an operator, e.g. \"opensearchcluster\"",
    (max_length = MAX_LABEL_VALUE_LENGTH),
    is_valid_label_value
}
attributed_string_type! {
    OperatorName,
    "The name of an operator, e.g. \"opensearch.stackable.tech\"",
    (max_length = MAX_LABEL_VALUE_LENGTH),
    is_valid_label_value
}
attributed_string_type! {
    RoleGroupName,
    "The name of a role-group name, e.g. \"cluster-manager\"",
    (max_length = 16),
    is_object_name,
    is_valid_label_value
}
attributed_string_type! {
    RoleName,
    "The name of a role name, e.g. \"nodes\"",
    (max_length = 10),
    is_object_name,
    is_valid_label_value
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::framework::ProductName;

    #[test]
    fn test_object_name_constraints() {
        assert!(ProductName::from_str("valid-role-group-name").is_ok());
        assert!(ProductName::from_str("invalid-character: /").is_err());
        assert!(
            ProductName::from_str(
                "too-long-123456789012345678901234567890123456789012345678901234567890"
            )
            .is_err()
        );
    }
}
