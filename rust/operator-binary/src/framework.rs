// Type-safe wrappers that cannot throw errors
// The point is, to move the validation "upwards".

use std::{fmt::Display, str::FromStr};

// use kvp::label::LABEL_VALUE_MAX_LENGTH;
use snafu::{ResultExt, Snafu, ensure};
use stackable_operator::kvp::LabelValue;
use strum::{EnumDiscriminants, IntoStaticStr};

pub mod builder;
pub mod cluster_resources;
pub mod kvp;
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

// according to RFC 1123
const _OBJECT_NAME_MAX_LENGTH: usize = 253;

// useful?
pub trait HasObjectName {
    fn to_object_name(&self) -> String;
}

pub trait HasNamespace {
    fn to_namespace(&self) -> String;
}

pub trait HasUid {
    fn to_uid(&self) -> String;
}

pub trait IsLabelValue {
    fn to_label_value(&self) -> String;
}

/// max_length must not exceed 63! This cannot be checked at compile time.
macro_rules! attributed_string_type {
    ($name:ident $(, $attribute:tt)*) => {
        /// Bla
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
    (@from_str $name:ident, $s:expr, (max_length = $max_length:literal)) => {
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
    (@trait_impl $name:ident, (max_length = $max_length:literal)) => {
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

// There are compile time checks elsewhere ...
attributed_string_type! {
    AppName,
    (max_length = 54),
    is_valid_label_value
}
attributed_string_type! {
    AppVersion,
    (max_length = 63),
    is_valid_label_value
}
attributed_string_type! {
    ClusterName,
    (max_length = 63),
    is_object_name,
    is_valid_label_value
}
attributed_string_type! {
    ControllerName,
    (max_length = 63),
    is_valid_label_value
}
attributed_string_type! {
    OperatorName,
    (max_length = 63),
    is_valid_label_value
}
attributed_string_type! {
    RoleGroupName,
    (max_length = 63),
    is_object_name,
    is_valid_label_value
}
attributed_string_type! {
    RoleName,
    (max_length = 63),
    is_object_name,
    is_valid_label_value
}

pub fn to_qualified_role_group_name(
    cluster_name: &ClusterName,
    role_name: &RoleName,
    role_group_name: &RoleGroupName,
) -> String {
    // Compile time check
    const _: () = assert!(
        ClusterName::MAX_LENGTH + RoleName::MAX_LENGTH + RoleGroupName::MAX_LENGTH
            <= _OBJECT_NAME_MAX_LENGTH - 3 /* dashes */ - 4, /* digits */
        "The maximum lengths of the cluster name, role name and role group name must be defined so that the combination of these names (including separators and the sequential pod number) is also a valid object name with a maximum of 263 characters (see RFC 1123)"
    );

    format!(
        "{}-{}-{}",
        cluster_name.to_object_name(),
        role_name.to_object_name(),
        role_group_name.to_object_name()
    )
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::{ClusterName, RoleGroupName, RoleName, to_qualified_role_group_name};
    use crate::framework::AppName;

    #[test]
    fn test_object_name_constraints() {
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
        let qualified_role_group_name = to_qualified_role_group_name(
            &ClusterName::from_str("test-cluster").expect("should be a valid cluster name"),
            &RoleName::from_str("data-nodes").expect("should be a valid role name"),
            &RoleGroupName::from_str("ssd-storage").expect("should be a valid role group name"),
        );

        assert_eq!(
            "test-cluster-data-nodes-ssd-storage",
            qualified_role_group_name
        );
    }
}
