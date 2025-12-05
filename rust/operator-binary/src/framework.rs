//! Additions to stackable-operator
//!
//! Functions in stackable-operator usually accept generic types like strings and validate the
//! parameters as late as possible. Therefore, nearly all functions have to return a [`Result`] and
//! errors are returned along the call chain. That makes error handling complex because every
//! module re-packages the received error. Also, the validation is repeated if the value is used in
//! different function calls. Sometimes, validation is not necessary if constant values are used,
//! e.g. the name of the operator.
//!
//! The OpenSearch operator uses a different approach. The incoming values are validated as early
//! as possible and wrapped in a fail-safe type. This type is then used along the call chain,
//! validation is not necessary anymore and functions without side effects do not need to return a
//! [`Result`].
//!
//! However, the OpenSearch operator uses stackable-operator and at the interface, the fail-safe
//! types must be unwrapped and the [`Result`] returned by the stackable-operator function must be
//! handled. This is done by calling [`Result::expect`] which requires thorough testing.
//!
//! When the development of the OpenSearch operator has progressed and changes in this module
//! become less frequent, then this module can be incorporated into stackable-operator. The module
//! structure should already resemble the one of stackable-operator.

use std::str::FromStr;

use snafu::Snafu;
use stackable_operator::validation::{RFC_1123_LABEL_MAX_LENGTH, RFC_1123_SUBDOMAIN_MAX_LENGTH};
use strum::{EnumDiscriminants, IntoStaticStr};

pub mod builder;
pub mod cluster_resources;
pub mod kvp;
pub mod product_logging;
pub mod role_group_utils;
pub mod role_utils;

#[derive(Debug, EnumDiscriminants, Snafu)]
#[strum_discriminants(derive(IntoStaticStr))]
pub enum Error {
    #[snafu(display("empty strings are not allowed"))]
    EmptyString {},

    #[snafu(display("minimum length not met"))]
    MinimumLengthNotMet { length: usize, min_length: usize },

    #[snafu(display("maximum length exceeded"))]
    LengthExceeded { length: usize, max_length: usize },

    #[snafu(display("invalid regular expression"))]
    InvalidRegex { source: regex::Error },

    #[snafu(display("regular expression not matched"))]
    RegexNotMatched { value: String, regex: &'static str },

    #[snafu(display("not a valid label value"))]
    InvalidLabelValue {
        source: stackable_operator::kvp::LabelValueError,
    },

    #[snafu(display("not a valid label name as defined in RFC 1035"))]
    InvalidRfc1035LabelName {
        source: stackable_operator::validation::Errors,
    },

    #[snafu(display("not a valid DNS subdomain name as defined in RFC 1123"))]
    InvalidRfc1123DnsSubdomainName {
        source: stackable_operator::validation::Errors,
    },

    #[snafu(display("not a valid label name as defined in RFC 1123"))]
    InvalidRfc1123LabelName {
        source: stackable_operator::validation::Errors,
    },

    #[snafu(display("not a valid UUID"))]
    InvalidUid { source: uuid::Error },
}

/// Maximum length of label values
///
/// Duplicates the private constant [`stackable-operator::kvp::label::value::LABEL_VALUE_MAX_LEN`]
pub const MAX_LABEL_VALUE_LENGTH: usize = 63;

/// Has a non-empty name
///
/// Useful as an object reference; Should not be used to create an object because the name could
/// violate the naming constraints (e.g. maximum length) of the object.
pub trait HasName {
    #[allow(dead_code)]
    fn to_name(&self) -> String;
}

/// Has a Kubernetes UID
pub trait HasUid {
    fn to_uid(&self) -> Uid;
}

/// The name is a valid label value
pub trait NameIsValidLabelValue {
    fn to_label_value(&self) -> String;
}

#[derive(Clone, Copy, Debug)]
pub enum Regex {
    /// There is a regular expression but it is unknown (or too complicated).
    Unknown,

    /// `MatchAll` equals Expression(".*") but can be matched in a const context.
    MatchAll,

    /// There is a regular expression.
    Expression(&'static str),
}

impl Regex {
    pub const fn combine(self, other: Regex) -> Regex {
        match (self, other) {
            (_, Regex::MatchAll) => self,
            (Regex::MatchAll, _) => other,
            _ => Regex::Unknown,
        }
    }
}

/// Restricted string type with attributes like maximum length.
///
/// Fully-qualified types are used to ease the import into other modules.
///
/// # Examples
///
/// ```rust
/// attributed_string_type! {
///     ConfigMapName,
///     "The name of a ConfigMap",
///     "opensearch-nodes-default",
///     is_rfc_1123_dns_subdomain_name
/// }
/// ```
#[macro_export(local_inner_macros)]
macro_rules! attributed_string_type {
    ($name:ident, $description:literal, $example:literal $(, $attribute:tt)*) => {
        #[doc = std::concat!($description, ", e.g. \"", $example, "\"")]
        #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl From<&$name> for String {
            fn from(value: &$name) -> Self {
                value.0.clone()
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl std::str::FromStr for $name {
            type Err = $crate::framework::Error;

            fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
                // ResultExt::context is used on most but not all usages of this macro
                #[allow(unused_imports)]
                use snafu::ResultExt;

                snafu::ensure!(
                    !s.is_empty(),
                    $crate::framework::EmptyStringSnafu {}
                );

                $(attributed_string_type!(@from_str $name, s, $attribute);)*

                Ok(Self(s.to_owned()))
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let string: String = serde::Deserialize::deserialize(deserializer)?;
                $name::from_str(&string).map_err(|err| serde::de::Error::custom(&err))
            }
        }

        impl serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                self.0.serialize(serializer)
            }
        }

        impl stackable_operator::config::merge::Atomic for $name {}

        impl $name {
            pub const MIN_LENGTH: usize = attributed_string_type!(@min_length $($attribute)*);
            pub const MAX_LENGTH: usize = attributed_string_type!(@max_length $($attribute)*);

            /// None if there are restrictions but the regular expression could not be calculated.
            pub const REGEX: $crate::framework::Regex = attributed_string_type!(@regex $($attribute)*);
        }

        // The JsonSchema implementation requires `max_length`.
        impl schemars::JsonSchema for $name {
            fn schema_name() -> std::borrow::Cow<'static, str> {
                std::stringify!($name).into()
            }

            fn json_schema(_generator: &mut schemars::generate::SchemaGenerator) -> schemars::Schema {
                schemars::json_schema!({
                    "type": "string",
                    "minLength": $name::MIN_LENGTH,
                    "maxLength": if $name::MAX_LENGTH != usize::MAX {
                        Some($name::MAX_LENGTH)
                    } else {
                        // Do not set maxLength if it is usize::MAX.
                        None
                    },
                    "pattern": match $name::REGEX {
                        $crate::framework::Regex::Expression(regex) => Some(std::format!("^{regex}$")),
                        _ => None
                    }
                })
            }
        }

        #[cfg(test)]
        impl $name {
            #[allow(dead_code)]
            pub fn from_str_unsafe(s: &str) -> Self {
                std::str::FromStr::from_str(s).expect("should be a valid {name}")
            }

            // A dead_code warning is emitted if there is no unit test that calls this function.
            pub fn test_example() {
                Self::from_str_unsafe($example);
            }
        }

        $(attributed_string_type!(@trait_impl $name, $attribute);)*
    };

    // std::str::FromStr

    (@from_str $name:ident, $s:expr, (min_length = $min_length:expr)) => {
        let length = $s.len() as usize;
        snafu::ensure!(
            length >= $name::MIN_LENGTH,
            $crate::framework::MinimumLengthNotMetSnafu {
                length,
                min_length: $name::MIN_LENGTH,
            }
        );
    };
    (@from_str $name:ident, $s:expr, (max_length = $max_length:expr)) => {
        let length = $s.len() as usize;
        snafu::ensure!(
            length <= $name::MAX_LENGTH,
            $crate::framework::LengthExceededSnafu {
                length,
                max_length: $name::MAX_LENGTH,
            }
        );
    };
    (@from_str $name:ident, $s:expr, (regex = $regex:expr)) => {
        let regex = regex::Regex::new($regex).context($crate::framework::InvalidRegexSnafu)?;
        snafu::ensure!(
            regex.is_match($s),
            $crate::framework::RegexNotMatchedSnafu {
                value: $s,
                regex: $regex
            }
        );
    };
    (@from_str $name:ident, $s:expr, is_rfc_1035_label_name) => {
        stackable_operator::validation::is_lowercase_rfc_1035_label($s).context($crate::framework::InvalidRfc1035LabelNameSnafu)?;
    };
    (@from_str $name:ident, $s:expr, is_rfc_1123_dns_subdomain_name) => {
        stackable_operator::validation::is_lowercase_rfc_1123_subdomain($s).context($crate::framework::InvalidRfc1123DnsSubdomainNameSnafu)?;
    };
    (@from_str $name:ident, $s:expr, is_rfc_1123_label_name) => {
        stackable_operator::validation::is_lowercase_rfc_1123_label($s).context($crate::framework::InvalidRfc1123LabelNameSnafu)?;
    };
    (@from_str $name:ident, $s:expr, is_valid_label_value) => {
        stackable_operator::kvp::LabelValue::from_str($s).context($crate::framework::InvalidLabelValueSnafu)?;
    };
    (@from_str $name:ident, $s:expr, is_uid) => {
        uuid::Uuid::try_parse($s).context($crate::framework::InvalidUidSnafu)?;
    };

    // MIN_LENGTH

    (@min_length) => {
        // The minimum String length is 0.
        0
    };
    (@min_length (min_length = $min_length:expr) $($attribute:tt)*) => {
        $crate::framework::max(
            $min_length,
            attributed_string_type!(@min_length $($attribute)*)
        )
    };
    (@min_length (max_length = $max_length:expr) $($attribute:tt)*) => {
        // max_length has no opinion on the min_length.
        attributed_string_type!(@min_length $($attribute)*)
    };
    (@min_length (regex = $regex:expr) $($attribute:tt)*) => {
        // regex has no influence on the min_length.
        attributed_string_type!(@min_length $($attribute)*)
    };
    (@min_length is_rfc_1035_label_name $($attribute:tt)*) => {
        $crate::framework::max(
            1,
            attributed_string_type!(@min_length $($attribute)*)
        )
    };
    (@min_length is_rfc_1123_dns_subdomain_name $($attribute:tt)*) => {
        $crate::framework::max(
            1,
            attributed_string_type!(@min_length $($attribute)*)
        )
    };
    (@min_length is_rfc_1123_label_name $($attribute:tt)*) => {
        $crate::framework::max(
            1,
            attributed_string_type!(@min_length $($attribute)*)
        )
    };
    (@min_length is_valid_label_value $($attribute:tt)*) => {
        $crate::framework::max(
            1,
            attributed_string_type!(@min_length $($attribute)*)
        )
    };
    (@min_length is_uid $($attribute:tt)*) => {
        $crate::framework::max(
            uuid::fmt::Hyphenated::LENGTH,
            attributed_string_type!(@min_length $($attribute)*)
        )
    };

    // MAX_LENGTH

    (@max_length) => {
        // If there is no other max_length defined, then the upper bound is usize::MAX.
        usize::MAX
    };
    (@max_length (min_length = $min_length:expr) $($attribute:tt)*) => {
        // min_length has no opinion on the max_length.
        attributed_string_type!(@max_length $($attribute)*)
    };
    (@max_length (max_length = $max_length:expr) $($attribute:tt)*) => {
        $crate::framework::min(
            $max_length,
            attributed_string_type!(@max_length $($attribute)*)
        )
    };
    (@max_length (regex = $regex:expr) $($attribute:tt)*) => {
        // regex has no influence on the max_length.
        attributed_string_type!(@max_length $($attribute)*)
    };
    (@max_length is_rfc_1035_label_name $($attribute:tt)*) => {
        $crate::framework::min(
            stackable_operator::validation::RFC_1035_LABEL_MAX_LENGTH,
            attributed_string_type!(@max_length $($attribute)*)
        )
    };
    (@max_length is_rfc_1123_dns_subdomain_name $($attribute:tt)*) => {
        $crate::framework::min(
            stackable_operator::validation::RFC_1123_SUBDOMAIN_MAX_LENGTH,
            attributed_string_type!(@max_length $($attribute)*)
        )
    };
    (@max_length is_rfc_1123_label_name $($attribute:tt)*) => {
        $crate::framework::min(
            stackable_operator::validation::RFC_1123_LABEL_MAX_LENGTH,
            attributed_string_type!(@max_length $($attribute)*)
        )
    };
    (@max_length is_valid_label_value $($attribute:tt)*) => {
        $crate::framework::min(
            $crate::framework::MAX_LABEL_VALUE_LENGTH,
            attributed_string_type!(@max_length $($attribute)*)
        )
    };
    (@max_length is_uid $($attribute:tt)*) => {
        $crate::framework::min(
            uuid::fmt::Hyphenated::LENGTH,
            attributed_string_type!(@max_length $($attribute)*)
        )
    };

    // REGEX

    (@regex) => {
        // Everything is allowed if there is no other regular expression.
        $crate::framework::Regex::MatchAll
    };
    (@regex (min_length = $min_length:expr) $($attribute:tt)*) => {
        // min_length has no influence on the regular expression.
        attributed_string_type!(@regex $($attribute)*)
    };
    (@regex (max_length = $max_length:expr) $($attribute:tt)*) => {
        // max_length has no influence on the regular expression.
        attributed_string_type!(@regex $($attribute)*)
    };
    (@regex (regex = $regex:expr) $($attribute:tt)*) => {
        $crate::framework::Regex::Expression($regex)
            .combine(attributed_string_type!(@regex $($attribute)*))
    };
    (@regex is_rfc_1035_label_name $($attribute:tt)*) => {
        $crate::framework::Regex::Expression(stackable_operator::validation::LOWERCASE_RFC_1035_LABEL_FMT)
            .combine(attributed_string_type!(@regex $($attribute)*))
    };
    (@regex is_rfc_1123_dns_subdomain_name $($attribute:tt)*) => {
        $crate::framework::Regex::Expression(stackable_operator::validation::LOWERCASE_RFC_1123_SUBDOMAIN_FMT)
            .combine(attributed_string_type!(@regex $($attribute)*))
    };
    (@regex is_rfc_1123_label_name $($attribute:tt)*) => {
        $crate::framework::Regex::Expression(stackable_operator::validation::LOWERCASE_RFC_1123_LABEL_FMT)
            .combine(attributed_string_type!(@regex $($attribute)*))
    };
    (@regex is_valid_label_value $($attribute:tt)*) => {
        // regular expression from stackable_operator::kvp::label::LABEL_VALUE_REGEX
        $crate::framework::Regex::Expression("[a-z0-9A-Z]([a-z0-9A-Z-_.]*[a-z0-9A-Z]+)?")
            .combine(attributed_string_type!(@regex $($attribute)*))
    };
    (@regex is_uid $($attribute:tt)*) => {
        $crate::framework::Regex::Expression("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
            .combine(attributed_string_type!(@regex $($attribute)*))
    };

    // additional constants and trait implementations

    (@trait_impl $name:ident, (min_length = $max_length:expr)) => {
    };
    (@trait_impl $name:ident, (max_length = $max_length:expr)) => {
    };
    (@trait_impl $name:ident, (regex = $regex:expr)) => {
    };
    (@trait_impl $name:ident, is_rfc_1035_label_name) => {
        impl $name {
            pub const IS_RFC_1035_LABEL_NAME: bool = true;
            pub const IS_RFC_1123_LABEL_NAME: bool = true;
            pub const IS_RFC_1123_SUBDOMAIN_NAME: bool = true;
        }
    };
    (@trait_impl $name:ident, is_rfc_1123_dns_subdomain_name) => {
        impl $name {
            pub const IS_RFC_1123_SUBDOMAIN_NAME: bool = true;
        }
    };
    (@trait_impl $name:ident, is_rfc_1123_label_name) => {
        impl $name {
            pub const IS_RFC_1123_LABEL_NAME: bool = true;
            pub const IS_RFC_1123_SUBDOMAIN_NAME: bool = true;
        }
    };
    (@trait_impl $name:ident, is_uid) => {
        impl From<uuid::Uuid> for $name {
            fn from(value: uuid::Uuid) -> Self {
                Self(value.to_string())
            }
        }

        impl From<&uuid::Uuid> for $name {
            fn from(value: &uuid::Uuid) -> Self {
                Self(value.to_string())
            }
        }
    };
    (@trait_impl $name:ident, is_valid_label_value) => {
        impl $name {
            pub const IS_VALID_LABEL_VALUE: bool = true;
        }

        impl $crate::framework::NameIsValidLabelValue for $name {
            fn to_label_value(&self) -> String {
                self.0.clone()
            }
        }
    };
}

/// Use [`std::sync::LazyLock`] to define a static "constant" from a string.
///
/// The string is converted into the given type with [`std::str::FromStr::from_str`].
///
/// # Examples
///
/// ```rust
/// constant!(DATA_VOLUME_NAME: VolumeName = "data");
/// constant!(pub CONFIG_VOLUME_NAME: VolumeName = "config");
/// ```
#[macro_export(local_inner_macros)]
macro_rules! constant {
    ($qualifier:vis $name:ident: $type:ident = $value:literal) => {
        $qualifier static $name: std::sync::LazyLock<$type> =
            std::sync::LazyLock::new(|| $type::from_str($value).expect("should be a valid $name"));
    };
}

/// Returns the minimum of the given values.
///
/// As opposed to [`std::cmp::min`], this function can be used at compile-time.
///
/// # Examples
///
/// ```rust
/// assert_eq!(2, min(2, 3));
/// assert_eq!(4, min(5, 4));
/// assert_eq!(1, min(1, 1));
/// ```
pub const fn min(x: usize, y: usize) -> usize {
    if x < y { x } else { y }
}

/// Returns the maximum of the given values.
///
/// As opposed to [`std::cmp::max`], this function can be used at compile-time.
///
/// # Examples
///
/// ```rust
/// assert_eq!(3, max(2, 3));
/// assert_eq!(5, max(5, 4));
/// assert_eq!(1, max(1, 1));
/// ```
pub const fn max(x: usize, y: usize) -> usize {
    if x < y { y } else { x }
}

// Kubernetes (resource) names

attributed_string_type! {
    ConfigMapName,
    "The name of a ConfigMap",
    "opensearch-nodes-default",
    is_rfc_1123_dns_subdomain_name
}
attributed_string_type! {
    ConfigMapKey,
    "The key for a ConfigMap",
    "log4j2.properties",
    (min_length = 1),
    // see https://github.com/kubernetes/kubernetes/blob/v1.34.1/staging/src/k8s.io/apimachinery/pkg/util/validation/validation.go#L435-L451
    (max_length = RFC_1123_SUBDOMAIN_MAX_LENGTH),
    (regex = "[-._a-zA-Z0-9]+")
}
attributed_string_type! {
    ContainerName,
    "The name of a container in a Pod",
    "opensearch",
    is_rfc_1123_label_name
}
attributed_string_type! {
    ClusterRoleName,
    "The name of a ClusterRole",
    "opensearch-clusterrole",
    // On the one hand, ClusterRoles must only contain characters that are allowed for DNS
    // subdomain names, on the other hand, their length does not seem to be restricted – at least
    // on Kind. However, 253 characters are sufficient for the Stackable operators, and to avoid
    // problems on other Kubernetes providers, the length is restricted here.
    is_rfc_1123_dns_subdomain_name
}
attributed_string_type! {
    ListenerName,
    "The name of a Listener",
    "opensearch-nodes-default",
    is_rfc_1123_dns_subdomain_name
}
attributed_string_type! {
    ListenerClassName,
    "The name of a Listener",
    "external-stable",
    is_rfc_1123_dns_subdomain_name
}
attributed_string_type! {
    NamespaceName,
    "The name of a Namespace",
    "stackable-operators",
    is_rfc_1123_label_name,
    is_valid_label_value
}
attributed_string_type! {
    PersistentVolumeClaimName,
    "The name of a PersistentVolumeClaim",
    "config",
    is_rfc_1123_dns_subdomain_name
}
attributed_string_type! {
    RoleBindingName,
    "The name of a RoleBinding",
    "opensearch-rolebinding",
    // On the one hand, RoleBindings must only contain characters that are allowed for DNS
    // subdomain names, on the other hand, their length does not seem to be restricted – at least
    // on Kind. However, 253 characters are sufficient for the Stackable operators, and to avoid
    // problems on other Kubernetes providers, the length is restricted here.
    is_rfc_1123_dns_subdomain_name
}
attributed_string_type! {
    SecretKey,
    "The key for a Secret",
    "accessKey",
    (min_length = 1),
    // see https://github.com/kubernetes/kubernetes/blob/v1.34.1/staging/src/k8s.io/apimachinery/pkg/util/validation/validation.go#L435-L451
    (max_length = RFC_1123_SUBDOMAIN_MAX_LENGTH),
    (regex = "[-._a-zA-Z0-9]+")
}
attributed_string_type! {
    ServiceAccountName,
    "The name of a ServiceAccount",
    "opensearch-serviceaccount",
    is_rfc_1123_dns_subdomain_name
}
attributed_string_type! {
    ServiceName,
    "The name of a Service",
    "opensearch-nodes-default-headless",
    is_rfc_1035_label_name,
    is_valid_label_value
}
attributed_string_type! {
    StatefulSetName,
    "The name of a StatefulSet",
    "opensearch-nodes-default",
    (max_length =
        // see https://github.com/kubernetes/kubernetes/issues/64023
        RFC_1123_LABEL_MAX_LENGTH
            - 1 /* dash */
            - 10 /* digits for the controller-revision-hash label */),
    is_rfc_1123_label_name,
    is_valid_label_value
}
attributed_string_type! {
    Uid,
    "A UID",
    "c27b3971-ca72-42c1-80a4-abdfc1db0ddd",
    is_uid,
    is_valid_label_value
}
attributed_string_type! {
    VolumeName,
    "The name of a Volume",
    "opensearch-nodes-default",
    is_rfc_1123_label_name,
    is_valid_label_value
}

// Operator names

attributed_string_type! {
    ProductName,
    "The name of a product",
    "opensearch",
    // A suffix is added to produce a label value. An according compile-time check ensures that
    // max_length cannot be set higher.
    (max_length = 54),
    is_rfc_1123_dns_subdomain_name,
    is_valid_label_value
}
attributed_string_type! {
    ProductVersion,
    "The version of a product",
    "3.1.0",
    is_valid_label_value
}
attributed_string_type! {
    ClusterName,
    "The name of a cluster/stacklet",
    "my-opensearch-cluster",
    // Suffixes are added to produce resource names. According compile-time checks ensure that
    // max_length cannot be set higher.
    (max_length = 24),
    is_rfc_1035_label_name,
    is_valid_label_value
}
attributed_string_type! {
    ControllerName,
    "The name of a controller in an operator",
    "opensearchcluster",
    is_valid_label_value
}
attributed_string_type! {
    OperatorName,
    "The name of an operator",
    "opensearch.stackable.tech",
    is_valid_label_value
}
attributed_string_type! {
    RoleGroupName,
    "The name of a role-group name",
    "cluster-manager",
    // The role-group name is used to produce resource names. To make sure that all resource names
    // are valid, max_length is restricted. Compile-time checks ensure that max_length cannot be
    // set higher if not other names like the RoleName are set lower accordingly.
    (max_length = 16),
    is_rfc_1123_label_name,
    is_valid_label_value
}
attributed_string_type! {
    RoleName,
    "The name of a role name",
    "nodes",
    // The role name is used to produce resource names. To make sure that all resource names are
    // valid, max_length is restricted. Compile-time checks ensure that max_length cannot be set
    // higher if not other names like the RoleGroupName are set lower accordingly.
    (max_length = 10),
    is_rfc_1123_label_name,
    is_valid_label_value
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use schemars::{JsonSchema, SchemaGenerator};
    use serde_json::{Number, Value, json};
    use uuid::uuid;

    use super::{
        ClusterName, ClusterRoleName, ConfigMapKey, ConfigMapName, ContainerName, ControllerName,
        ErrorDiscriminants, ListenerClassName, ListenerName, NamespaceName, OperatorName,
        PersistentVolumeClaimName, ProductVersion, RoleBindingName, RoleGroupName, RoleName,
        ServiceAccountName, ServiceName, StatefulSetName, Uid, VolumeName,
    };
    use crate::framework::{NameIsValidLabelValue, ProductName};

    #[test]
    fn test_attributed_string_type_examples() {
        ConfigMapName::test_example();
        ConfigMapKey::test_example();
        ContainerName::test_example();
        ClusterRoleName::test_example();
        ListenerName::test_example();
        ListenerClassName::test_example();
        NamespaceName::test_example();
        PersistentVolumeClaimName::test_example();
        RoleBindingName::test_example();
        ServiceAccountName::test_example();
        ServiceName::test_example();
        StatefulSetName::test_example();
        Uid::test_example();
        VolumeName::test_example();

        ProductName::test_example();
        ProductVersion::test_example();
        ClusterName::test_example();
        ControllerName::test_example();
        OperatorName::test_example();
        RoleGroupName::test_example();
        RoleName::test_example();
    }

    attributed_string_type! {
        DisplayFmtTest,
        "Display::fmt test",
        "test"
    }

    #[test]
    fn test_attributed_string_type_display_fmt() {
        type T = DisplayFmtTest;

        assert_eq!("test", format!("{}", T::from_str_unsafe("test")));
    }

    attributed_string_type! {
        StringFromTest,
        "String::from test",
        "test"
    }

    #[test]
    fn test_attributed_string_type_string_from() {
        type T = StringFromTest;

        T::test_example();
        assert_eq!("test", String::from(T::from_str_unsafe("test")));
        assert_eq!("test", String::from(&T::from_str_unsafe("test")));
    }

    attributed_string_type! {
        LengthTest,
        "empty string and max_length test",
        "test",
        (max_length = 4)
    }

    #[test]
    fn test_attributed_string_type_length() {
        type T = LengthTest;

        T::test_example();
        assert_eq!(4, T::MAX_LENGTH);
        assert_eq!(
            Err(ErrorDiscriminants::EmptyString),
            T::from_str("").map_err(ErrorDiscriminants::from)
        );
        assert_eq!(
            Err(ErrorDiscriminants::LengthExceeded),
            T::from_str("testX").map_err(ErrorDiscriminants::from)
        );
    }

    attributed_string_type! {
        JsonSchemaTest,
        "JsonSchemaTest test",
        "test",
        (min_length = 4),
        (max_length = 8),
        (regex = "[est]+")
    }

    #[test]
    fn test_attributed_string_type_json_schema() {
        type T = JsonSchemaTest;

        T::test_example();
        assert_eq!("JsonSchemaTest", JsonSchemaTest::schema_name());
        assert_eq!(
            json!({
                "type": "string",
                "minLength": 4,
                "maxLength": 8,
                "pattern": "^[est]+$",
            }),
            JsonSchemaTest::json_schema(&mut SchemaGenerator::default())
        );
    }

    attributed_string_type! {
        SerializeTest,
        "serde::Serialize test",
        "test"
    }

    #[test]
    fn test_attributed_string_type_serialize() {
        type T = SerializeTest;

        T::test_example();
        assert_eq!(
            "\"test\"".to_owned(),
            serde_json::to_string(&T::from_str_unsafe("test")).expect("should be serializable")
        );
    }

    attributed_string_type! {
        DeserializeTest,
        "serde::Deserialize test",
        "test",
        (max_length = 4),
        is_rfc_1123_label_name
    }

    #[test]
    fn test_attributed_string_type_deserialize() {
        type T = DeserializeTest;

        T::test_example();
        assert_eq!(
            T::from_str_unsafe("test"),
            serde_json::from_value(Value::String("test".to_owned()))
                .expect("should be deserializable")
        );
        assert_eq!(
            Err("empty strings are not allowed".to_owned()),
            serde_json::from_value::<T>(Value::String("".to_owned()))
                .map_err(|err| err.to_string())
        );
        assert_eq!(
            Err("maximum length exceeded".to_owned()),
            serde_json::from_value::<T>(Value::String("testx".to_owned()))
                .map_err(|err| err.to_string())
        );
        assert_eq!(
            Err("not a valid label name as defined in RFC 1123".to_owned()),
            serde_json::from_value::<T>(Value::String("-".to_owned()))
                .map_err(|err| err.to_string())
        );
        assert_eq!(
            Err("invalid type: null, expected a string".to_owned()),
            serde_json::from_value::<T>(Value::Null).map_err(|err| err.to_string())
        );
        assert_eq!(
            Err("invalid type: boolean `true`, expected a string".to_owned()),
            serde_json::from_value::<T>(Value::Bool(true)).map_err(|err| err.to_string())
        );
        assert_eq!(
            Err("invalid type: integer `1`, expected a string".to_owned()),
            serde_json::from_value::<T>(Value::Number(
                Number::from_i128(1).expect("should be a valid number")
            ))
            .map_err(|err| err.to_string())
        );
        assert_eq!(
            Err("invalid type: sequence, expected a string".to_owned()),
            serde_json::from_value::<T>(Value::Array(vec![])).map_err(|err| err.to_string())
        );
        assert_eq!(
            Err("invalid type: map, expected a string".to_owned()),
            serde_json::from_value::<T>(Value::Object(serde_json::Map::new()))
                .map_err(|err| err.to_string())
        );
    }

    attributed_string_type! {
        IsRfc1035LabelNameTest,
        "is_rfc_1035_label_name test",
        "a-b",
        is_rfc_1035_label_name
    }

    #[test]
    fn test_attributed_string_type_is_rfc_1035_label_name() {
        type T = IsRfc1035LabelNameTest;

        let _ = T::IS_RFC_1035_LABEL_NAME;
        let _ = T::IS_RFC_1123_LABEL_NAME;
        let _ = T::IS_RFC_1123_SUBDOMAIN_NAME;

        T::test_example();
        assert_eq!(
            Err(ErrorDiscriminants::InvalidRfc1035LabelName),
            T::from_str("A").map_err(ErrorDiscriminants::from)
        );
    }

    attributed_string_type! {
        IsRfc1123DnsSubdomainNameTest,
        "is_rfc_1123_dns_subdomain_name test",
        "a-b.c",
        is_rfc_1123_dns_subdomain_name
    }

    #[test]
    fn test_attributed_string_type_is_rfc_1123_dns_subdomain_name() {
        type T = IsRfc1123DnsSubdomainNameTest;

        let _ = T::IS_RFC_1123_SUBDOMAIN_NAME;

        T::test_example();
        assert_eq!(
            Err(ErrorDiscriminants::InvalidRfc1123DnsSubdomainName),
            T::from_str("A").map_err(ErrorDiscriminants::from)
        );
    }

    attributed_string_type! {
        IsRfc1123LabelNameTest,
        "is_rfc_1123_label_name test",
        "1-a",
        is_rfc_1123_label_name
    }

    #[test]
    fn test_attributed_string_type_is_rfc_1123_label_name() {
        type T = IsRfc1123LabelNameTest;

        let _ = T::IS_RFC_1123_LABEL_NAME;
        let _ = T::IS_RFC_1123_SUBDOMAIN_NAME;

        T::test_example();
        assert_eq!(
            Err(ErrorDiscriminants::InvalidRfc1123LabelName),
            T::from_str("A").map_err(ErrorDiscriminants::from)
        );
    }

    attributed_string_type! {
        IsValidLabelValueTest,
        "is_valid_label_value test",
        "a-_.1",
        is_valid_label_value
    }

    #[test]
    fn test_attributed_string_type_is_valid_label_value() {
        type T = IsValidLabelValueTest;

        let _ = T::IS_VALID_LABEL_VALUE;

        T::test_example();
        assert_eq!(
            Err(ErrorDiscriminants::InvalidLabelValue),
            T::from_str("invalid label value").map_err(ErrorDiscriminants::from)
        );
        assert_eq!(
            "label-value",
            T::from_str_unsafe("label-value").to_label_value()
        );
    }

    attributed_string_type! {
        IsUidTest,
        "is_uid test",
        "c27b3971-ca72-42c1-80a4-abdfc1db0ddd",
        is_uid
    }

    #[test]
    fn test_attributed_string_type_is_uid() {
        type T = IsUidTest;

        T::test_example();
        assert_eq!(
            Err(ErrorDiscriminants::InvalidUid),
            T::from_str("invalid UID").map_err(ErrorDiscriminants::from)
        );
        assert_eq!(
            "c27b3971-ca72-42c1-80a4-abdfc1db0ddd",
            T::from(uuid!("c27b3971-ca72-42c1-80a4-abdfc1db0ddd")).to_string()
        );
        assert_eq!(
            "c27b3971-ca72-42c1-80a4-abdfc1db0ddd",
            T::from(&uuid!("c27b3971-ca72-42c1-80a4-abdfc1db0ddd")).to_string()
        );
    }
}
