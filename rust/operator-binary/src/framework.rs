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

use std::{fmt::Display, str::FromStr};

use snafu::{ResultExt, Snafu, ensure};
use stackable_operator::kvp::LabelValue;
use strum::{EnumDiscriminants, IntoStaticStr};
use uuid::Uuid;

pub mod builder;
pub mod cluster_resources;
pub mod kvp;
pub mod role_group_utils;
pub mod role_utils;

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
pub enum Error {
    #[snafu(display("empty strings are not allowed"))]
    EmptyString {},

    #[snafu(display("maximum length exceeded"))]
    LengthExceeded { length: usize, max_length: usize },

    #[snafu(display("not a valid label value"))]
    InvalidLabelValue {
        source: stackable_operator::kvp::LabelValueError,
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

/// Maximum length of DNS subdomain names as defined in RFC 1123.
///
/// Duplicates the private constant
/// [`stackable-operator::validation::RFC_1123_SUBDOMAIN_MAX_LENGTH`]
pub const MAX_RFC_1123_DNS_SUBDOMAIN_NAME_LENGTH: usize = 253;

/// Maximum length of label names as defined in RFC 1123.
///
/// Duplicates the private constant [`stackable-operator::validation::RFC_1123_LABEL_MAX_LENGTH`]
pub const MAX_RFC_1123_LABEL_NAME_LENGTH: usize = 63;

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

        impl FromStr for $name {
            type Err = Error;

            fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {

                ensure!(
                    !s.is_empty(),
                    EmptyStringSnafu {}
                );

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
    (@from_str $name:ident, $s:expr, is_rfc_1123_dns_subdomain_name) => {
        stackable_operator::validation::is_rfc_1123_subdomain($s).context(InvalidRfc1123DnsSubdomainNameSnafu)?;
    };
    (@from_str $name:ident, $s:expr, is_rfc_1123_label_name) => {
        stackable_operator::validation::is_rfc_1123_label($s).context(InvalidRfc1123LabelNameSnafu)?;
    };
    (@from_str $name:ident, $s:expr, is_valid_label_value) => {
        LabelValue::from_str($s).context(InvalidLabelValueSnafu)?;
    };
    (@from_str $name:ident, $s:expr, is_uid) => {
        Uuid::try_parse($s).context(InvalidUidSnafu)?;
    };
    (@trait_impl $name:ident, (max_length = $max_length:expr)) => {
        impl $name {
            // type arithmetic would be better
            pub const MAX_LENGTH: usize = $max_length;
        }
    };
    (@trait_impl $name:ident, is_rfc_1123_dns_subdomain_name) => {
    };
    (@trait_impl $name:ident, is_rfc_1123_label_name) => {
    };
    (@trait_impl $name:ident, is_uid) => {
        impl From<Uuid> for $name {
            fn from(value: Uuid) -> Self {
                Self(value.to_string())
            }
        }

        impl From<&Uuid> for $name {
            fn from(value: &Uuid) -> Self {
                Self(value.to_string())
            }
        }
    };
    (@trait_impl $name:ident, is_valid_label_value) => {
        impl NameIsValidLabelValue for $name {
            fn to_label_value(&self) -> String {
                self.0.clone()
            }
        }
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

// Kubernetes (resource) names

attributed_string_type! {
    ConfigMapName,
    "The name of a ConfigMap",
    "opensearch-nodes-default",
    (max_length = MAX_RFC_1123_DNS_SUBDOMAIN_NAME_LENGTH),
    is_rfc_1123_dns_subdomain_name
}
attributed_string_type! {
    ClusterRoleName,
    "The name of a ClusterRole",
    "opensearch-clusterrole",
    // On the one hand, ClusterRoles must only contain characters that are allowed for DNS
    // subdomain names, on the other hand, their length does not seem to be restricted – at least
    // on Kind. However, 253 characters are sufficient for the Stackable operators, and to avoid
    // problems on other Kubernetes providers, the length is restricted here.
    (max_length = MAX_RFC_1123_DNS_SUBDOMAIN_NAME_LENGTH),
    is_rfc_1123_dns_subdomain_name
}
attributed_string_type! {
    ListenerName,
    "The name of a Listener",
    "opensearch-nodes-default",
    (max_length = MAX_RFC_1123_DNS_SUBDOMAIN_NAME_LENGTH),
    is_rfc_1123_dns_subdomain_name
}
attributed_string_type! {
    ListenerClassName,
    "The name of a Listener",
    "external-stable",
    (max_length = MAX_RFC_1123_DNS_SUBDOMAIN_NAME_LENGTH),
    is_rfc_1123_dns_subdomain_name
}
attributed_string_type! {
    NamespaceName,
    "The name of a Namespace",
    "stackable-operators",
    (max_length = min(MAX_RFC_1123_LABEL_NAME_LENGTH, MAX_LABEL_VALUE_LENGTH)),
    is_rfc_1123_label_name,
    is_valid_label_value
}
attributed_string_type! {
    PersistentVolumeClaimName,
    "The name of a PersistentVolumeClaim",
    "config",
    (max_length = MAX_RFC_1123_DNS_SUBDOMAIN_NAME_LENGTH),
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
    (max_length = MAX_RFC_1123_DNS_SUBDOMAIN_NAME_LENGTH),
    is_rfc_1123_dns_subdomain_name
}
attributed_string_type! {
    ServiceAccountName,
    "The name of a ServiceAccount",
    "opensearch-serviceaccount",
    (max_length = MAX_RFC_1123_DNS_SUBDOMAIN_NAME_LENGTH),
    is_rfc_1123_dns_subdomain_name
}
attributed_string_type! {
    ServiceName,
    "The name of a Service",
    "opensearch-nodes-default-headless",
    (max_length = min(MAX_RFC_1123_LABEL_NAME_LENGTH, MAX_LABEL_VALUE_LENGTH)),
    is_rfc_1123_label_name,
    is_valid_label_value
}
attributed_string_type! {
    StatefulSetName,
    "The name of a StatefulSet",
    "opensearch-nodes-default",
    (max_length = min(MAX_RFC_1123_LABEL_NAME_LENGTH, MAX_LABEL_VALUE_LENGTH)),
    is_rfc_1123_label_name,
    is_valid_label_value
}
attributed_string_type! {
    Uid,
    "A UID",
    "c27b3971-ca72-42c1-80a4-abdfc1db0ddd",
    (max_length = min(uuid::fmt::Hyphenated::LENGTH, MAX_LABEL_VALUE_LENGTH)),
    is_uid,
    is_valid_label_value
}
attributed_string_type! {
    VolumeName,
    "The name of a Volume",
    "opensearch-nodes-default",
    (max_length = min(MAX_RFC_1123_LABEL_NAME_LENGTH, MAX_LABEL_VALUE_LENGTH)),
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
    (max_length = min(54, MAX_LABEL_VALUE_LENGTH)),
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
    (max_length = min(24, MAX_LABEL_VALUE_LENGTH)),
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
    // The role-group name is used to produce resource names. To make sure that all resource names
    // are valid, max_length is restricted. Compile-time checks ensure that max_length cannot be
    // set higher if not other names like the RoleName are set lower accordingly.
    (max_length = min(16, MAX_LABEL_VALUE_LENGTH)),
    is_valid_label_value
}
attributed_string_type! {
    RoleName,
    "The name of a role name",
    "nodes",
    // The role name is used to produce resource names. To make sure that all resource names are
    // valid, max_length is restricted. Compile-time checks ensure that max_length cannot be set
    // higher if not other names like the RoleGroupName are set lower accordingly.
    (max_length = min(10, MAX_LABEL_VALUE_LENGTH)),
    is_valid_label_value
}

#[cfg(test)]
mod tests {
    use std::{fmt::Display, str::FromStr};

    use snafu::{ResultExt, ensure};
    use uuid::{Uuid, uuid};

    use super::{
        ClusterName, ClusterRoleName, ConfigMapName, ControllerName, EmptyStringSnafu, Error,
        ErrorDiscriminants, InvalidLabelValueSnafu, InvalidRfc1123DnsSubdomainNameSnafu,
        InvalidRfc1123LabelNameSnafu, InvalidUidSnafu, LabelValue, LengthExceededSnafu,
        NamespaceName, OperatorName, PersistentVolumeClaimName, ProductVersion, RoleBindingName,
        RoleGroupName, RoleName, ServiceAccountName, ServiceName, StatefulSetName, Uid, VolumeName,
    };
    use crate::framework::{NameIsValidLabelValue, ProductName};

    #[test]
    fn test_attributed_string_type_examples() {
        ConfigMapName::test_example();
        ClusterRoleName::test_example();
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
        IsRfc1123DnsSubdomainNameTest,
        "is_rfc_1123_dns_subdomain_name test",
        "a-b.c",
        is_rfc_1123_dns_subdomain_name
    }

    #[test]
    fn test_attributed_string_type_is_rfc_1123_dns_subdomain_name() {
        type T = IsRfc1123DnsSubdomainNameTest;

        T::test_example();
        assert_eq!(
            Err(ErrorDiscriminants::InvalidRfc1123DnsSubdomainName),
            T::from_str("A").map_err(ErrorDiscriminants::from)
        );
    }

    attributed_string_type! {
        IsRfc1123LabelNameTest,
        "is_rfc_1123_label_name test",
        "a-b",
        is_rfc_1123_label_name
    }

    #[test]
    fn test_attributed_string_type_is_rfc_1123_label_name() {
        type T = IsRfc1123LabelNameTest;

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
