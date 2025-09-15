use std::{
    collections::{BTreeMap, HashMap},
    str::FromStr,
};

use serde::{Deserialize, Serialize};
use stackable_operator::{
    config::{
        fragment::{self, FromFragment},
        merge::{Merge, merge},
    },
    k8s_openapi::{DeepMerge, api::core::v1::PodTemplateSpec},
    role_utils::{CommonConfiguration, Role, RoleGroup},
    schemars::JsonSchema,
};

use super::{
    ProductName, RoleBindingName, ServiceAccountName, ServiceName,
    builder::pod::container::EnvVarSet,
};
use crate::framework::{ClusterName, ClusterRoleName};

/// Variant of `stackable_operator::role_utils::GenericProductSpecificCommonConfig` that implements
/// `Merge`
#[derive(Clone, Debug, Default, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct GenericProductSpecificCommonConfig {}

impl Merge for GenericProductSpecificCommonConfig {
    fn merge(&mut self, _defaults: &Self) {}
}

/// Variant of `stackable_operator::role_utils::RoleGroup` that is easier to work with
///
/// Differences are:
/// * `replicas` is non-optional.
/// * `config` is flattened.
/// * The `HashMap` in `env_overrides` is replaced with an `EnvVarSet`.
#[derive(Clone, Debug, PartialEq)]
pub struct RoleGroupConfig<ProductSpecificCommonConfig, T> {
    pub replicas: u16,
    pub config: T,
    pub config_overrides: HashMap<String, HashMap<String, String>>,
    pub env_overrides: EnvVarSet,
    pub cli_overrides: BTreeMap<String, String>,
    pub pod_overrides: PodTemplateSpec,
    // allow(dead_code) is not necessary anymore when moved to operator-rs
    #[allow(dead_code)]
    pub product_specific_common_config: ProductSpecificCommonConfig,
}

impl<ProductSpecificCommonConfig, T> RoleGroupConfig<ProductSpecificCommonConfig, T> {
    pub fn cli_overrides_to_vec(&self) -> Vec<String> {
        self.cli_overrides
            .clone()
            .into_iter()
            .flat_map(|(option, value)| [option, value])
            .collect()
    }
}

/// Variant of `stackable_operator::role_utils::RoleGroup::validate_config` with fixed types
///
/// The `role` parameter takes the `ProductSpecificCommonConfig` into account.
pub fn validate_config<C, ProductSpecificCommonConfig, T, U>(
    role_group: &RoleGroup<T, ProductSpecificCommonConfig>,
    role: &Role<T, U, ProductSpecificCommonConfig>,
    default_config: &T,
) -> Result<C, fragment::ValidationError>
where
    C: FromFragment<Fragment = T>,
    ProductSpecificCommonConfig: Default + JsonSchema + Serialize,
    T: Merge + Clone,
    U: Default + JsonSchema + Serialize,
{
    let mut role_config = role.config.config.clone();
    role_config.merge(default_config);
    let mut rolegroup_config = role_group.config.config.clone();
    rolegroup_config.merge(&role_config);
    fragment::validate(rolegroup_config)
}

/// Merges and validates the `RoleGroup` with the given `role` and `default_config`
pub fn with_validated_config<C, ProductSpecificCommonConfig, T, U>(
    role_group: &RoleGroup<T, ProductSpecificCommonConfig>,
    role: &Role<T, U, ProductSpecificCommonConfig>,
    default_config: &T,
) -> Result<RoleGroup<C, ProductSpecificCommonConfig>, fragment::ValidationError>
where
    C: FromFragment<Fragment = T>,
    ProductSpecificCommonConfig: Clone + Default + JsonSchema + Merge + Serialize,
    T: Clone + Merge,
    U: Default + JsonSchema + Serialize,
{
    let validated_config = validate_config(role_group, role, default_config)?;
    Ok(RoleGroup {
        config: CommonConfiguration {
            config: validated_config,
            config_overrides: merged_config_overrides(
                role.config.config_overrides.clone(),
                role_group.config.config_overrides.clone(),
            ),
            env_overrides: merged_env_overrides(
                role.config.env_overrides.clone(),
                role_group.config.env_overrides.clone(),
            ),
            cli_overrides: merged_cli_overrides(
                role.config.cli_overrides.clone(),
                role_group.config.cli_overrides.clone(),
            ),
            pod_overrides: merged_pod_overrides(
                role.config.pod_overrides.clone(),
                role_group.config.pod_overrides.clone(),
            ),
            product_specific_common_config: merged_product_specific_common_config(
                role.config.product_specific_common_config.clone(),
                role_group.config.product_specific_common_config.clone(),
            ),
        },
        replicas: role_group.replicas,
    })
}

fn merged_config_overrides(
    role_config_overrides: HashMap<String, HashMap<String, String>>,
    role_group_config_overrides: HashMap<String, HashMap<String, String>>,
) -> HashMap<String, HashMap<String, String>> {
    let mut merged_config_overrides = role_config_overrides;

    for (filename, role_group_config_file_overrides) in role_group_config_overrides {
        merged_config_overrides
            .entry(filename)
            .or_default()
            .extend(role_group_config_file_overrides);
    }

    merged_config_overrides
}

fn merged_env_overrides(
    role_env_overrides: HashMap<String, String>,
    role_group_env_overrides: HashMap<String, String>,
) -> HashMap<String, String> {
    let mut merged_env_overrides = role_env_overrides;
    merged_env_overrides.extend(role_group_env_overrides);
    merged_env_overrides
}

fn merged_cli_overrides(
    role_cli_overrides: BTreeMap<String, String>,
    role_group_cli_overrides: BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut merged_cli_overrides = role_cli_overrides;
    merged_cli_overrides.extend(role_group_cli_overrides);
    merged_cli_overrides
}

fn merged_pod_overrides(
    role_pod_overrides: PodTemplateSpec,
    role_group_pod_overrides: PodTemplateSpec,
) -> PodTemplateSpec {
    let mut merged_pod_overrides = role_pod_overrides;
    merged_pod_overrides.merge_from(role_group_pod_overrides);
    merged_pod_overrides
}

fn merged_product_specific_common_config<T>(role_config: T, role_group_config: T) -> T
where
    T: Merge,
{
    merge(role_group_config, &role_config)
}

/// Type-safe names for role resources
pub struct ResourceNames {
    pub cluster_name: ClusterName,
    pub product_name: ProductName,
}

impl ResourceNames {
    pub fn service_account_name(&self) -> ServiceAccountName {
        const SUFFIX: &str = "-serviceaccount";

        // Compile-time check
        const _: () = assert!(
            ClusterName::MAX_LENGTH + SUFFIX.len() <= ServiceAccountName::MAX_LENGTH,
            "The string `<cluster_name>-serviceaccount` must not exceed the limit of ServiceAccount names."
        );

        ServiceAccountName::from_str(&format!("{}{SUFFIX}", self.cluster_name))
            .expect("should be a valid ServiceAccount name")
    }

    pub fn role_binding_name(&self) -> RoleBindingName {
        const SUFFIX: &str = "-rolebinding";

        // Compile-time check
        const _: () = assert!(
            ClusterName::MAX_LENGTH + SUFFIX.len() <= RoleBindingName::MAX_LENGTH,
            "The string `<cluster_name>-rolebinding` must not exceed the limit of RoleBinding names."
        );

        RoleBindingName::from_str(&format!("{}{SUFFIX}", self.cluster_name))
            .expect("should be a valid RoleBinding name")
    }

    pub fn cluster_role_name(&self) -> ClusterRoleName {
        const SUFFIX: &str = "-clusterrole";

        // Compile-time check
        const _: () = assert!(
            ProductName::MAX_LENGTH + SUFFIX.len() <= ClusterRoleName::MAX_LENGTH,
            "The string `<cluster_name>-clusterrole` must not exceed the limit of cluster role names."
        );

        ClusterRoleName::from_str(&format!("{}{SUFFIX}", self.product_name))
            .expect("should be a valid cluster role name")
    }

    pub fn discovery_service_name(&self) -> ServiceName {
        // Compile-time check
        const _: () = assert!(
            ClusterName::MAX_LENGTH <= ServiceName::MAX_LENGTH,
            "The string `<cluster_name>` must not exceed the limit of Service names."
        );

        ServiceName::from_str(self.cluster_name.as_ref()).expect("should be a valid Service name")
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};

    use rstest::*;
    use schemars::JsonSchema;
    use serde::Serialize;
    use stackable_operator::{
        config::{fragment::Fragment, merge::Merge},
        k8s_openapi::api::core::v1::PodTemplateSpec,
        kube::api::ObjectMeta,
        role_utils::{CommonConfiguration, GenericRoleConfig, Role, RoleGroup},
    };

    use super::ResourceNames;
    use crate::framework::{
        ClusterName, ClusterRoleName, ProductName, RoleBindingName, ServiceAccountName,
        ServiceName, role_utils::with_validated_config,
    };

    #[derive(Debug, Fragment, PartialEq)]
    #[fragment_attrs(derive(Clone, Debug, Default, Merge, PartialEq))]
    struct Config {
        property: String,
    }

    impl Config {
        fn new(value: &str) -> Self {
            Self {
                property: value.to_owned(),
            }
        }
    }

    impl ConfigFragment {
        fn new(value: Option<&str>) -> Self {
            Self {
                property: value.map(str::to_owned),
            }
        }
    }

    #[derive(Clone, Debug, Default, JsonSchema, Merge, PartialEq, Serialize)]
    struct ProductCommonConfig {
        property: Option<String>,
    }

    fn new_common_config<T>(
        config: T,
        override_value: Option<&str>,
    ) -> CommonConfiguration<T, ProductCommonConfig> {
        let mut config_file_overrides = HashMap::new();
        let mut env_overrides = HashMap::new();
        let mut cli_overrides = BTreeMap::new();

        if let Some(value) = override_value {
            config_file_overrides.insert("property".to_owned(), value.to_owned());
            env_overrides.insert("PROPERTY".to_owned(), value.to_owned());
            cli_overrides.insert("--property".to_owned(), value.to_owned());
        }

        CommonConfiguration {
            config,
            config_overrides: [("config.file".to_owned(), config_file_overrides)].into(),
            env_overrides,
            cli_overrides,
            pod_overrides: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    name: override_value.map(str::to_owned),
                    ..ObjectMeta::default()
                }),
                ..PodTemplateSpec::default()
            },
            product_specific_common_config: ProductCommonConfig {
                property: override_value.map(str::to_owned),
            },
        }
    }

    #[rstest]
    #[case(
        "role-group",
        Some("role-group"),
        Some("role-group"),
        Some("role"),
        Some("default")
    )]
    #[case(
        "role-group",
        Some("role-group"),
        Some("role-group"),
        Some("role"),
        None
    )]
    #[case(
        "role-group",
        Some("role-group"),
        Some("role-group"),
        None,
        Some("default")
    )]
    #[case("role-group", Some("role-group"), Some("role-group"), None, None)]
    #[case("role", Some("role"), None, Some("role"), Some("default"))]
    #[case("role", Some("role"), None, Some("role"), None)]
    #[case("default", None, None, None, Some("default"))]
    fn test_with_validated_config_and_result_ok(
        #[case] expected_config_value: &str,
        #[case] expected_override_value: Option<&str>,
        #[case] role_group_value: Option<&str>,
        #[case] role_value: Option<&str>,
        #[case] default_value: Option<&str>,
    ) {
        let role_group = RoleGroup {
            config: new_common_config(ConfigFragment::new(role_group_value), role_group_value),
            replicas: Some(3),
        };
        let role = Role::<_, GenericRoleConfig, _> {
            config: new_common_config(ConfigFragment::new(role_value), role_value),
            ..Role::default()
        };
        let default_config = ConfigFragment::new(default_value);

        let result = with_validated_config(&role_group, &role, &default_config);

        assert_eq!(
            Some(RoleGroup {
                config: new_common_config(
                    Config::new(expected_config_value),
                    expected_override_value
                ),
                replicas: Some(3)
            }),
            result.ok()
        )
    }

    #[test]
    fn test_with_validated_config_and_result_err() {
        let role_group = RoleGroup {
            config: new_common_config(ConfigFragment::new(None), None),
            replicas: None,
        };
        let role = Role::<_, GenericRoleConfig, _> {
            config: new_common_config(ConfigFragment::new(None), None),
            ..Role::default()
        };
        let default_config = ConfigFragment::new(None);

        let result: Result<RoleGroup<Config, _>, _> =
            with_validated_config(&role_group, &role, &default_config);

        assert!(result.is_err())
    }

    #[test]
    fn test_resource_names() {
        let resource_names = ResourceNames {
            cluster_name: ClusterName::from_str_unsafe("my-cluster"),
            product_name: ProductName::from_str_unsafe("my-product"),
        };

        assert_eq!(
            ServiceAccountName::from_str_unsafe("my-cluster-serviceaccount"),
            resource_names.service_account_name()
        );
        assert_eq!(
            RoleBindingName::from_str_unsafe("my-cluster-rolebinding"),
            resource_names.role_binding_name()
        );
        assert_eq!(
            ClusterRoleName::from_str_unsafe("my-product-clusterrole"),
            resource_names.cluster_role_name()
        );
        assert_eq!(
            ServiceName::from_str_unsafe("my-cluster"),
            resource_names.discovery_service_name()
        );
    }
}
