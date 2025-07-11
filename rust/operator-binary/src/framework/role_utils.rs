use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};
use stackable_operator::{
    config::{
        fragment::{self, FromFragment},
        merge::Merge,
    },
    k8s_openapi::api::core::v1::PodTemplateSpec,
    role_utils::{CommonConfiguration, Role, RoleGroup},
    schemars::JsonSchema,
};

use super::ProductName;
use crate::framework::{ClusterName, MAX_OBJECT_NAME_LENGTH, kvp::label::MAX_LABEL_VALUE_LENGTH};

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct GenericProductSpecificCommonConfig {}

impl Merge for GenericProductSpecificCommonConfig {
    fn merge(&mut self, _defaults: &Self) {}
}

// much better to work with than RoleGroup
#[derive(Clone, Debug, PartialEq)]
pub struct RoleGroupConfig<ProductSpecificCommonConfig, T> {
    pub replicas: u16,
    pub config: T,
    pub config_overrides: HashMap<String, HashMap<String, String>>,
    pub env_overrides: HashMap<String, String>,
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

impl<ProductSpecificCommonConfig, T> From<RoleGroup<T, ProductSpecificCommonConfig>>
    for RoleGroupConfig<ProductSpecificCommonConfig, T>
{
    fn from(value: RoleGroup<T, ProductSpecificCommonConfig>) -> Self {
        RoleGroupConfig {
            // Kubernetes defaults to 1 if not set
            replicas: value.replicas.unwrap_or(1),
            config: value.config.config,
            config_overrides: value.config.config_overrides,
            env_overrides: value.config.env_overrides,
            cli_overrides: value.config.cli_overrides,
            pod_overrides: value.config.pod_overrides,
            product_specific_common_config: value.config.product_specific_common_config,
        }
    }
}

// RoleGroup::validate_config with fixed types
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

// also useful for operators which use the product config
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
    let mut merged_pod_overrides = role_group_pod_overrides;
    merged_pod_overrides.merge(&role_pod_overrides);
    merged_pod_overrides
}

fn merged_product_specific_common_config<T>(role_config: T, role_group_config: T) -> T
where
    T: Merge,
{
    let mut merged_config = role_group_config;
    merged_config.merge(&role_config);
    merged_config
}

pub struct ResourceNames {
    pub cluster_name: ClusterName,
    pub product_name: ProductName,
}

impl ResourceNames {
    pub fn service_account_name(&self) -> String {
        const SUFFIX: &str = "-serviceaccount";

        // Compile-time check
        const _: () = assert!(
            ClusterName::MAX_LENGTH + SUFFIX.len() <= MAX_OBJECT_NAME_LENGTH,
            "The ServiceAccount name `<cluster_name>-serviceaccount` must not exceed 253 characters."
        );

        format!("{}{SUFFIX}", self.cluster_name)
    }

    pub fn role_binding_name(&self) -> String {
        const SUFFIX: &str = "-rolebinding";

        // No compile-time check, because RoleBinding names do not seem to be restricted.

        format!("{}{SUFFIX}", self.cluster_name)
    }

    pub fn cluster_role_name(&self) -> String {
        const SUFFIX: &str = "-clusterrole";

        // No compile-time check, because ClusterRole names do not seem to be restricted.

        format!("{}{SUFFIX}", self.product_name)
    }

    pub fn discovery_service_name(&self) -> String {
        // Compile-time check
        const _: () = assert!(
            ClusterName::MAX_LENGTH <= MAX_LABEL_VALUE_LENGTH,
            "The Service name `<cluster_name>` must not exceed 63 characters."
        );

        format!("{}", self.cluster_name)
    }
}
