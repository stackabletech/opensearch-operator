use serde::Serialize;
use stackable_operator::{
    config::{
        fragment::{self, FromFragment},
        merge::Merge,
    },
    role_utils::{CommonConfiguration, Role, RoleGroup},
    schemars::JsonSchema,
};

pub fn with_validated_config<C, ProductSpecificCommonConfig, T, U>(
    role_group: &RoleGroup<T, ProductSpecificCommonConfig>,
    role: &Role<T, U>,
    default_config: &T,
) -> Result<RoleGroup<C, ProductSpecificCommonConfig>, fragment::ValidationError>
where
    C: FromFragment<Fragment = T>,
    ProductSpecificCommonConfig: Clone,
    T: Merge + Clone,
    U: Default + JsonSchema + Serialize,
{
    let validated_config = role_group.validate_config(role, default_config)?;
    Ok(RoleGroup {
        config: CommonConfiguration {
            config: validated_config,
            config_overrides: role_group.config.config_overrides.clone(),
            env_overrides: role_group.config.env_overrides.clone(),
            cli_overrides: role_group.config.cli_overrides.clone(),
            pod_overrides: role_group.config.pod_overrides.clone(),
            product_specific_common_config: role_group
                .config
                .product_specific_common_config
                .clone(),
        },
        replicas: role_group.replicas,
    })
}
