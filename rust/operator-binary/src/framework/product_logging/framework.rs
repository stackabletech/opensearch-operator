use std::{fmt::Display, str::FromStr};

use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    builder::pod::{container::FieldPathEnvVar, resources::ResourceRequirementsBuilder},
    commons::product_image_selection::ResolvedProductImage,
    k8s_openapi::api::core::v1::{Container, VolumeMount},
    product_logging::spec::{
        AppenderConfig, AutomaticContainerLogConfig, ConfigMapLogConfig, ContainerLogConfigChoice,
        CustomContainerLogConfig, LogLevel, Logging,
    },
};
use strum::{EnumDiscriminants, IntoStaticStr};

use crate::framework::{
    ClusterName, ConfigMapName, ContainerName, RoleGroupName, RoleName, VolumeName,
    builder::pod::container::{EnvVarName, EnvVarSet, new_container_builder},
};

const STACKABLE_LOG_DIR: &str = "/stackable/log";
const VECTOR_CONFIG_FILE: &str = "vector.yaml";

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
pub enum Error {
    #[snafu(display("failed to get the container log configuration"))]
    GetContainerLogConfiguration { container: String },

    #[snafu(display("failed to parse the container name"))]
    ParseContainerName { source: crate::framework::Error },
}

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Clone, Debug, PartialEq)]
pub enum ValidatedContainerLogConfigChoice {
    Automatic(AutomaticContainerLogConfig),
    Custom(ConfigMapName),
}

#[derive(Clone, Debug, PartialEq)]
pub struct VectorContainerLogConfig {
    pub log_config: ValidatedContainerLogConfigChoice,
    pub vector_aggregator_config_map_name: ConfigMapName,
}

pub fn validate_logging_configuration_for_container<T>(
    logging: &Logging<T>,
    container: T,
) -> Result<ValidatedContainerLogConfigChoice>
where
    T: Clone + Display + Ord,
{
    let container_log_config_choice = logging
        .containers
        .get(&container)
        .and_then(|container_log_config| container_log_config.choice.as_ref())
        // This should never happen because a default configuration should have been set in
        // `v1alpha1::OpenSearchConfig` for all containers.
        .context(GetContainerLogConfigurationSnafu {
            container: container.to_string(),
        })?;

    let validated_container_log_config_choice = match container_log_config_choice {
        ContainerLogConfigChoice::Custom(CustomContainerLogConfig {
            custom: ConfigMapLogConfig { config_map },
        }) => ValidatedContainerLogConfigChoice::Custom(
            ConfigMapName::from_str(config_map).context(ParseContainerNameSnafu)?,
        ),
        ContainerLogConfigChoice::Automatic(automatic_log_config) => {
            ValidatedContainerLogConfigChoice::Automatic(automatic_log_config.clone())
        }
    };

    Ok(validated_container_log_config_choice)
}

/// Builds the container for the [`PodTemplateSpec`]
pub fn vector_container(
    container_name: &ContainerName,
    vector_container_log_config: &VectorContainerLogConfig,
    cluster_name: &ClusterName,
    role_name: &RoleName,
    role_group_name: &RoleGroupName,
    image: &ResolvedProductImage,
    log_config_volume_name: &VolumeName,
    log_volume_name: &VolumeName,
) -> Option<Container> {
    let log_level = if let ValidatedContainerLogConfigChoice::Automatic(log_config) =
        &vector_container_log_config.log_config
    {
        log_config.root_log_level()
    } else {
        LogLevel::default()
    };
    let vector_file_log_level =
        if let ValidatedContainerLogConfigChoice::Automatic(AutomaticContainerLogConfig {
            file: Some(AppenderConfig {
                level: Some(log_level),
            }),
            ..
        }) = vector_container_log_config.log_config
        {
            log_level
        } else {
            LogLevel::default()
        };

    let env_vars = EnvVarSet::new()
        .with_value(EnvVarName::from_str_unsafe("CLUSTER_NAME"), cluster_name)
        .with_value(EnvVarName::from_str_unsafe("LOG_DIR"), "/stackable/log")
        .with_field_path(
            EnvVarName::from_str_unsafe("NAMESPACE"),
            FieldPathEnvVar::Namespace,
        )
        .with_value(
            EnvVarName::from_str_unsafe("OPENSEARCH_SERVER_LOG_FILE"),
            "opensearch_server.json",
        )
        .with_value(
            EnvVarName::from_str_unsafe("ROLE_GROUP_NAME"),
            role_group_name,
        )
        .with_value(EnvVarName::from_str_unsafe("ROLE_NAME"), role_name)
        .with_config_map_key_ref(
            EnvVarName::from_str_unsafe("VECTOR_AGGREGATOR"),
            &vector_container_log_config.vector_aggregator_config_map_name,
            // TODO type-safe?
            "ADDRESS",
        )
        .with_value(
            EnvVarName::from_str_unsafe("VECTOR_CONFIG_YAML"),
            format!("/stackable/config/{VECTOR_CONFIG_FILE}"),
        )
        .with_value(
            EnvVarName::from_str_unsafe("VECTOR_FILE_LOG_LEVEL"),
            vector_file_log_level.to_vector_literal(),
        )
        .with_value(
            EnvVarName::from_str_unsafe("VECTOR_LOG"),
            log_level.to_vector_literal(),
        );

    let resources = ResourceRequirementsBuilder::new()
        .with_cpu_request("250m")
        .with_cpu_limit("500m")
        .with_memory_request("128Mi")
        .with_memory_limit("128Mi")
        .build();

    let container = new_container_builder(container_name)
            .image_from_product_image(image)
            .command(vec![
                "/bin/bash".to_string(),
                "-x".to_string(),
                "-euo".to_string(),
                "pipefail".to_string(),
                "-c".to_string(),
            ])
            .args(vec![format!(
                "# Vector will ignore SIGTERM (as PID != 1) and must be shut down by writing a shutdown trigger file\n\
                vector & vector_pid=$!\n\
                if [ ! -f \"{vector_control_directory}/{SHUTDOWN_FILE}\" ]; then\n\
                    mkdir -p {vector_control_directory}\n\
                    inotifywait -qq --event create {vector_control_directory};\n\
                fi\n\
                sleep 1\n\
                kill $vector_pid",
                vector_control_directory = format!("{STACKABLE_LOG_DIR}/_vector"),
                // TODO
                SHUTDOWN_FILE = "shutdown"
            )])
            .add_env_vars(env_vars.into())
            .add_volume_mounts([
                VolumeMount {
                    mount_path: format!(
                        "/stackable/config/{VECTOR_CONFIG_FILE}"
                    ),
                    name: log_config_volume_name.to_string(),
                    read_only: Some(true),
                    sub_path: Some(VECTOR_CONFIG_FILE.to_owned()),
                    ..VolumeMount::default()
                },
                VolumeMount {
                    mount_path: STACKABLE_LOG_DIR.to_owned(),
                    name: log_volume_name.to_string(),
                    ..VolumeMount::default()
                },
            ])
            .expect("The mount paths are statically defined and there should be no duplicates.")
            .resources(resources)
            .build();

    Some(container)
}
