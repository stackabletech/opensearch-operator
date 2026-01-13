//! The validate step in the OpenSearchCluster controller

use std::{collections::BTreeMap, str::FromStr};

use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    crd::listener, kube::ResourceExt, product_logging::spec::Logging, role_utils::RoleGroup,
    shared::time::Duration,
};
use strum::{EnumDiscriminants, IntoStaticStr};

use super::{
    ContextNames, OpenSearchRoleGroupConfig, ProductVersion, RoleGroupName, ValidatedCluster,
    ValidatedLogging, ValidatedOpenSearchConfig,
};
use crate::{
    controller::{DereferencedObjects, ValidatedDiscoveryEndpoint},
    crd::v1alpha1::{self},
    framework::{
        builder::pod::container::{EnvVarName, EnvVarSet},
        controller_utils::{get_cluster_name, get_namespace, get_uid},
        product_logging::framework::{
            VectorContainerLogConfig, validate_logging_configuration_for_container,
        },
        role_utils::{GenericProductSpecificCommonConfig, RoleGroupConfig, with_validated_config},
        types::{
            common::Port,
            kubernetes::{ConfigMapName, Hostname},
            operator::ClusterName,
        },
    },
};

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
pub enum Error {
    #[snafu(display("failed to get the cluster name"))]
    GetClusterName {
        source: crate::framework::controller_utils::Error,
    },

    #[snafu(display("failed to get the cluster namespace"))]
    GetClusterNamespace {
        source: crate::framework::controller_utils::Error,
    },

    #[snafu(display("failed to get the cluster UID"))]
    GetClusterUid {
        source: crate::framework::controller_utils::Error,
    },

    #[snafu(display("failed to get the port of the Listener status"))]
    GetListenerStatusPort {},

    #[snafu(display(
        "failed to get vectorAggregatorConfigMapName; It must be set if enableVectorAgent is true."
    ))]
    GetVectorAggregatorConfigMapName {},

    #[snafu(display("failed to parse environment variable"))]
    ParseEnvironmentVariable {
        source: crate::framework::builder::pod::container::Error,
    },

    #[snafu(display("failed to parse the hostname of the Listener status"))]
    ParseListenerStatusHostname {
        source: crate::framework::macros::attributed_string_type::Error,
    },

    #[snafu(display("failed to parse the port of the Listener status"))]
    ParseListenerStatusPort {
        source: crate::framework::types::common::Error,
    },

    #[snafu(display("failed to set product version"))]
    ParseProductVersion {
        source: crate::framework::macros::attributed_string_type::Error,
    },

    #[snafu(display("failed to set role-group name"))]
    ParseRoleGroupName {
        source: crate::framework::macros::attributed_string_type::Error,
    },

    #[snafu(display("failed to resolve product image"))]
    ResolveProductImage {
        source: stackable_operator::commons::product_image_selection::Error,
    },

    #[snafu(display("failed to validate the logging configuration"))]
    ValidateLoggingConfig {
        source: crate::framework::product_logging::framework::Error,
    },

    #[snafu(display("fragment validation failure"))]
    ValidateOpenSearchConfig {
        source: stackable_operator::config::fragment::ValidationError,
    },

    #[snafu(display("termination grace period is too long (got {duration}, maximum allowed is {max})", max = Duration::from_secs(i64::MAX as u64)))]
    TerminationGracePeriodTooLong {
        source: std::num::TryFromIntError,
        duration: Duration,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

const DEFAULT_IMAGE_BASE_NAME: &str = "opensearch";

/// Validates the [`v1alpha1::OpenSearchCluster`] and returns a [`ValidatedCluster`]
///
/// The validated values should be wrapped in fail-safe types so that illegal states are
/// unrepresentable in the following steps.
///
/// A Kubernetes client is not required because references to other Kubernetes resources must
/// already be dereferenced in a prior step.
pub fn validate(
    context_names: &ContextNames,
    cluster: &v1alpha1::OpenSearchCluster,
    dereferenced_objects: &DereferencedObjects,
) -> Result<ValidatedCluster> {
    let cluster_name = get_cluster_name(cluster).context(GetClusterNameSnafu)?;
    let namespace = get_namespace(cluster).context(GetClusterNamespaceSnafu)?;
    let uid = get_uid(cluster).context(GetClusterUidSnafu)?;

    let product_image = cluster
        .spec
        .image
        .resolve(DEFAULT_IMAGE_BASE_NAME, crate::built_info::PKG_VERSION)
        .context(ResolveProductImageSnafu)?;

    // Cannot fail because `ProductImage::resolve` already validated it and would have thrown a
    // `ResolveProductImage` error if it were not valid.
    let product_version = ProductVersion::from_str(&product_image.product_version)
        .context(ParseProductVersionSnafu)?;

    let mut role_group_configs = BTreeMap::new();
    for (raw_role_group_name, role_group_config) in &cluster.spec.nodes.role_groups {
        let role_group_name =
            RoleGroupName::from_str(raw_role_group_name).context(ParseRoleGroupNameSnafu)?;

        let validated_role_group_config =
            validate_role_group_config(context_names, &cluster_name, cluster, role_group_config)?;

        role_group_configs.insert(role_group_name, validated_role_group_config);
    }

    let validated_discovery_endpoint = validate_discovery_endpoint(dereferenced_objects)?;

    Ok(ValidatedCluster::new(
        product_image,
        product_version,
        cluster_name,
        namespace,
        uid,
        cluster.spec.nodes.role_config.clone(),
        role_group_configs,
        cluster.spec.cluster_config.tls.clone(),
        cluster.spec.cluster_config.keystore.clone(),
        validated_discovery_endpoint,
    ))
}

fn validate_role_group_config(
    context_names: &ContextNames,
    cluster_name: &ClusterName,
    cluster: &v1alpha1::OpenSearchCluster,
    role_group_config: &RoleGroup<
        v1alpha1::OpenSearchConfigFragment,
        GenericProductSpecificCommonConfig,
    >,
) -> Result<OpenSearchRoleGroupConfig> {
    let merged_role_group: RoleGroup<v1alpha1::OpenSearchConfig, _> = with_validated_config(
        role_group_config,
        &cluster.spec.nodes,
        &v1alpha1::OpenSearchConfig::default_config(
            &context_names.product_name,
            cluster_name,
            &ValidatedCluster::role_name(),
        ),
    )
    .context(ValidateOpenSearchConfigSnafu)?;

    let logging = validate_logging_configuration(
        &merged_role_group.config.config.logging,
        &cluster
            .spec
            .cluster_config
            .vector_aggregator_config_map_name,
    )?;

    let graceful_shutdown_timeout = merged_role_group.config.config.graceful_shutdown_timeout;
    let termination_grace_period_seconds = graceful_shutdown_timeout.as_secs().try_into().context(
        TerminationGracePeriodTooLongSnafu {
            duration: graceful_shutdown_timeout,
        },
    )?;

    let validated_config = ValidatedOpenSearchConfig {
        affinity: merged_role_group.config.config.affinity,
        discovery_service_exposed: merged_role_group.config.config.discovery_service_exposed,
        listener_class: merged_role_group.config.config.listener_class,
        logging,
        node_roles: merged_role_group.config.config.node_roles,
        requested_secret_lifetime: merged_role_group.config.config.requested_secret_lifetime,
        resources: merged_role_group.config.config.resources,
        termination_grace_period_seconds,
    };

    let mut env_overrides = EnvVarSet::new();

    for (env_var_name, env_var_value) in merged_role_group.config.env_overrides {
        env_overrides = env_overrides.with_value(
            &EnvVarName::from_str(&env_var_name).context(ParseEnvironmentVariableSnafu)?,
            env_var_value,
        );
    }

    Ok(RoleGroupConfig {
        // Kubernetes defaults to 1 if not set
        replicas: merged_role_group.replicas.unwrap_or(1),
        config: validated_config,
        config_overrides: merged_role_group.config.config_overrides,
        env_overrides,
        cli_overrides: merged_role_group.config.cli_overrides,
        pod_overrides: merged_role_group.config.pod_overrides,
        product_specific_common_config: merged_role_group.config.product_specific_common_config,
    })
}

fn validate_logging_configuration(
    logging: &Logging<v1alpha1::Container>,
    vector_aggregator_config_map_name: &Option<ConfigMapName>,
) -> Result<ValidatedLogging> {
    let opensearch_container =
        validate_logging_configuration_for_container(logging, v1alpha1::Container::OpenSearch)
            .context(ValidateLoggingConfigSnafu)?;

    let vector_container = if logging.enable_vector_agent {
        let vector_aggregator_config_map_name = vector_aggregator_config_map_name
            .clone()
            .context(GetVectorAggregatorConfigMapNameSnafu)?;
        Some(VectorContainerLogConfig {
            log_config: validate_logging_configuration_for_container(
                logging,
                v1alpha1::Container::Vector,
            )
            .context(ValidateLoggingConfigSnafu)?,
            vector_aggregator_config_map_name,
        })
    } else {
        None
    };

    Ok(ValidatedLogging {
        opensearch_container,
        vector_container,
    })
}

fn validate_discovery_endpoint(
    dereferenced_objects: &DereferencedObjects,
) -> Result<Option<ValidatedDiscoveryEndpoint>> {
    let validated_discovery_endpoint = if let Some(discovery_service_listener) =
        &dereferenced_objects.maybe_discovery_service_listener
    {
        if let Some((hostname, port)) = extract_listener_ingresses(discovery_service_listener)? {
            tracing::info!(
                "The status of the discovery service listener {} contains the discovery endpoint. \
                The discovery ConfigMap will be created or updated.",
                discovery_service_listener.name_any()
            );
            Some(ValidatedDiscoveryEndpoint { hostname, port })
        } else {
            tracing::info!(
                "The status of the discovery service listener {} does not yet contain the \
                discovery endpoint. The creation of the discovery ConfigMap will be postponed \
                until the status is updated.",
                discovery_service_listener.name_any()
            );
            None
        }
    } else {
        tracing::info!(
            "The discovery service listener is not yet deployed. The creation of the discovery \
            ConfigMap will be postponed until the discovery service listener is deployed and its \
            status is set."
        );
        None
    };

    Ok(validated_discovery_endpoint)
}

fn extract_listener_ingresses(
    discovery_service_listener: &listener::v1alpha1::Listener,
) -> Result<Option<(Hostname, Port)>> {
    let maybe_first_ingress_address = discovery_service_listener
        .status
        .as_ref()
        .and_then(|status| status.ingress_addresses.as_ref())
        .into_iter()
        .flatten()
        .next();

    // It is okay if the status is not set yet. But if it is set, then it must be valid.
    if let Some(ingress_address) = maybe_first_ingress_address {
        let hostname = Hostname::from_str(&ingress_address.address)
            .context(ParseListenerStatusHostnameSnafu)?;

        let raw_port = *ingress_address
            .ports
            // TODO Use HTTP_PORT_NAME somehow
            .get("http")
            .context(GetListenerStatusPortSnafu)?;
        let port = Port::try_from(raw_port).context(ParseListenerStatusPortSnafu)?;

        Ok(Some((hostname, port)))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, str::FromStr};

    use pretty_assertions::assert_eq;
    use stackable_operator::{
        commons::{
            affinity::StackableAffinity,
            cluster_operation::ClusterOperation,
            networking::DomainName,
            product_image_selection::ResolvedProductImage,
            resources::{CpuLimits, MemoryLimits, PvcConfig, Resources},
        },
        k8s_openapi::{
            api::core::v1::{
                PodAffinityTerm, PodAntiAffinity, PodTemplateSpec, WeightedPodAffinityTerm,
            },
            apimachinery::pkg::{api::resource::Quantity, apis::meta::v1::LabelSelector},
        },
        kube::api::ObjectMeta,
        kvp::LabelValue,
        product_logging::spec::{
            AppenderConfig, AutomaticContainerLogConfig, ConfigMapLogConfigFragment,
            ContainerLogConfigChoiceFragment, ContainerLogConfigFragment,
            CustomContainerLogConfigFragment, LogLevel, LoggerConfig, LoggingFragment,
        },
        role_utils::{CommonConfiguration, Role, RoleGroup},
        shared::time::Duration,
    };
    use uuid::uuid;

    use super::{ErrorDiscriminants, validate};
    use crate::{
        built_info,
        controller::{
            ContextNames, DereferencedObjects, ValidatedCluster, ValidatedLogging,
            ValidatedOpenSearchConfig,
        },
        crd::{NodeRoles, OpenSearchKeystoreKey, v1alpha1},
        framework::{
            builder::pod::container::{EnvVarName, EnvVarSet},
            product_logging::framework::{
                ValidatedContainerLogConfigChoice, VectorContainerLogConfig,
            },
            role_utils::{GenericProductSpecificCommonConfig, RoleGroupConfig},
            types::{
                kubernetes::{
                    ConfigMapName, ListenerClassName, NamespaceName, SecretClassName, SecretKey,
                    SecretName,
                },
                operator::{
                    ClusterName, ControllerName, OperatorName, ProductName, ProductVersion,
                    RoleGroupName,
                },
            },
        },
    };

    #[test]
    fn test_validate_ok() {
        let dereferenced_objects = DereferencedObjects {
            maybe_discovery_service_listener: None,
        };

        let result = validate(&context_names(), &cluster(), &dereferenced_objects);

        assert_eq!(
            Some(ValidatedCluster::new(
                ResolvedProductImage {
                    product_version: "3.1.0".to_owned(),
                    app_version_label_value: LabelValue::from_str(&format!(
                        "3.1.0-stackable{pkg_version}",
                        pkg_version = built_info::PKG_VERSION
                    ))
                    .expect("should be a valid label value"),
                    image: format!(
                        "oci.stackable.tech/sdp/opensearch:3.1.0-stackable{pkg_version}",
                        pkg_version = built_info::PKG_VERSION
                    ),
                    image_pull_policy: "Always".to_owned(),
                    pull_secrets: None,
                },
                ProductVersion::from_str_unsafe("3.1.0"),
                ClusterName::from_str_unsafe("my-opensearch"),
                NamespaceName::from_str_unsafe("default"),
                uuid!("e6ac237d-a6d4-43a1-8135-f36506110912"),
                v1alpha1::OpenSearchRoleConfig::default(),
                [(
                    RoleGroupName::from_str_unsafe("default"),
                    RoleGroupConfig {
                        replicas: 3,
                        config: ValidatedOpenSearchConfig {
                            affinity: StackableAffinity {
                                pod_anti_affinity: Some(PodAntiAffinity {
                                    preferred_during_scheduling_ignored_during_execution: Some(
                                        [WeightedPodAffinityTerm {
                                            pod_affinity_term: PodAffinityTerm {
                                                label_selector: Some(LabelSelector {
                                                    match_labels: Some(
                                                        [
                                                            (
                                                                "app.kubernetes.io/component"
                                                                    .to_owned(),
                                                                "nodes".to_owned()
                                                            ),
                                                            (
                                                                "app.kubernetes.io/instance"
                                                                    .to_owned(),
                                                                "my-opensearch".to_owned()
                                                            ),
                                                            (
                                                                "app.kubernetes.io/name".to_owned(),
                                                                "opensearch".to_owned()
                                                            )
                                                        ]
                                                        .into()
                                                    ),
                                                    ..LabelSelector::default()
                                                }),
                                                topology_key: "kubernetes.io/hostname".to_owned(),
                                                ..PodAffinityTerm::default()
                                            },
                                            weight: 1
                                        }]
                                        .into()
                                    ),
                                    ..PodAntiAffinity::default()
                                }),
                                ..StackableAffinity::default()
                            },
                            discovery_service_exposed: true,
                            listener_class: ListenerClassName::from_str_unsafe(
                                "listener-class-from-role-group-level"
                            ),
                            logging: ValidatedLogging {
                                opensearch_container: ValidatedContainerLogConfigChoice::Automatic(
                                    AutomaticContainerLogConfig {
                                        loggers: [(
                                            "ROOT".to_owned(),
                                            LoggerConfig {
                                                level: LogLevel::INFO
                                            }
                                        )]
                                        .into(),
                                        console: Some(AppenderConfig {
                                            level: Some(LogLevel::INFO)
                                        }),
                                        file: Some(AppenderConfig {
                                            level: Some(LogLevel::INFO)
                                        }),
                                    },
                                ),
                                vector_container: Some(VectorContainerLogConfig {
                                    log_config: ValidatedContainerLogConfigChoice::Automatic(
                                        AutomaticContainerLogConfig {
                                            loggers: [(
                                                "ROOT".to_owned(),
                                                LoggerConfig {
                                                    level: LogLevel::INFO
                                                },
                                            )]
                                            .into(),
                                            console: Some(AppenderConfig {
                                                level: Some(LogLevel::INFO)
                                            }),
                                            file: Some(AppenderConfig {
                                                level: Some(LogLevel::INFO)
                                            }),
                                        },
                                    ),
                                    vector_aggregator_config_map_name:
                                        ConfigMapName::from_str_unsafe("vector-aggregator"),
                                }),
                            },
                            node_roles: NodeRoles(
                                [
                                    v1alpha1::NodeRole::ClusterManager,
                                    v1alpha1::NodeRole::Ingest,
                                    v1alpha1::NodeRole::Data,
                                    v1alpha1::NodeRole::RemoteClusterClient
                                ]
                                .into()
                            ),
                            requested_secret_lifetime: Duration::from_str("1d")
                                .expect("should be a valid duration"),
                            resources: Resources {
                                memory: MemoryLimits {
                                    limit: Some(Quantity("2Gi".to_owned())),
                                    ..MemoryLimits::default()
                                },
                                cpu: CpuLimits {
                                    min: Some(Quantity("1".to_owned())),
                                    max: Some(Quantity("4".to_owned()))
                                },
                                storage: v1alpha1::StorageConfig {
                                    data: PvcConfig {
                                        capacity: Some(Quantity("8Gi".to_owned())),
                                        ..PvcConfig::default()
                                    }
                                }
                            },
                            termination_grace_period_seconds: 300,
                        },
                        config_overrides: [(
                            "opensearch.yml".to_owned(),
                            [
                                ("setting1".to_owned(), "value from role level".to_owned()),
                                (
                                    "setting2".to_owned(),
                                    "value from role-group level".to_owned()
                                ),
                                (
                                    "setting3".to_owned(),
                                    "value from role-group level".to_owned()
                                ),
                            ]
                            .into()
                        )]
                        .into(),
                        env_overrides: EnvVarSet::new().with_values([
                            (
                                EnvVarName::from_str_unsafe("ENV1"),
                                "value from role level".to_owned()
                            ),
                            (
                                EnvVarName::from_str_unsafe("ENV2"),
                                "value from role-group level".to_owned()
                            ),
                            (
                                EnvVarName::from_str_unsafe("ENV3"),
                                "value from role-group level".to_owned()
                            )
                        ]),
                        cli_overrides: [
                            ("--param1".to_owned(), "value from role level".to_owned()),
                            (
                                "--param2".to_owned(),
                                "value from role-group level".to_owned()
                            ),
                            (
                                "--param3".to_owned(),
                                "value from role-group level".to_owned()
                            )
                        ]
                        .into(),
                        pod_overrides: PodTemplateSpec {
                            metadata: Some(ObjectMeta {
                                labels: Some(
                                    [
                                        ("label1".to_owned(), "value from role level".to_owned()),
                                        (
                                            "label2".to_owned(),
                                            "value from role-group level".to_owned()
                                        ),
                                        (
                                            "label3".to_owned(),
                                            "value from role-group level".to_owned()
                                        )
                                    ]
                                    .into()
                                ),
                                ..ObjectMeta::default()
                            }),
                            ..PodTemplateSpec::default()
                        },
                        product_specific_common_config: GenericProductSpecificCommonConfig::default(
                        )
                    }
                )]
                .into(),
                v1alpha1::OpenSearchTls {
                    server_secret_class: Some(SecretClassName::from_str_unsafe("tls")),
                    internal_secret_class: SecretClassName::from_str_unsafe("tls")
                },
                vec![v1alpha1::OpenSearchKeystore {
                    key: OpenSearchKeystoreKey::from_str_unsafe("Keystore1"),
                    secret_key_ref: v1alpha1::SecretKeyRef {
                        name: SecretName::from_str_unsafe("my-keystore-secret"),
                        key: SecretKey::from_str_unsafe("my-keystore-file")
                    }
                }],
                None
            )),
            result.ok()
        );
    }

    #[test]
    fn test_validate_err_get_cluster_name() {
        test_validate_err(
            |cluster| cluster.metadata.name = None,
            ErrorDiscriminants::GetClusterName,
        );
    }

    #[test]
    fn test_validate_err_get_cluster_namespace() {
        test_validate_err(
            |cluster| cluster.metadata.namespace = None,
            ErrorDiscriminants::GetClusterNamespace,
        );
    }

    #[test]
    fn test_validate_err_get_cluster_uid() {
        test_validate_err(
            |cluster| cluster.metadata.uid = None,
            ErrorDiscriminants::GetClusterUid,
        );
    }

    #[test]
    fn test_validate_err_resolve_product_image() {
        test_validate_err(
            |cluster| {
                cluster.spec.image =
                    serde_json::from_str(r#"{"productVersion": "invalid product version"}"#)
                        .expect("should be a valid ProductImage structure")
            },
            ErrorDiscriminants::ResolveProductImage,
        );
    }

    #[test]
    fn test_validate_err_parse_role_group_name() {
        test_validate_err(
            |cluster| {
                let role_group = cluster
                    .spec
                    .nodes
                    .role_groups
                    .remove("default")
                    .expect("should be set");
                cluster
                    .spec
                    .nodes
                    .role_groups
                    .insert("invalid role-group name".to_owned(), role_group);
            },
            ErrorDiscriminants::ParseRoleGroupName,
        );
    }

    #[test]
    fn test_validate_err_validate_logging_config() {
        test_validate_err(
            |cluster| {
                cluster.spec.nodes.config.config.logging.containers = [(
                    v1alpha1::Container::OpenSearch,
                    ContainerLogConfigFragment {
                        choice: Some(ContainerLogConfigChoiceFragment::Custom(
                            CustomContainerLogConfigFragment {
                                custom: ConfigMapLogConfigFragment {
                                    config_map: Some("invalid ConfigMap name".to_owned()),
                                },
                            },
                        )),
                    },
                )]
                .into()
            },
            ErrorDiscriminants::ValidateLoggingConfig,
        );
    }

    #[test]
    fn test_validate_err_get_vector_aggregator_config_map_name() {
        test_validate_err(
            |cluster| {
                cluster
                    .spec
                    .cluster_config
                    .vector_aggregator_config_map_name = None
            },
            ErrorDiscriminants::GetVectorAggregatorConfigMapName,
        );
    }

    #[test]
    fn test_validate_err_termination_grace_period_too_long() {
        test_validate_err(
            |cluster| {
                cluster.spec.nodes.config.config.graceful_shutdown_timeout =
                    Some(Duration::from_secs(u64::MAX))
            },
            ErrorDiscriminants::TerminationGracePeriodTooLong,
        );
    }

    #[test]
    fn test_validate_err_parse_environment_variable() {
        test_validate_err(
            |cluster| {
                cluster.spec.nodes.config.env_overrides = [(
                    "INVALID_ENVIRONMENT_VARIABLE_WITH_=".to_owned(),
                    "value".to_owned(),
                )]
                .into()
            },
            ErrorDiscriminants::ParseEnvironmentVariable,
        );
    }

    fn test_validate_err(
        f: fn(&mut v1alpha1::OpenSearchCluster) -> (),
        expected_err: ErrorDiscriminants,
    ) {
        let mut cluster = cluster();
        f(&mut cluster);

        let dereferenced_objects = DereferencedObjects {
            maybe_discovery_service_listener: None,
        };

        let result = validate(&context_names(), &cluster, &dereferenced_objects);

        assert_eq!(Err(expected_err), result.map_err(ErrorDiscriminants::from));
    }

    fn context_names() -> ContextNames {
        ContextNames {
            product_name: ProductName::from_str_unsafe("opensearch"),
            operator_name: OperatorName::from_str_unsafe("opensearch.stackable.tech"),
            controller_name: ControllerName::from_str_unsafe("opensearchcluster"),
            cluster_domain_name: DomainName::from_str("cluster.local")
                .expect("should be a valid domain name"),
        }
    }

    fn cluster() -> v1alpha1::OpenSearchCluster {
        v1alpha1::OpenSearchCluster {
            metadata: ObjectMeta {
                name: Some("my-opensearch".to_owned()),
                namespace: Some("default".to_owned()),
                uid: Some("e6ac237d-a6d4-43a1-8135-f36506110912".to_owned()),
                ..ObjectMeta::default()
            },
            spec: v1alpha1::OpenSearchClusterSpec {
                image: serde_json::from_str(r#"{"productVersion": "3.1.0"}"#)
                    .expect("should be a valid ProductImage structure"),
                cluster_config: v1alpha1::OpenSearchClusterConfig {
                    tls: v1alpha1::OpenSearchTls::default(),
                    keystore: vec![v1alpha1::OpenSearchKeystore {
                        key: OpenSearchKeystoreKey::from_str_unsafe("Keystore1"),
                        secret_key_ref: v1alpha1::SecretKeyRef {
                            name: SecretName::from_str_unsafe("my-keystore-secret"),
                            key: SecretKey::from_str_unsafe("my-keystore-file"),
                        },
                    }],
                    vector_aggregator_config_map_name: Some(ConfigMapName::from_str_unsafe(
                        "vector-aggregator",
                    )),
                },
                cluster_operation: ClusterOperation::default(),
                nodes: Role {
                    config: CommonConfiguration {
                        config: v1alpha1::OpenSearchConfigFragment {
                            graceful_shutdown_timeout: Some(Duration::from_minutes_unchecked(5)),
                            listener_class: Some(ListenerClassName::from_str_unsafe(
                                "listener-class-from-role-level",
                            )),
                            logging: LoggingFragment {
                                enable_vector_agent: Some(true),
                                containers: BTreeMap::default(),
                            },
                            ..v1alpha1::OpenSearchConfigFragment::default()
                        },
                        config_overrides: [(
                            "opensearch.yml".to_owned(),
                            [
                                ("setting1".to_owned(), "value from role level".to_owned()),
                                ("setting2".to_owned(), "value from role level".to_owned()),
                            ]
                            .into(),
                        )]
                        .into(),
                        env_overrides: [
                            ("ENV1".to_owned(), "value from role level".to_owned()),
                            ("ENV2".to_owned(), "value from role level".to_owned()),
                        ]
                        .into(),
                        cli_overrides: [
                            ("--param1".to_owned(), "value from role level".to_owned()),
                            ("--param2".to_owned(), "value from role level".to_owned()),
                        ]
                        .into(),
                        pod_overrides: PodTemplateSpec {
                            metadata: Some(ObjectMeta {
                                labels: Some(
                                    [
                                        ("label1".to_owned(), "value from role level".to_owned()),
                                        ("label2".to_owned(), "value from role level".to_owned()),
                                    ]
                                    .into(),
                                ),
                                ..ObjectMeta::default()
                            }),
                            ..PodTemplateSpec::default()
                        },
                        product_specific_common_config: GenericProductSpecificCommonConfig::default(
                        ),
                    },
                    role_config: v1alpha1::OpenSearchRoleConfig::default(),
                    role_groups: [(
                        "default".to_owned(),
                        RoleGroup {
                            config: CommonConfiguration {
                                config: v1alpha1::OpenSearchConfigFragment {
                                    listener_class: Some(ListenerClassName::from_str_unsafe(
                                        "listener-class-from-role-group-level",
                                    )),
                                    ..v1alpha1::OpenSearchConfigFragment::default()
                                },
                                config_overrides: [(
                                    "opensearch.yml".to_owned(),
                                    [
                                        (
                                            "setting2".to_owned(),
                                            "value from role-group level".to_owned(),
                                        ),
                                        (
                                            "setting3".to_owned(),
                                            "value from role-group level".to_owned(),
                                        ),
                                    ]
                                    .into(),
                                )]
                                .into(),
                                env_overrides: [
                                    ("ENV2".to_owned(), "value from role-group level".to_owned()),
                                    ("ENV3".to_owned(), "value from role-group level".to_owned()),
                                ]
                                .into(),
                                cli_overrides: [
                                    (
                                        "--param2".to_owned(),
                                        "value from role-group level".to_owned(),
                                    ),
                                    (
                                        "--param3".to_owned(),
                                        "value from role-group level".to_owned(),
                                    ),
                                ]
                                .into(),
                                pod_overrides: PodTemplateSpec {
                                    metadata: Some(ObjectMeta {
                                        labels: Some(
                                            [
                                                (
                                                    "label2".to_owned(),
                                                    "value from role-group level".to_owned(),
                                                ),
                                                (
                                                    "label3".to_owned(),
                                                    "value from role-group level".to_owned(),
                                                ),
                                            ]
                                            .into(),
                                        ),
                                        ..ObjectMeta::default()
                                    }),
                                    ..PodTemplateSpec::default()
                                },
                                product_specific_common_config:
                                    GenericProductSpecificCommonConfig::default(),
                            },
                            replicas: Some(3),
                        },
                    )]
                    .into(),
                },
            },
            status: None,
        }
    }
}
