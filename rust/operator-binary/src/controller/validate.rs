use std::{collections::BTreeMap, num::TryFromIntError, str::FromStr};

use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    kube::{Resource, ResourceExt},
    role_utils::RoleGroup,
    time::Duration,
};
use strum::{EnumDiscriminants, IntoStaticStr};

use super::{
    ContextNames, OpenSearchRoleGroupConfig, ProductVersion, RoleGroupName, ValidatedCluster,
    ValidatedOpenSearchConfig,
};
use crate::{
    crd::v1alpha1::{self, OpenSearchConfig, OpenSearchConfigFragment},
    framework::{
        ClusterName,
        builder::pod::container::{EnvVarName, EnvVarSet},
        role_utils::{GenericProductSpecificCommonConfig, RoleGroupConfig, with_validated_config},
    },
};

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
pub enum Error {
    #[snafu(display("failed to get the cluster name"))]
    GetClusterName {},

    #[snafu(display("failed to get the cluster namespace"))]
    GetClusterNamespace {},

    #[snafu(display("failed to get the cluster UID"))]
    GetClusterUid {},

    #[snafu(display("failed to set cluster name"))]
    ParseClusterName { source: crate::framework::Error },

    #[snafu(display("failed to set product version"))]
    ParseProductVersion { source: crate::framework::Error },

    #[snafu(display("failed to set role-group name"))]
    ParseRoleGroupName { source: crate::framework::Error },

    #[snafu(display("failed to parse environment variable"))]
    ParseEnvironmentVariable {
        source: crate::framework::builder::pod::container::Error,
    },

    #[snafu(display("fragment validation failure"))]
    ValidateOpenSearchConfig {
        source: stackable_operator::config::fragment::ValidationError,
    },

    #[snafu(display("termination grace period is too long (got {duration}, maximum allowed is {max})", max = Duration::from_secs(i64::MAX as u64)))]
    TerminationGracePeriodTooLong {
        source: TryFromIntError,
        duration: Duration,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

// no client needed
pub fn validate(
    context_names: &ContextNames,
    cluster: &v1alpha1::OpenSearchCluster,
) -> Result<ValidatedCluster> {
    let raw_cluster_name = cluster.meta().name.clone().context(GetClusterNameSnafu)?;
    let cluster_name = ClusterName::from_str(&raw_cluster_name).context(ParseClusterNameSnafu)?;

    let namespace = cluster.namespace().context(GetClusterNamespaceSnafu)?;

    let uid = cluster.uid().context(GetClusterUidSnafu)?;

    let product_version = ProductVersion::from_str(cluster.spec.image.product_version())
        .context(ParseProductVersionSnafu)?;

    let mut role_group_configs = BTreeMap::new();
    for (raw_role_group_name, role_group_config) in &cluster.spec.nodes.role_groups {
        let role_group_name =
            RoleGroupName::from_str(raw_role_group_name).context(ParseRoleGroupNameSnafu)?;

        let validated_role_group_config =
            validate_role_group_config(context_names, &cluster_name, cluster, role_group_config)?;

        role_group_configs.insert(role_group_name, validated_role_group_config);
    }

    Ok(ValidatedCluster::new(
        cluster.spec.image.clone(),
        product_version,
        cluster_name,
        namespace,
        uid,
        cluster.spec.nodes.role_config.clone(),
        role_group_configs,
    ))
}

fn validate_role_group_config(
    context_names: &ContextNames,
    cluster_name: &ClusterName,
    cluster: &v1alpha1::OpenSearchCluster,
    role_group_config: &RoleGroup<OpenSearchConfigFragment, GenericProductSpecificCommonConfig>,
) -> Result<OpenSearchRoleGroupConfig> {
    let merged_role_group: RoleGroup<OpenSearchConfig, _> = with_validated_config(
        role_group_config,
        &cluster.spec.nodes,
        &v1alpha1::OpenSearchConfig::default_config(
            &context_names.product_name,
            cluster_name,
            &ValidatedCluster::role_name(),
        ),
    )
    .context(ValidateOpenSearchConfigSnafu)?;

    let graceful_shutdown_timeout = merged_role_group.config.config.graceful_shutdown_timeout;
    let termination_grace_period_seconds = graceful_shutdown_timeout.as_secs().try_into().context(
        TerminationGracePeriodTooLongSnafu {
            duration: graceful_shutdown_timeout,
        },
    )?;

    let validated_config = ValidatedOpenSearchConfig {
        affinity: merged_role_group.config.config.affinity,
        node_roles: merged_role_group.config.config.node_roles,
        resources: merged_role_group.config.config.resources,
        termination_grace_period_seconds,
        listener_class: merged_role_group.config.config.listener_class,
    };

    let mut env_overrides = EnvVarSet::new();

    for (env_var_name, env_var_value) in merged_role_group.config.env_overrides {
        env_overrides = env_overrides.with_value(
            EnvVarName::from_str(&env_var_name).context(ParseEnvironmentVariableSnafu)?,
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

#[cfg(test)]
mod tests {
    use stackable_operator::{
        commons::{
            affinity::StackableAffinity,
            cluster_operation::ClusterOperation,
            resources::{CpuLimits, MemoryLimits, PvcConfig, Resources},
        },
        k8s_openapi::{
            api::core::v1::{
                PodAffinityTerm, PodAntiAffinity, PodTemplateSpec, WeightedPodAffinityTerm,
            },
            apimachinery::pkg::{api::resource::Quantity, apis::meta::v1::LabelSelector},
        },
        kube::api::ObjectMeta,
        role_utils::{CommonConfiguration, GenericRoleConfig, Role, RoleGroup},
        time::Duration,
    };

    use super::{ErrorDiscriminants, validate};
    use crate::{
        controller::{ContextNames, ValidatedCluster, ValidatedOpenSearchConfig},
        crd::{
            NodeRoles,
            v1alpha1::{self, OpenSearchClusterSpec, OpenSearchConfigFragment, StorageConfig},
        },
        framework::{
            ClusterName, ControllerName, OperatorName, ProductName, ProductVersion, RoleGroupName,
            builder::pod::container::{EnvVarName, EnvVarSet},
            role_utils::{GenericProductSpecificCommonConfig, RoleGroupConfig},
        },
    };

    #[test]
    fn test_validate_ok() {
        let result = validate(&context_names(), &cluster());

        assert_eq!(
            Some(ValidatedCluster::new(
                serde_json::from_str(r#"{"productVersion": "3.1.0"}"#)
                    .expect("should be a valid ProductImage structure"),
                ProductVersion::from_str_unsafe("3.1.0"),
                ClusterName::from_str_unsafe("my-opensearch"),
                "default".to_owned(),
                "e6ac237d-a6d4-43a1-8135-f36506110912".to_owned(),
                GenericRoleConfig::default(),
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
                            node_roles: NodeRoles(
                                [
                                    v1alpha1::NodeRole::ClusterManager,
                                    v1alpha1::NodeRole::Ingest,
                                    v1alpha1::NodeRole::Data,
                                    v1alpha1::NodeRole::RemoteClusterClient
                                ]
                                .into()
                            ),
                            resources: Resources {
                                memory: MemoryLimits {
                                    limit: Some(Quantity("2Gi".to_owned())),
                                    ..MemoryLimits::default()
                                },
                                cpu: CpuLimits {
                                    min: Some(Quantity("1".to_owned())),
                                    max: Some(Quantity("4".to_owned()))
                                },
                                storage: StorageConfig {
                                    data: PvcConfig {
                                        capacity: Some(Quantity("8Gi".to_owned())),
                                        ..PvcConfig::default()
                                    }
                                }
                            },
                            termination_grace_period_seconds: 300,
                            listener_class: "listener-class-from-role-group-level".to_owned(),
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
    fn test_validate_err_parse_cluster_name() {
        test_validate_err(
            |cluster| cluster.metadata.name = Some("invalid cluster name".to_owned()),
            ErrorDiscriminants::ParseClusterName,
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
    fn test_validate_err_parse_product_version() {
        test_validate_err(
            |cluster| {
                cluster.spec.image =
                    serde_json::from_str(r#"{"productVersion": "invalid product version"}"#)
                        .expect("should be a valid ProductImage structure")
            },
            ErrorDiscriminants::ParseProductVersion,
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

        let result = validate(&context_names(), &cluster);

        assert_eq!(Err(expected_err), result.map_err(ErrorDiscriminants::from));
    }

    fn context_names() -> ContextNames {
        ContextNames {
            product_name: ProductName::from_str_unsafe("opensearch"),
            operator_name: OperatorName::from_str_unsafe("opensearch.stackable.tech"),
            controller_name: ControllerName::from_str_unsafe("opensearchcluster"),
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
            spec: OpenSearchClusterSpec {
                image: serde_json::from_str(r#"{"productVersion": "3.1.0"}"#)
                    .expect("should be a valid ProductImage structure"),
                cluster_operation: ClusterOperation::default(),
                nodes: Role {
                    config: CommonConfiguration {
                        config: OpenSearchConfigFragment {
                            graceful_shutdown_timeout: Some(Duration::from_minutes_unchecked(5)),
                            listener_class: Some("listener-class-from-role-level".to_owned()),
                            ..OpenSearchConfigFragment::default()
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
                    role_config: GenericRoleConfig::default(),
                    role_groups: [(
                        "default".to_owned(),
                        RoleGroup {
                            config: CommonConfiguration {
                                config: OpenSearchConfigFragment {
                                    listener_class: Some(
                                        "listener-class-from-role-group-level".to_owned(),
                                    ),
                                    ..OpenSearchConfigFragment::default()
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
