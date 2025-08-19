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
    crd::v1alpha1::{
        self, OpenSearchClusterConfig, OpenSearchConfig, OpenSearchConfigFragment, OpenSearchTls,
    },
    framework::{
        ClusterName, TlsSecretClassName,
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

    #[snafu(display("failed to set tls secret class"))]
    ParseTlsSecretClassName { source: crate::framework::Error },

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

    let validated_cluster_config = validate_cluster_config(cluster.spec.cluster_config.clone())?;

    let mut role_group_configs = BTreeMap::new();
    for (raw_role_group_name, role_group_config) in &cluster.spec.nodes.role_groups {
        let role_group_name =
            RoleGroupName::from_str(raw_role_group_name).context(ParseRoleGroupNameSnafu)?;

        let validated_role_group_config =
            validate_role_group_config(context_names, &cluster_name, cluster, role_group_config)?;

        role_group_configs.insert(role_group_name, validated_role_group_config);
    }

    Ok(ValidatedCluster {
        metadata: cluster.meta().to_owned(),
        image: cluster.spec.image.clone(),
        product_version,
        name: cluster_name,
        namespace,
        uid,
        cluster_config: validated_cluster_config,
        role_config: cluster.spec.nodes.role_config.clone(),
        role_group_configs,
    })
}

fn validate_cluster_config(
    cluster_config: OpenSearchClusterConfig,
) -> Result<OpenSearchClusterConfig> {
    validate_tls_config(&cluster_config.tls)?;
    Ok(cluster_config)
}

fn validate_tls_config(tls_config: &OpenSearchTls) -> Result<()> {
    TlsSecretClassName::from_str(&tls_config.secret_class).context(ParseTlsSecretClassNameSnafu)?;
    Ok(())
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

    Ok(RoleGroupConfig {
        // Kubernetes defaults to 1 if not set
        replicas: merged_role_group.replicas.unwrap_or(1),
        config: validated_config,
        config_overrides: merged_role_group.config.config_overrides,
        env_overrides: merged_role_group.config.env_overrides,
        cli_overrides: merged_role_group.config.cli_overrides,
        pod_overrides: merged_role_group.config.pod_overrides,
        product_specific_common_config: merged_role_group.config.product_specific_common_config,
    })
}
