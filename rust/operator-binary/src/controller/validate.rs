use std::{collections::BTreeMap, str::FromStr};

use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::kube::{Resource, ResourceExt};
use strum::{EnumDiscriminants, IntoStaticStr};

use super::{AppVersion, RoleGroupName, ValidatedCluster};
use crate::{crd::v1alpha1, framework::ClusterName};

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
pub enum Error {
    // TODO Improve message
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

    #[snafu(display("failed to set recommended labels"))]
    RecommendedLabels {
        source: stackable_operator::kvp::LabelError,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

// no client needed
pub fn validate(cluster: &v1alpha1::OpenSearchCluster) -> Result<ValidatedCluster> {
    let raw_cluster_name = cluster.meta().name.clone().context(GetClusterNameSnafu)?;
    let cluster_name = ClusterName::from_str(&raw_cluster_name).context(ParseClusterNameSnafu)?;

    let namespace = cluster.namespace().context(GetClusterNamespaceSnafu)?;

    let uid = cluster.uid().context(GetClusterUidSnafu)?;

    let product_version = AppVersion::from_str(cluster.spec.image.product_version())
        .context(ParseProductVersionSnafu)?;

    let mut role_group_configs = BTreeMap::new();
    for (raw_role_group_name, role_group_config) in &cluster.spec.nodes.role_groups {
        let role_group_name =
            RoleGroupName::from_str(raw_role_group_name).context(ParseRoleGroupNameSnafu)?;
        role_group_configs.insert(role_group_name, role_group_config.clone());

        // TODO merge configs
    }

    Ok(ValidatedCluster {
        origin: cluster.to_owned(),
        image: cluster.spec.image.clone(),
        product_version,
        name: cluster_name,
        namespace,
        uid,
        role_config: cluster.spec.nodes.role_config.clone(),
        role_group_configs,
    })
}
