use std::{collections::BTreeMap, str::FromStr};

use snafu::{ResultExt, Snafu};
use stackable_operator::kube::ResourceExt;
use strum::{EnumDiscriminants, IntoStaticStr};

use super::{AppVersion, RoleGroupName, ValidatedCluster};
use crate::{crd::v1alpha1, framework::ClusterName};

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
pub enum Error {
    #[snafu(display("failed to set recommended labels"))]
    InvalidClusterName { source: crate::framework::Error },

    #[snafu(display("failed to set recommended labels"))]
    RecommendedLabels {
        source: stackable_operator::kvp::LabelError,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

// no client needed
pub fn validate(cluster: &v1alpha1::OpenSearchCluster) -> Result<ValidatedCluster> {
    let cluster_name =
        ClusterName::from_str(&cluster.name_unchecked()).context(InvalidClusterNameSnafu)?;

    let product_version = AppVersion::from_str(cluster.spec.image.product_version()).expect("oops");

    let mut role_group_configs = BTreeMap::new();
    for (raw_role_group_name, role_group_config) in &cluster.spec.nodes.role_groups {
        let role_group_name = RoleGroupName::from_str(raw_role_group_name).unwrap();
        role_group_configs.insert(role_group_name, role_group_config.clone());

        // TODO merge configs
    }

    Ok(ValidatedCluster {
        origin: cluster.to_owned(),
        image: cluster.spec.image.clone(),
        product_version,
        name: cluster_name,
        namespace: cluster.namespace().expect("muss da sein"),
        role_config: cluster.spec.nodes.role_config.clone(),
        role_group_configs,
    })
}
