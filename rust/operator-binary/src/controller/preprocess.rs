use snafu::Snafu;
use stackable_operator::{
    commons::resources::{PvcConfigFragment, ResourcesFragment},
    k8s_openapi::apimachinery::pkg::api::resource::Quantity,
    role_utils::{CommonConfiguration, RoleGroup},
};
use strum::{EnumDiscriminants, IntoStaticStr};
use tracing::info;

use crate::{
    crd::{NodeRoles, v1alpha1},
    framework::role_utils::GenericProductSpecificCommonConfig,
};

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
pub enum Error {
    #[snafu(display("failed to get the cluster name"))]
    GetClusterName {
        source: crate::framework::controller_utils::Error,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

pub fn preprocess(mut cluster: v1alpha1::OpenSearchCluster) -> Result<v1alpha1::OpenSearchCluster> {
    let security = &cluster.spec.cluster_config.security;
    if security.enabled
        && !security.config.is_only_managed_by_api()
        && !cluster
            .spec
            .nodes
            .role_groups
            .contains_key(&security.managing_role_group.to_string())
    {
        info!(
            "The security configuration is managed by the role group \"{role_group}\". \
            This role group was not specified explicitly and will be created.",
            role_group = security.managing_role_group
        );

        let role_group =
            RoleGroup::<v1alpha1::OpenSearchConfigFragment, GenericProductSpecificCommonConfig> {
                config: CommonConfiguration {
                    config: v1alpha1::OpenSearchConfigFragment {
                        discovery_service_exposed: Some(false),
                        node_roles: Some(NodeRoles(vec![])),
                        resources: ResourcesFragment {
                            storage: v1alpha1::StorageConfigFragment {
                                data: PvcConfigFragment {
                                    capacity: Some(Quantity("100Mi".to_owned())),
                                    ..PvcConfigFragment::default()
                                },
                            },
                            ..ResourcesFragment::default()
                        },
                        ..v1alpha1::OpenSearchConfigFragment::default()
                    },
                    ..CommonConfiguration::default()
                },
                replicas: Some(1),
            };

        cluster
            .spec
            .nodes
            .role_groups
            .insert(security.managing_role_group.to_string(), role_group);
    }

    Ok(cluster)
}
