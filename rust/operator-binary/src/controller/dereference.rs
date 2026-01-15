//! The dereference step in the OpenSearchCluster controller

use snafu::{ResultExt, Snafu};
use stackable_operator::{client::Client, crd::listener};
use strum::{EnumDiscriminants, IntoStaticStr};

use crate::{
    controller::{DereferencedObjects, build::role_builder},
    crd::v1alpha1,
    framework::{
        controller_utils::{get_cluster_name, get_namespace},
        types::{kubernetes::NamespaceName, operator::ClusterName},
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

    #[snafu(display("failed to fetch the discovery service listener"))]
    FetchDiscoveryServiceListener {
        source: stackable_operator::client::Error,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

/// Dereference additional objects that are required to build the cluster resources.
pub async fn dereference(
    client: &Client,
    cluster: &v1alpha1::OpenSearchCluster,
) -> Result<DereferencedObjects> {
    let cluster_name = get_cluster_name(cluster).context(GetClusterNameSnafu)?;
    let namespace = get_namespace(cluster).context(GetClusterNamespaceSnafu)?;

    let maybe_discovery_service_listener =
        fetch_discovery_service_listener(client, &cluster_name, &namespace).await?;

    Ok(DereferencedObjects {
        maybe_discovery_service_listener,
    })
}

async fn fetch_discovery_service_listener(
    client: &Client,
    cluster_name: &ClusterName,
    namespace: &NamespaceName,
) -> Result<Option<listener::v1alpha1::Listener>> {
    let discovery_service_listener_name =
        role_builder::discovery_service_listener_name(cluster_name);

    client
        .get_opt(discovery_service_listener_name.as_ref(), namespace.as_ref())
        .await
        .context(FetchDiscoveryServiceListenerSnafu)
}
