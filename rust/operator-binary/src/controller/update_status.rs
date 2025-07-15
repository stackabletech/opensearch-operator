use snafu::{ResultExt, Snafu};
use stackable_operator::{
    client::Client,
    status::condition::{
        compute_conditions, operations::ClusterOperationsConditionBuilder,
        statefulset::StatefulSetConditionBuilder,
    },
};
use strum::{EnumDiscriminants, IntoStaticStr};

use super::{Applied, ContextNames, KubernetesResources};
use crate::crd::v1alpha1::{self, OpenSearchClusterStatus};

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
pub enum Error {
    #[snafu(display("failed to create cluster resources"))]
    CreateClusterResources {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to delete orphaned resources"))]
    DeleteOrphanedResources {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to update status"))]
    UpdateStatus {
        source: stackable_operator::client::Error,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

pub async fn update_status(
    client: &Client,
    names: &ContextNames,
    cluster: &v1alpha1::OpenSearchCluster,
    applied_resources: KubernetesResources<Applied>,
) -> Result<()> {
    let mut stateful_set_condition_builder = StatefulSetConditionBuilder::default();
    for stateful_set in applied_resources.stateful_sets {
        stateful_set_condition_builder.add(stateful_set);
    }

    let cluster_operation_cond_builder =
        ClusterOperationsConditionBuilder::new(&cluster.spec.cluster_operation);

    let status = OpenSearchClusterStatus {
        conditions: compute_conditions(
            cluster,
            &[
                &stateful_set_condition_builder,
                &cluster_operation_cond_builder,
            ],
        ),
        discovery_hash: None,
    };

    client
        .apply_patch_status(&format!("{}", names.operator_name), cluster, &status)
        .await
        .context(UpdateStatusSnafu)?;

    Ok(())
}
