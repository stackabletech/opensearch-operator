use snafu::{ResultExt, Snafu};
use stackable_operator::{client::Client, cluster_resources::ClusterResourceApplyStrategy};
use strum::{EnumDiscriminants, IntoStaticStr};

use super::{Applied, Prepared, Resources};
use crate::framework::{
    AppName, ControllerName, HasNamespace, HasObjectName, HasUid, OperatorName,
    cluster_resources::cluster_resources_new,
};

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
pub enum Error {
    #[snafu(display("failed to delete orphaned resources"))]
    DeleteOrphanedResources {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to update status"))]
    ApplyStatus {
        source: stackable_operator::client::Error,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

pub async fn apply(
    client: &Client,
    // app_name, operator_name, ... in context?
    app_name: &AppName,
    operator_name: &OperatorName,
    controller_name: &ControllerName,
    cluster: &(impl HasObjectName + HasNamespace + HasUid),
    // ref?
    apply_strategy: ClusterResourceApplyStrategy,
    resources: Resources<Prepared>,
) -> Result<Resources<Applied>> {
    let mut cluster_resources = cluster_resources_new(
        app_name,
        operator_name,
        controller_name,
        cluster,
        apply_strategy,
    );

    let mut applied_resources = Resources::new();
    for stateful_set in resources.stateful_sets {
        let applied_stateful_set = cluster_resources.add(client, stateful_set).await.unwrap();
        applied_resources.stateful_sets.push(applied_stateful_set);
    }

    cluster_resources
        .delete_orphaned_resources(client)
        .await
        .context(DeleteOrphanedResourcesSnafu)?;

    Ok(applied_resources)
}
