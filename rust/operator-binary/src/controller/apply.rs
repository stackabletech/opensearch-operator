use snafu::{ResultExt, Snafu};
use stackable_operator::{client::Client, cluster_resources::ClusterResourceApplyStrategy};
use strum::{EnumDiscriminants, IntoStaticStr};

use super::{Applied, ContextNames, Prepared, Resources};
use crate::framework::{
    HasNamespace, HasObjectName, HasUid, cluster_resources::cluster_resources_new,
};

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
pub enum Error {
    #[snafu(display("failed to apply resource"))]
    ApplyResource {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to delete orphaned resources"))]
    DeleteOrphanedResources {
        source: stackable_operator::cluster_resources::Error,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

pub async fn apply(
    client: &Client,
    names: &ContextNames,
    cluster: &(impl HasObjectName + HasNamespace + HasUid),
    apply_strategy: ClusterResourceApplyStrategy,
    resources: Resources<Prepared>,
) -> Result<Resources<Applied>> {
    let mut cluster_resources = cluster_resources_new(
        &names.app_name,
        &names.operator_name,
        &names.controller_name,
        cluster,
        apply_strategy,
    );

    let mut applied_resources = Resources::new();
    for stateful_set in resources.stateful_sets {
        let applied_stateful_set = cluster_resources
            .add(client, stateful_set)
            .await
            .context(ApplyResourceSnafu)?;
        applied_resources.stateful_sets.push(applied_stateful_set);
    }

    cluster_resources
        .delete_orphaned_resources(client)
        .await
        .context(DeleteOrphanedResourcesSnafu)?;

    Ok(applied_resources)
}
