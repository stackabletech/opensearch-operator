use std::marker::PhantomData;

use snafu::{ResultExt, Snafu};
use stackable_operator::{
    client::Client,
    cluster_resources::{ClusterResource, ClusterResourceApplyStrategy, ClusterResources},
};
use strum::{EnumDiscriminants, IntoStaticStr};

use super::{Applied, ContextNames, KubernetesResources, Prepared};
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

pub struct Applier<'a> {
    client: &'a Client,
    cluster_resources: ClusterResources,
}

impl<'a> Applier<'a> {
    pub fn new(
        client: &'a Client,
        names: &ContextNames,
        cluster: &(impl HasObjectName + HasNamespace + HasUid),
        apply_strategy: ClusterResourceApplyStrategy,
    ) -> Applier<'a> {
        let cluster_resources = cluster_resources_new(
            &names.product_name,
            &names.operator_name,
            &names.controller_name,
            cluster,
            apply_strategy,
        );

        Applier {
            client,
            cluster_resources,
        }
    }

    pub async fn apply(
        mut self,
        resources: KubernetesResources<Prepared>,
    ) -> Result<KubernetesResources<Applied>> {
        let stateful_sets = self.add_resources(resources.stateful_sets).await?;

        let services = self.add_resources(resources.services).await?;

        let config_maps = self.add_resources(resources.config_maps).await?;

        let service_accounts = self.add_resources(resources.service_accounts).await?;

        let role_bindings = self.add_resources(resources.role_bindings).await?;

        let pod_disruption_budgets = self.add_resources(resources.pod_disruption_budgets).await?;

        self.cluster_resources
            .delete_orphaned_resources(self.client)
            .await
            .context(DeleteOrphanedResourcesSnafu)?;

        Ok(KubernetesResources {
            stateful_sets,
            services,
            config_maps,
            service_accounts,
            role_bindings,
            pod_disruption_budgets,
            status: PhantomData,
        })
    }

    async fn add_resources<T: ClusterResource + Sync>(
        &mut self,
        resources: Vec<T>,
    ) -> Result<Vec<T>> {
        let mut applied_resources = vec![];

        for resource in resources {
            let applied_resource = self
                .cluster_resources
                .add(self.client, resource)
                .await
                .context(ApplyResourceSnafu)?;
            applied_resources.push(applied_resource);
        }

        Ok(applied_resources)
    }
}
