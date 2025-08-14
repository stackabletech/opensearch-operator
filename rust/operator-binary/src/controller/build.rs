use std::marker::PhantomData;

use role_builder::RoleBuilder;

use crate::controller::build::job_builder::JobBuilder;

use super::{ContextNames, KubernetesResources, Prepared, ValidatedCluster};

pub mod job_builder;
pub mod node_config;
pub mod role_builder;
pub mod role_group_builder;

pub fn build(names: &ContextNames, cluster: ValidatedCluster) -> KubernetesResources<Prepared> {
    let mut config_maps = vec![];
    let mut stateful_sets = vec![];
    let mut services = vec![];
    let mut listeners = vec![];
    let mut jobs = vec![];

    let role_builder = RoleBuilder::new(cluster.clone(), names);
    let job_builder = JobBuilder::new(cluster.clone(), names);

    for role_group_builder in role_builder.role_group_builders() {
        config_maps.push(role_group_builder.build_config_map());
        stateful_sets.push(role_group_builder.build_stateful_set());
        services.push(role_group_builder.build_headless_service());
        listeners.push(role_group_builder.build_listener());
    }

    let cluster_manager_service = role_builder.build_cluster_manager_service();
    services.push(cluster_manager_service);

    let service_accounts = vec![role_builder.build_service_account()];

    let role_bindings = vec![role_builder.build_role_binding()];

    let pod_disruption_budgets = role_builder.build_pdb().into_iter().collect();

    jobs.push(job_builder.build_run_securityadmin_job());

    KubernetesResources {
        stateful_sets,
        services,
        listeners,
        config_maps,
        service_accounts,
        role_bindings,
        pod_disruption_budgets,
        jobs,
        status: PhantomData,
    }
}
