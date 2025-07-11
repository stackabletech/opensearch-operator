use std::{marker::PhantomData, str::FromStr};

use role_builder::RoleBuilder;

use super::{ContextNames, Prepared, Resources, ValidatedCluster};
use crate::framework::RoleName;

pub mod node_config;
pub mod role_builder;
pub mod role_group_builder;

pub fn build(names: &ContextNames, cluster: ValidatedCluster) -> Resources<Prepared> {
    let mut config_maps = vec![];
    let mut stateful_sets = vec![];
    let mut services = vec![];

    let role_name = RoleName::from_str("nodes").expect("should be a valid role name");

    let role_builder = RoleBuilder::new(role_name, cluster.clone(), names);

    for role_group_builder in role_builder.role_group_builders() {
        config_maps.push(role_group_builder.build_config_map());
        stateful_sets.push(role_group_builder.build_stateful_set());
        services.push(role_group_builder.build_headless_service());
    }

    let cluster_manager_service = role_builder.build_cluster_manager_service();
    services.push(cluster_manager_service);

    let service_accounts = vec![role_builder.build_service_account()];

    let role_bindings = vec![role_builder.build_role_binding()];

    let pod_disruption_budgets = role_builder.build_pdb().into_iter().collect();

    Resources {
        stateful_sets,
        services,
        config_maps,
        service_accounts,
        role_bindings,
        pod_disruption_budgets,
        status: PhantomData,
    }
}
