use std::{marker::PhantomData, str::FromStr};

use stackable_operator::{
    builder::{
        meta::ObjectMetaBuilder,
        pod::{PodBuilder, container::ContainerBuilder},
    },
    k8s_openapi::{
        api::{
            apps::v1::{StatefulSet, StatefulSetSpec},
            core::v1::{Container, PodTemplateSpec},
            policy::v1::PodDisruptionBudget,
        },
        apimachinery::pkg::apis::meta::v1::LabelSelector,
    },
    kvp::Labels,
};

use super::{ContextNames, Prepared, Resources, RoleGroupConfig, RoleGroupName, ValidatedCluster};
use crate::framework::{
    RoleName,
    builder::pdb::pod_disruption_budget_builder_with_role,
    kvp::label::{recommended_labels, role_group_selector},
    to_qualified_role_group_name,
};

const PDB_DEFAULT_MAX_UNAVAILABLE: u16 = 1;

pub struct Builder<'a> {
    names: &'a ContextNames,
    role_name: RoleName,
    cluster: ValidatedCluster,
}

impl<'a> Builder<'a> {
    pub fn new(names: &'a ContextNames, cluster: ValidatedCluster) -> Builder<'a> {
        Builder {
            names,
            role_name: RoleName::from_str("nodes").unwrap(),
            cluster,
        }
    }

    pub fn build(&self) -> Resources<Prepared> {
        let stateful_sets = self
            .cluster
            .role_group_configs
            .iter()
            .map(|(role_group_name, role_group_config)| {
                self.build_statefulset(role_group_name, role_group_config)
            })
            .collect();

        let pod_disruption_budgets = self.build_pdb().into_iter().collect();

        Resources {
            stateful_sets,
            pod_disruption_budgets,
            status: PhantomData,
        }
    }

    fn build_statefulset(
        &self,
        role_group_name: &RoleGroupName,
        role_group_config: &RoleGroupConfig,
    ) -> StatefulSet {
        let metadata = ObjectMetaBuilder::new()
            .name(to_qualified_role_group_name(
                &self.cluster.name,
                &self.role_name,
                role_group_name,
            ))
            .namespace(&self.cluster.namespace)
            .with_labels(self.build_recommended_labels(role_group_name))
            .build();

        let template = self.build_pod_template(role_group_name);

        let statefulset_match_labels = role_group_selector(
            &self.cluster,
            &self.names.app_name,
            &self.role_name,
            role_group_name,
        );

        let spec = StatefulSetSpec {
            // Order does not matter for OpenSearch
            pod_management_policy: Some("Parallel".to_string()),
            replicas: role_group_config.replicas.map(i32::from),
            selector: LabelSelector {
                match_labels: Some(statefulset_match_labels.into()),
                ..LabelSelector::default()
            },
            service_name: None,
            template,
            ..StatefulSetSpec::default()
        };

        // TODO Implement overrides

        StatefulSet {
            metadata,
            spec: Some(spec),
            status: None,
        }
    }

    fn build_pod_template(&self, role_group_name: &RoleGroupName) -> PodTemplateSpec {
        let mut builder = PodBuilder::new();

        let metadata = ObjectMetaBuilder::new()
            .with_labels(self.build_recommended_labels(role_group_name))
            .build();

        let container = self.build_container();

        builder
            .metadata(metadata)
            .add_container(container)
            .build_template()
    }

    fn build_container(&self) -> Container {
        let product_image = self
            .cluster
            .image
            .resolve("opensearch", crate::built_info::PKG_VERSION);

        // TODO ContainerName as typed string?
        ContainerBuilder::new("opensearch")
            .expect("ContainerBuilder not created")
            .image_from_product_image(&product_image)
            .add_env_var("OPENSEARCH_INITIAL_ADMIN_PASSWORD", "super@Secret1")
            .add_env_var("cluster.initial_master_nodes", "opensearch-0")
            .build()
    }

    fn build_recommended_labels(&self, role_group_name: &RoleGroupName) -> Labels {
        recommended_labels(
            &self.cluster,
            &self.names.app_name,
            &self.cluster.product_version,
            &self.names.operator_name,
            &self.names.controller_name,
            &self.role_name,
            role_group_name,
        )
    }

    fn build_pdb(&self) -> Option<PodDisruptionBudget> {
        let pdb_config = &self.cluster.role_config.pod_disruption_budget;

        if pdb_config.enabled {
            let max_unavailable = pdb_config
                .max_unavailable
                .unwrap_or(PDB_DEFAULT_MAX_UNAVAILABLE);
            Some(
                pod_disruption_budget_builder_with_role(
                    &self.cluster,
                    &self.names.app_name,
                    &self.role_name,
                    &self.names.operator_name,
                    &self.names.controller_name,
                )
                .with_max_unavailable(max_unavailable)
                .build(),
            )
        } else {
            None
        }
    }
}
