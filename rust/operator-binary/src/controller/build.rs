use std::{marker::PhantomData, str::FromStr};

use stackable_operator::{
    builder::{
        meta::ObjectMetaBuilder,
        pod::{
            PodBuilder,
            container::{ContainerBuilder, FieldPathEnvVar},
        },
    },
    k8s_openapi::{
        api::{
            apps::v1::{StatefulSet, StatefulSetSpec},
            core::v1::{
                Container, ContainerPort, PodTemplateSpec, Service, ServicePort, ServiceSpec,
            },
            policy::v1::PodDisruptionBudget,
        },
        apimachinery::pkg::apis::meta::v1::LabelSelector,
    },
    kvp::{
        Label, Labels,
        consts::{STACKABLE_VENDOR_KEY, STACKABLE_VENDOR_VALUE},
    },
};

use super::{
    ContextNames, Prepared, Resources, RoleGroupConfig, RoleGroupName, ValidatedCluster,
    node_config::{
        DISCOVERY_SEED_HOSTS, DISCOVERY_TYPE, INITIAL_CLUSTER_MANAGER_NODES, NETWORK_HOST,
        NODE_NAME, NODE_ROLES, NodeConfig,
    },
};
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
    node_config: NodeConfig,
}

impl<'a> Builder<'a> {
    pub fn new(names: &'a ContextNames, cluster: ValidatedCluster) -> Builder<'a> {
        let role_name = RoleName::from_str("nodes").expect("should be a valid role name");
        Builder {
            names,
            role_name: role_name.clone(),
            cluster: cluster.clone(),
            node_config: NodeConfig::new(role_name, cluster),
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

        let services = vec![self.build_cluster_manager_service()];

        // TODO Create further services

        let pod_disruption_budgets = self.build_pdb().into_iter().collect();

        Resources {
            stateful_sets,
            services,
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

        let template = self.build_pod_template(role_group_name, role_group_config);

        let statefulset_match_labels = role_group_selector(
            &self.cluster,
            &self.names.product_name,
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

    fn build_pod_template(
        &self,
        role_group_name: &RoleGroupName,
        role_group_config: &RoleGroupConfig,
    ) -> PodTemplateSpec {
        let mut builder = PodBuilder::new();

        let opensearch_config = &role_group_config.config.config;
        let mut node_role_labels = Labels::new();
        for node_role in opensearch_config.node_roles.iter() {
            node_role_labels
                .insert(Label::try_from((format!("{node_role}"), "true".to_string())).unwrap());
        }

        let metadata = ObjectMetaBuilder::new()
            .with_labels(self.build_recommended_labels(role_group_name))
            .with_labels(node_role_labels)
            .build();

        let container = self.build_container(role_group_config);

        builder
            .metadata(metadata)
            .add_container(container)
            .build_template()
    }

    fn build_container(&self, role_group_config: &RoleGroupConfig) -> Container {
        let product_image = self
            .cluster
            .image
            .resolve("opensearch", crate::built_info::PKG_VERSION);

        let opensearch_config = &role_group_config.config.config;

        ContainerBuilder::new("opensearch")
            .expect("should be a valid container name")
            .image_from_product_image(&product_image)
            .add_env_var(
                DISCOVERY_SEED_HOSTS,
                self.node_config.discovery_seed_hosts(),
            )
            .add_env_var(DISCOVERY_TYPE, self.node_config.discovery_type())
            .add_env_var(
                INITIAL_CLUSTER_MANAGER_NODES,
                self.node_config
                    .initial_cluster_manager_nodes(&opensearch_config.node_roles),
            )
            .add_env_var(NETWORK_HOST, self.node_config.network_host())
            // TODO Is this option also required on a proper custom image?
            .add_env_var("OPENSEARCH_INITIAL_ADMIN_PASSWORD", "super@Secret1")
            // Set the OpenSearch node name to the Pod name.
            // The node name is used e.g. for `{INITIAL_CLUSTER_MANAGER_NODES}`.
            .add_env_var_from_field_path(NODE_NAME, FieldPathEnvVar::Name)
            .add_env_var(
                NODE_ROLES,
                self.node_config.node_roles(&opensearch_config.node_roles),
            )
            .add_container_ports(vec![
                ContainerPort {
                    name: Some("http".to_owned()),
                    container_port: 9200,
                    ..ContainerPort::default()
                },
                ContainerPort {
                    name: Some("transport".to_owned()),
                    container_port: 9300,
                    ..ContainerPort::default()
                },
            ])
            .build()
    }

    fn build_recommended_labels(&self, role_group_name: &RoleGroupName) -> Labels {
        recommended_labels(
            &self.cluster,
            &self.names.product_name,
            &self.cluster.product_version,
            &self.names.operator_name,
            &self.names.controller_name,
            &self.role_name,
            role_group_name,
        )
    }

    fn build_cluster_manager_service(&self) -> Service {
        let ports = vec![
            ServicePort {
                name: Some("http".to_owned()),
                port: 9200,
                ..ServicePort::default()
            },
            ServicePort {
                name: Some("transport".to_owned()),
                port: 9300,
                ..ServicePort::default()
            },
        ];

        // Well-known Kubernetes labels
        let mut labels = Labels::role_selector(
            &self.cluster,
            &self.names.product_name.to_string(),
            &self.role_name.to_string(),
        )
        .unwrap();

        let managed_by = Label::managed_by(
            &self.names.operator_name.to_string(),
            &self.names.controller_name.to_string(),
        )
        .unwrap();
        let version = Label::version(&self.cluster.product_version.to_string()).unwrap();

        labels.insert(managed_by);
        labels.insert(version);

        // Stackable-specific labels
        labels
            .parse_insert((STACKABLE_VENDOR_KEY, STACKABLE_VENDOR_VALUE))
            .unwrap();

        let metadata = ObjectMetaBuilder::new()
            .name(format!("{}-cluster-manager", self.cluster.name))
            .namespace(&self.cluster.namespace)
            .ownerreference_from_resource(&self.cluster, None, Some(true))
            // TODO Fix
            .unwrap()
            .with_labels(labels)
            .build();

        let service_selector = [("cluster-manager".to_owned(), "true".to_owned())].into();

        let service_spec = ServiceSpec {
            // Internal communication does not need to be exposed
            type_: Some("ClusterIP".to_string()),
            cluster_ip: Some("None".to_string()),
            ports: Some(ports),
            selector: Some(service_selector),
            publish_not_ready_addresses: Some(true),
            ..ServiceSpec::default()
        };

        Service {
            metadata,
            spec: Some(service_spec),
            status: None,
        }
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
                    &self.names.product_name,
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
