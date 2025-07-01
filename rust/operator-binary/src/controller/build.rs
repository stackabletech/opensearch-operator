use std::{marker::PhantomData, str::FromStr};

use stackable_operator::{
    builder::{
        configmap::ConfigMapBuilder,
        meta::ObjectMetaBuilder,
        pod::{PodBuilder, container::ContainerBuilder},
    },
    k8s_openapi::{
        DeepMerge,
        api::{
            apps::v1::{StatefulSet, StatefulSetSpec},
            core::v1::{
                ConfigMap, ConfigMapVolumeSource, Container, ContainerPort, PodTemplateSpec, Probe,
                Service, ServicePort, ServiceSpec, TCPSocketAction, Volume, VolumeMount,
            },
            policy::v1::PodDisruptionBudget,
        },
        apimachinery::pkg::{apis::meta::v1::LabelSelector, util::intstr::IntOrString},
    },
    kvp::{
        Label, Labels, ObjectLabels,
        consts::{STACKABLE_VENDOR_KEY, STACKABLE_VENDOR_VALUE},
    },
};

use super::{
    ContextNames, OpenSearchRoleGroupConfig, Prepared, Resources, RoleGroupName, ValidatedCluster,
    node_config::{CONFIGURATION_FILE_OPENSEARCH_YML, NodeConfig},
};
use crate::{
    crd::v1alpha1,
    framework::{
        IsLabelValue, RoleName,
        builder::pdb::pod_disruption_budget_builder_with_role,
        kvp::label::{recommended_labels, role_group_selector},
        to_qualified_role_group_name,
    },
};

const PDB_DEFAULT_MAX_UNAVAILABLE: u16 = 1;

// TODO Convert to RoleGroupBuilder
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
        let mut config_maps = vec![];
        let mut stateful_sets = vec![];
        let mut services = vec![];

        for (role_group_name, role_group_config) in &self.cluster.role_group_configs {
            // used for the name of the StatefulSet, role-group ConfigMap, ...
            let qualified_role_group_name =
                to_qualified_role_group_name(&self.cluster.name, &self.role_name, role_group_name);

            let config_map = self.build_role_group_config_map(
                &qualified_role_group_name,
                role_group_name,
                role_group_config,
            );
            let stateful_set = self.build_statefulset(
                &qualified_role_group_name,
                role_group_name,
                role_group_config,
            );

            let service =
                self.build_role_group_service(&qualified_role_group_name, role_group_name);

            config_maps.push(config_map);
            stateful_sets.push(stateful_set);
            services.push(service);
        }

        let cluster_manager_service = self.build_cluster_manager_service();
        services.push(cluster_manager_service);

        let pod_disruption_budgets = self.build_pdb().into_iter().collect();

        Resources {
            stateful_sets,
            services,
            config_maps,
            pod_disruption_budgets,
            status: PhantomData,
        }
    }

    fn build_role_group_config_map(
        &self,
        config_map_name: &str,
        role_group_name: &RoleGroupName,
        role_group_config: &OpenSearchRoleGroupConfig,
    ) -> ConfigMap {
        let metadata = ObjectMetaBuilder::new()
            .name(config_map_name)
            .namespace(&self.cluster.namespace)
            .ownerreference_from_resource(&self.cluster, None, Some(true))
            // TODO Fix
            .unwrap()
            .with_labels(self.build_recommended_labels(role_group_name))
            .build();

        ConfigMapBuilder::new()
            .metadata(metadata)
            .add_data(
                CONFIGURATION_FILE_OPENSEARCH_YML,
                self.node_config.static_opensearch_config(role_group_config),
            )
            .build()
            // TODO Fix
            .unwrap()
    }

    fn build_statefulset(
        &self,
        qualified_role_group_name: &str,
        role_group_name: &RoleGroupName,
        role_group_config: &OpenSearchRoleGroupConfig,
    ) -> StatefulSet {
        let metadata = ObjectMetaBuilder::new()
            .name(qualified_role_group_name)
            .namespace(&self.cluster.namespace)
            .ownerreference_from_resource(&self.cluster, None, Some(true))
            // TODO Fix
            .unwrap()
            .with_labels(self.build_recommended_labels(role_group_name))
            .build();

        let template = self.build_pod_template(
            qualified_role_group_name,
            role_group_name,
            role_group_config,
        );

        let statefulset_match_labels = role_group_selector(
            &self.cluster,
            &self.names.product_name,
            &self.role_name,
            role_group_name,
        );

        let spec = StatefulSetSpec {
            // Order does not matter for OpenSearch
            pod_management_policy: Some("Parallel".to_string()),
            replicas: Some(role_group_config.replicas as i32),
            selector: LabelSelector {
                match_labels: Some(statefulset_match_labels.into()),
                ..LabelSelector::default()
            },
            service_name: None,
            template,
            ..StatefulSetSpec::default()
        };

        StatefulSet {
            metadata,
            spec: Some(spec),
            status: None,
        }
    }

    fn build_pod_template(
        &self,
        qualified_role_group_name: &str,
        role_group_name: &RoleGroupName,
        role_group_config: &OpenSearchRoleGroupConfig,
    ) -> PodTemplateSpec {
        let mut builder = PodBuilder::new();

        let mut node_role_labels = Labels::new();
        for node_role in role_group_config.config.node_roles.iter() {
            node_role_labels
                .insert(Label::try_from((format!("{node_role}"), "true".to_string())).unwrap());
        }

        let metadata = ObjectMetaBuilder::new()
            .with_labels(self.build_recommended_labels(role_group_name))
            .with_labels(node_role_labels)
            .build();

        let container = self.build_container(role_group_config);

        let mut pod_template = builder
            .metadata(metadata)
            .add_container(container)
            .add_volume(Volume {
                name: "config".to_string(),
                config_map: Some(ConfigMapVolumeSource {
                    name: qualified_role_group_name.to_owned(),
                    ..Default::default()
                }),
                ..Default::default()
            })
            // TODO ?
            .unwrap()
            .build_template();

        pod_template.merge_from(role_group_config.pod_overrides.clone());

        pod_template
    }

    fn build_container(&self, role_group_config: &OpenSearchRoleGroupConfig) -> Container {
        let product_image = self
            .cluster
            .image
            .resolve("opensearch", crate::built_info::PKG_VERSION);

        // Probe values taken from the official Helm chart
        let startup_probe = Probe {
            failure_threshold: Some(30),
            initial_delay_seconds: Some(5),
            period_seconds: Some(10),
            tcp_socket: Some(TCPSocketAction {
                port: IntOrString::Int(9200),
                ..TCPSocketAction::default()
            }),
            timeout_seconds: Some(3),
            ..Probe::default()
        };
        let readiness_probe = Probe {
            failure_threshold: Some(3),
            period_seconds: Some(5),
            tcp_socket: Some(TCPSocketAction {
                port: IntOrString::Int(9200),
                ..TCPSocketAction::default()
            }),
            timeout_seconds: Some(3),
            ..Probe::default()
        };

        ContainerBuilder::new("opensearch")
            .expect("should be a valid container name")
            .image_from_product_image(&product_image)
            .command(vec![
                "/usr/share/opensearch/opensearch-docker-entrypoint.sh".to_owned(),
            ])
            .args(role_group_config.cli_overrides_to_vec())
            .add_env_vars(
                self.node_config
                    .environment_variables(role_group_config)
                    .into(),
            )
            .add_volume_mounts([VolumeMount {
                // TODO Use path and file constants
                mount_path: "/usr/share/opensearch/config/opensearch.yml".to_owned(),
                name: "config".to_owned(),
                read_only: Some(true),
                sub_path: Some("opensearch.yml".to_owned()),
                ..VolumeMount::default()
            }])
            // TODO ?
            .unwrap()
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
            .startup_probe(startup_probe)
            .readiness_probe(readiness_probe)
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

    fn build_role_group_service(
        &self,
        qualified_role_group_name: &str,
        role_group_name: &RoleGroupName,
    ) -> Service {
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

        // TODO Add metrics port and Prometheus label

        let metadata = ObjectMetaBuilder::new()
            .name(qualified_role_group_name)
            .namespace(&self.cluster.namespace)
            .ownerreference_from_resource(&self.cluster, None, Some(true))
            // TODO Fix
            .unwrap()
            .with_recommended_labels(ObjectLabels {
                owner: &self.cluster,
                app_name: &self.names.product_name.to_label_value(),
                app_version: &self.cluster.product_version.to_label_value(),
                operator_name: &self.names.operator_name.to_label_value(),
                controller_name: &self.names.controller_name.to_label_value(),
                role: &self.role_name.to_label_value(),
                role_group: &role_group_name.to_label_value(),
            })
            // TODO fix
            .unwrap()
            .build();

        let service_selector = Labels::role_group_selector(
            &self.cluster,
            &self.names.product_name.to_label_value(),
            &self.role_name.to_label_value(),
            &role_group_name.to_label_value(),
        )
        // TODO fix
        .unwrap();

        let service_spec = ServiceSpec {
            // Internal communication does not need to be exposed
            type_: Some("ClusterIP".to_string()),
            cluster_ip: Some("None".to_string()),
            ports: Some(ports),
            selector: Some(service_selector.into()),
            publish_not_ready_addresses: Some(true),
            ..ServiceSpec::default()
        };

        Service {
            metadata,
            spec: Some(service_spec),
            status: None,
        }
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

        let service_selector = [(
            v1alpha1::NodeRole::ClusterManager.to_string(),
            "true".to_owned(),
        )]
        .into();

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
