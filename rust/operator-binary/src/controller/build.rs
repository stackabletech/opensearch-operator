use std::{marker::PhantomData, str::FromStr};

use stackable_operator::{
    builder::{
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
        Label, Labels,
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
        ClusterName, OBJECT_NAME_MAX_LENGTH, RoleName,
        builder::{
            meta::ownerreference_from_resource, pdb::pod_disruption_budget_builder_with_role,
        },
        kvp::label::{recommended_labels, role_group_selector},
        to_qualified_role_group_name,
    },
};

const PDB_DEFAULT_MAX_UNAVAILABLE: u16 = 1;
const CONFIG_VOLUME_NAME: &str = "config";
const DATA_VOLUME_NAME: &str = "data";
const HTTP_PORT_NAME: &str = "http";
const HTTP_PORT: u16 = 9200;
const TRANSPORT_PORT_NAME: &str = "transport";
const TRANSPORT_PORT: u16 = 9300;
const METRICS_PORT_NAME: &str = "metrics";
const METRICS_PORT: u16 = 9600;

struct RoleBuilder<'a> {
    names: &'a ContextNames,
    role_name: RoleName,
    cluster: ValidatedCluster,
}

impl<'a> RoleBuilder<'a> {
    fn new(
        names: &'a ContextNames,
        role_name: RoleName,
        cluster: ValidatedCluster,
    ) -> RoleBuilder<'a> {
        RoleBuilder {
            names,
            role_name: role_name.clone(),
            cluster: cluster.clone(),
        }
    }

    fn role_group_builders(&self) -> Vec<RoleGroupBuilder> {
        self.cluster
            .role_group_configs
            .iter()
            .map(|(role_group_name, role_group_config)| {
                RoleGroupBuilder::new(
                    self.names,
                    self.role_name.clone(),
                    self.cluster.clone(),
                    role_group_name.clone(),
                    role_group_config.clone(),
                    self.discovery_service_name(),
                )
            })
            .collect()
    }

    fn build_cluster_manager_service(&self) -> Service {
        let ports = vec![
            ServicePort {
                name: Some(HTTP_PORT_NAME.to_owned()),
                port: HTTP_PORT.into(),
                ..ServicePort::default()
            },
            ServicePort {
                name: Some(TRANSPORT_PORT_NAME.to_owned()),
                port: TRANSPORT_PORT.into(),
                ..ServicePort::default()
            },
            ServicePort {
                name: Some(METRICS_PORT_NAME.to_owned()),
                port: METRICS_PORT.into(),
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
            .name(self.discovery_service_name())
            .namespace(&self.cluster.namespace)
            .ownerreference(ownerreference_from_resource(
                &self.cluster,
                None,
                Some(true),
            ))
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

    fn discovery_service_name(&self) -> String {
        const SUFFIX: &str = "-cluster-manager";

        // Compile-time check
        const _: () = assert!(
            ClusterName::MAX_LENGTH + SUFFIX.len() <= OBJECT_NAME_MAX_LENGTH,
            "The resource name `<cluster_name>-cluster-manager` must not exceed 253 characters."
        );

        format!("{}{SUFFIX}", self.cluster.name)
    }
}

// Path in opensearchproject/opensearch:3.0.0
const OPENSEARCH_BASE_PATH: &str = "/usr/share/opensearch";

struct RoleGroupBuilder<'a> {
    names: &'a ContextNames,
    role_name: RoleName,
    cluster: ValidatedCluster,
    node_config: NodeConfig,
    qualified_role_group_name: String,
    role_group_name: RoleGroupName,
    role_group_config: OpenSearchRoleGroupConfig,
}

impl<'a> RoleGroupBuilder<'a> {
    fn new(
        names: &'a ContextNames,
        role_name: RoleName,
        cluster: ValidatedCluster,
        role_group_name: RoleGroupName,
        role_group_config: OpenSearchRoleGroupConfig,
        discovery_service_name: String,
    ) -> RoleGroupBuilder<'a> {
        // used for the name of the StatefulSet, role-group ConfigMap, ...
        let qualified_role_group_name =
            to_qualified_role_group_name(&cluster.name, &role_name, &role_group_name);

        RoleGroupBuilder {
            names,
            role_name: role_name.clone(),
            cluster: cluster.clone(),
            node_config: NodeConfig::new(
                role_name,
                cluster,
                role_group_config.clone(),
                discovery_service_name,
            ),
            qualified_role_group_name,
            role_group_name,
            role_group_config,
        }
    }

    fn build_config_map(&self) -> ConfigMap {
        let metadata = ObjectMetaBuilder::new()
            .name(self.qualified_role_group_name.clone())
            .namespace(&self.cluster.namespace)
            .ownerreference(ownerreference_from_resource(
                &self.cluster,
                None,
                Some(true),
            ))
            .with_labels(self.build_recommended_labels())
            .build();

        let data = [(
            CONFIGURATION_FILE_OPENSEARCH_YML.to_owned(),
            self.node_config.static_opensearch_config(),
        )]
        .into();

        ConfigMap {
            metadata,
            data: Some(data),
            ..ConfigMap::default()
        }
    }

    fn build_statefulset(&self) -> StatefulSet {
        let metadata = ObjectMetaBuilder::new()
            .name(self.qualified_role_group_name.clone())
            .namespace(&self.cluster.namespace)
            .ownerreference(ownerreference_from_resource(
                &self.cluster,
                None,
                Some(true),
            ))
            .with_labels(self.build_recommended_labels())
            .build();

        let statefulset_match_labels = role_group_selector(
            &self.cluster,
            &self.names.product_name,
            &self.role_name,
            &self.role_group_name,
        );

        let template = self.build_pod_template();

        let data_volume_claim_template = self
            .role_group_config
            .config
            .resources
            .storage
            .data
            // TODO Compare name with Helm chart
            .build_pvc(DATA_VOLUME_NAME, Some(vec!["ReadWriteOnce"]));

        let spec = StatefulSetSpec {
            // Order does not matter for OpenSearch
            pod_management_policy: Some("Parallel".to_string()),
            replicas: Some(self.role_group_config.replicas.into()),
            selector: LabelSelector {
                match_labels: Some(statefulset_match_labels.into()),
                ..LabelSelector::default()
            },
            service_name: None,
            template,
            volume_claim_templates: Some(vec![data_volume_claim_template]),
            ..StatefulSetSpec::default()
        };

        StatefulSet {
            metadata,
            spec: Some(spec),
            status: None,
        }
    }

    fn build_pod_template(&self) -> PodTemplateSpec {
        let mut builder = PodBuilder::new();

        let mut node_role_labels = Labels::new();
        for node_role in self.role_group_config.config.node_roles.iter() {
            node_role_labels
                .insert(Label::try_from((format!("{node_role}"), "true".to_string())).unwrap());
        }

        let metadata = ObjectMetaBuilder::new()
            .with_labels(self.build_recommended_labels())
            .with_labels(node_role_labels)
            .build();

        let container = self.build_container(&self.role_group_config);

        let mut pod_template = builder
            .metadata(metadata)
            .add_container(container)
            .add_volume(Volume {
                name: CONFIG_VOLUME_NAME.to_owned(),
                config_map: Some(ConfigMapVolumeSource {
                    name: self.qualified_role_group_name.clone(),
                    ..Default::default()
                }),
                ..Default::default()
            })
            .expect("The volume names are statically defined and there should be no duplicates.")
            .build_template();

        pod_template.merge_from(self.role_group_config.pod_overrides.clone());

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
                port: IntOrString::String(HTTP_PORT_NAME.to_owned()),
                ..TCPSocketAction::default()
            }),
            timeout_seconds: Some(3),
            ..Probe::default()
        };
        let readiness_probe = Probe {
            failure_threshold: Some(3),
            period_seconds: Some(5),
            tcp_socket: Some(TCPSocketAction {
                port: IntOrString::String(HTTP_PORT_NAME.to_owned()),
                ..TCPSocketAction::default()
            }),
            timeout_seconds: Some(3),
            ..Probe::default()
        };

        ContainerBuilder::new("opensearch")
            .expect("should be a valid container name")
            .image_from_product_image(&product_image)
            .command(vec![format!(
                "{OPENSEARCH_BASE_PATH}/opensearch-docker-entrypoint.sh"
            )])
            .args(role_group_config.cli_overrides_to_vec())
            .add_env_vars(self.node_config.environment_variables().into())
            .add_volume_mounts([
                VolumeMount {
                    mount_path: format!(
                        "{OPENSEARCH_BASE_PATH}/config/{CONFIGURATION_FILE_OPENSEARCH_YML}"
                    ),
                    name: CONFIG_VOLUME_NAME.to_owned(),
                    read_only: Some(true),
                    sub_path: Some(CONFIGURATION_FILE_OPENSEARCH_YML.to_owned()),
                    ..VolumeMount::default()
                },
                VolumeMount {
                    mount_path: format!("{OPENSEARCH_BASE_PATH}/data"),
                    name: DATA_VOLUME_NAME.to_owned(),
                    ..VolumeMount::default()
                },
            ])
            .expect("The mount paths are statically defined and there should be no duplicates.")
            .add_container_ports(vec![
                ContainerPort {
                    name: Some(HTTP_PORT_NAME.to_owned()),
                    container_port: HTTP_PORT.into(),
                    ..ContainerPort::default()
                },
                ContainerPort {
                    name: Some(TRANSPORT_PORT_NAME.to_owned()),
                    container_port: TRANSPORT_PORT.into(),
                    ..ContainerPort::default()
                },
                ContainerPort {
                    name: Some(METRICS_PORT_NAME.to_owned()),
                    container_port: METRICS_PORT.into(),
                    ..ContainerPort::default()
                },
            ])
            .resources(self.role_group_config.config.resources.clone().into())
            .startup_probe(startup_probe)
            .readiness_probe(readiness_probe)
            .build()
    }

    fn build_recommended_labels(&self) -> Labels {
        recommended_labels(
            &self.cluster,
            &self.names.product_name,
            &self.cluster.product_version,
            &self.names.operator_name,
            &self.names.controller_name,
            &self.role_name,
            &self.role_group_name,
        )
    }

    fn build_service(&self) -> Service {
        let ports = vec![
            ServicePort {
                name: Some(HTTP_PORT_NAME.to_owned()),
                port: HTTP_PORT.into(),
                ..ServicePort::default()
            },
            ServicePort {
                name: Some(TRANSPORT_PORT_NAME.to_owned()),
                port: TRANSPORT_PORT.into(),
                ..ServicePort::default()
            },
            ServicePort {
                name: Some(METRICS_PORT_NAME.to_owned()),
                port: METRICS_PORT.into(),
                ..ServicePort::default()
            },
        ];

        // TODO Add Prometheus label

        let metadata = ObjectMetaBuilder::new()
            .name(self.qualified_role_group_name.clone())
            .namespace(&self.cluster.namespace)
            .ownerreference(ownerreference_from_resource(
                &self.cluster,
                None,
                Some(true),
            ))
            .with_labels(self.build_recommended_labels())
            .build();

        let service_selector = role_group_selector(
            &self.cluster,
            &self.names.product_name,
            &self.role_name,
            &self.role_group_name,
        );

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
}

pub fn build(names: &ContextNames, cluster: ValidatedCluster) -> Resources<Prepared> {
    let mut config_maps = vec![];
    let mut stateful_sets = vec![];
    let mut services = vec![];

    let role_name = RoleName::from_str("nodes").expect("should be a valid role name");

    let role_builder = RoleBuilder::new(names, role_name, cluster.clone());

    for role_group_builder in role_builder.role_group_builders() {
        config_maps.push(role_group_builder.build_config_map());
        stateful_sets.push(role_group_builder.build_statefulset());
        services.push(role_group_builder.build_service());
    }

    let cluster_manager_service = role_builder.build_cluster_manager_service();
    services.push(cluster_manager_service);

    let pod_disruption_budgets = role_builder.build_pdb().into_iter().collect();

    Resources {
        stateful_sets,
        services,
        config_maps,
        pod_disruption_budgets,
        status: PhantomData,
    }
}
