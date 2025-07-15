use stackable_operator::{
    builder::{meta::ObjectMetaBuilder, pod::container::ContainerBuilder},
    k8s_openapi::{
        DeepMerge,
        api::{
            apps::v1::{StatefulSet, StatefulSetSpec},
            core::v1::{
                Affinity, ConfigMap, ConfigMapVolumeSource, Container, ContainerPort,
                PodSecurityContext, PodSpec, PodTemplateSpec, Probe, Service, ServicePort,
                ServiceSpec, TCPSocketAction, Volume, VolumeMount,
            },
        },
        apimachinery::pkg::{apis::meta::v1::LabelSelector, util::intstr::IntOrString},
    },
    kube::api::ObjectMeta,
    kvp::{Label, Labels},
};

use super::node_config::{CONFIGURATION_FILE_OPENSEARCH_YML, NodeConfig};
use crate::{
    controller::{ContextNames, OpenSearchRoleGroupConfig, ValidatedCluster},
    crd::v1alpha1,
    framework::{
        RoleGroupName,
        builder::meta::ownerreference_from_resource,
        kvp::label::{recommended_labels, role_group_selector, role_selector},
        role_group_utils::ResourceNames,
    },
};

pub const HTTP_PORT_NAME: &str = "http";
pub const HTTP_PORT: u16 = 9200;
pub const TRANSPORT_PORT_NAME: &str = "transport";
pub const TRANSPORT_PORT: u16 = 9300;

const CONFIG_VOLUME_NAME: &str = "config";
const DATA_VOLUME_NAME: &str = "data";

// Path in opensearchproject/opensearch:3.0.0
const OPENSEARCH_BASE_PATH: &str = "/usr/share/opensearch";

pub struct RoleGroupBuilder<'a> {
    service_account_name: String,
    cluster: ValidatedCluster,
    node_config: NodeConfig,
    role_group_name: RoleGroupName,
    role_group_config: OpenSearchRoleGroupConfig,
    context_names: &'a ContextNames,
    resource_names: ResourceNames,
}

impl<'a> RoleGroupBuilder<'a> {
    pub fn new(
        service_account_name: String,
        cluster: ValidatedCluster,
        role_group_name: RoleGroupName,
        role_group_config: OpenSearchRoleGroupConfig,
        context_names: &'a ContextNames,
        discovery_service_name: String,
    ) -> RoleGroupBuilder<'a> {
        RoleGroupBuilder {
            service_account_name,
            cluster: cluster.clone(),
            node_config: NodeConfig::new(
                cluster.clone(),
                role_group_config.clone(),
                discovery_service_name,
            ),
            role_group_name: role_group_name.clone(),
            role_group_config,
            context_names,
            resource_names: ResourceNames {
                cluster_name: cluster.name.clone(),
                role_name: ValidatedCluster::role_name(),
                role_group_name,
            },
        }
    }

    pub fn build_config_map(&self) -> ConfigMap {
        let metadata =
            self.common_metadata(self.resource_names.role_group_config_map(), Labels::new());

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

    pub fn build_stateful_set(&self) -> StatefulSet {
        let metadata = self.common_metadata(self.resource_names.stateful_set_name(), Labels::new());

        let template = self.build_pod_template();

        let data_volume_claim_template = self
            .role_group_config
            .config
            .resources
            .storage
            .data
            .build_pvc(DATA_VOLUME_NAME, Some(vec!["ReadWriteOnce"]));

        let spec = StatefulSetSpec {
            // Order does not matter for OpenSearch
            pod_management_policy: Some("Parallel".to_string()),
            replicas: Some(self.role_group_config.replicas.into()),
            selector: LabelSelector {
                match_labels: Some(self.pod_selector().into()),
                ..LabelSelector::default()
            },
            service_name: Some(self.resource_names.headless_service_name()),
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
        let mut node_role_labels = Labels::new();
        for node_role in self.role_group_config.config.node_roles.iter() {
            node_role_labels.insert(Self::build_node_role_label(node_role));
        }

        let metadata = ObjectMetaBuilder::new()
            .with_labels(self.recommended_labels())
            .with_labels(node_role_labels)
            .build();

        let container = self.build_container(&self.role_group_config);

        // The PodBuilder is not used because it re-validates the values which are already
        // validated. For instance, it would be necessary to convert the
        // termination_grace_period_seconds into a Duration, the PodBuilder parses the Duration,
        // converts it back into seconds and fails if this is not possible.
        let mut pod_template = PodTemplateSpec {
            metadata: Some(metadata),
            spec: Some(PodSpec {
                affinity: Some(Affinity {
                    node_affinity: self.role_group_config.config.affinity.node_affinity.clone(),
                    pod_affinity: self.role_group_config.config.affinity.pod_affinity.clone(),
                    pod_anti_affinity: self
                        .role_group_config
                        .config
                        .affinity
                        .pod_anti_affinity
                        .clone(),
                }),
                containers: vec![container],
                node_selector: self
                    .role_group_config
                    .config
                    .affinity
                    .node_selector
                    .clone()
                    .map(|wrapped| wrapped.node_selector),
                security_context: Some(PodSecurityContext {
                    fs_group: Some(1000),
                    ..PodSecurityContext::default()
                }),
                service_account_name: Some(self.service_account_name.clone()),
                termination_grace_period_seconds: Some(
                    self.role_group_config
                        .config
                        .termination_grace_period_seconds,
                ),
                volumes: Some(vec![Volume {
                    name: CONFIG_VOLUME_NAME.to_owned(),
                    config_map: Some(ConfigMapVolumeSource {
                        name: self.resource_names.role_group_config_map(),
                        ..Default::default()
                    }),
                    ..Volume::default()
                }]),
                ..PodSpec::default()
            }),
        };

        pod_template.merge_from(self.role_group_config.pod_overrides.clone());

        pod_template
    }

    pub fn cluster_manager_labels(
        cluster: &ValidatedCluster,
        context_names: &ContextNames,
    ) -> Labels {
        let mut labels = role_selector(
            cluster,
            &context_names.product_name,
            &ValidatedCluster::role_name(),
        );

        labels.insert(Self::build_node_role_label(
            &v1alpha1::NodeRole::ClusterManager,
        ));

        labels
    }

    fn build_node_role_label(node_role: &v1alpha1::NodeRole) -> Label {
        // TODO Check the maximum length at compile-time
        Label::try_from((
            format!("stackable.tech/opensearch-role.{node_role}"),
            "true".to_string(),
        ))
        .expect("should be a valid label")
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
            ])
            .resources(self.role_group_config.config.resources.clone().into())
            .startup_probe(startup_probe)
            .readiness_probe(readiness_probe)
            .build()
    }

    pub fn build_headless_service(&self) -> Service {
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
        ];

        self.build_role_group_service(
            self.resource_names.headless_service_name(),
            ports,
            Labels::new(),
        )
    }

    fn build_role_group_service(
        &self,
        service_name: impl Into<String>,
        ports: Vec<ServicePort>,
        extra_labels: Labels,
    ) -> Service {
        let metadata = self.common_metadata(service_name, extra_labels);

        let service_spec = ServiceSpec {
            // Internal communication does not need to be exposed
            type_: Some("ClusterIP".to_string()),
            cluster_ip: Some("None".to_string()),
            ports: Some(ports),
            selector: Some(self.pod_selector().into()),
            publish_not_ready_addresses: Some(true),
            ..ServiceSpec::default()
        };

        Service {
            metadata,
            spec: Some(service_spec),
            status: None,
        }
    }

    fn common_metadata(
        &self,
        resource_name: impl Into<String>,
        extra_labels: Labels,
    ) -> ObjectMeta {
        ObjectMetaBuilder::new()
            .name(resource_name)
            .namespace(&self.cluster.namespace)
            .ownerreference(ownerreference_from_resource(
                &self.cluster,
                None,
                Some(true),
            ))
            .with_labels(self.recommended_labels())
            .with_labels(extra_labels)
            .build()
    }

    fn recommended_labels(&self) -> Labels {
        recommended_labels(
            &self.cluster,
            &self.context_names.product_name,
            &self.cluster.product_version,
            &self.context_names.operator_name,
            &self.context_names.controller_name,
            &ValidatedCluster::role_name(),
            &self.role_group_name,
        )
    }

    fn pod_selector(&self) -> Labels {
        role_group_selector(
            &self.cluster,
            &self.context_names.product_name,
            &ValidatedCluster::role_name(),
            &self.role_group_name,
        )
    }
}
