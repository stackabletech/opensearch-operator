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
                ConfigMap, ConfigMapVolumeSource, Container, ContainerPort, PodSecurityContext,
                PodTemplateSpec, Probe, Service, ServicePort, ServiceSpec, TCPSocketAction, Volume,
                VolumeMount,
            },
        },
        apimachinery::pkg::{apis::meta::v1::LabelSelector, util::intstr::IntOrString},
    },
    kvp::{Label, Labels},
};

use super::node_config::{CONFIGURATION_FILE_OPENSEARCH_YML, NodeConfig};
use crate::{
    controller::{ContextNames, OpenSearchRoleGroupConfig, ValidatedCluster},
    framework::{
        RoleGroupName, RoleName,
        builder::meta::ownerreference_from_resource,
        kvp::label::{recommended_labels, role_group_selector},
        to_qualified_role_group_name,
    },
};

pub const HTTP_PORT_NAME: &str = "http";
pub const HTTP_PORT: u16 = 9200;
pub const TRANSPORT_PORT_NAME: &str = "transport";
pub const TRANSPORT_PORT: u16 = 9300;
pub const METRICS_PORT_NAME: &str = "metrics";
pub const METRICS_PORT: u16 = 9600;

const CONFIG_VOLUME_NAME: &str = "config";
const DATA_VOLUME_NAME: &str = "data";

// Path in opensearchproject/opensearch:3.0.0
const OPENSEARCH_BASE_PATH: &str = "/usr/share/opensearch";

pub struct RoleGroupBuilder<'a> {
    names: &'a ContextNames,
    role_name: RoleName,
    service_account_name: String,
    cluster: ValidatedCluster,
    node_config: NodeConfig,
    qualified_role_group_name: String,
    role_group_name: RoleGroupName,
    role_group_config: OpenSearchRoleGroupConfig,
}

impl<'a> RoleGroupBuilder<'a> {
    pub fn new(
        names: &'a ContextNames,
        role_name: RoleName,
        service_account_name: String,
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
            service_account_name,
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

    pub fn build_config_map(&self) -> ConfigMap {
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

    pub fn build_statefulset(&self) -> StatefulSet {
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
            .security_context(PodSecurityContext {
                fs_group: Some(1000),
                ..PodSecurityContext::default()
            })
            .service_account_name(&self.service_account_name)
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

    pub fn build_service(&self) -> Service {
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
