use stackable_operator::{
    builder::{meta::ObjectMetaBuilder, pod::container::ContainerBuilder},
    crd::listener::{self},
    k8s_openapi::{
        DeepMerge,
        api::{
            apps::v1::{StatefulSet, StatefulSetSpec},
            core::v1::{
                Affinity, ConfigMap, ConfigMapVolumeSource, Container, ContainerPort,
                PersistentVolumeClaim, PodSecurityContext, PodSpec, PodTemplateSpec, Probe,
                Service, ServicePort, ServiceSpec, TCPSocketAction, Volume, VolumeMount,
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
        builder::{meta::ownerreference_from_resource, pod::container::EnvVarName},
        kvp::label::{recommended_labels, role_group_selector, role_selector},
        listener::listener_pvc,
        role_group_utils::ResourceNames,
    },
};

pub const HTTP_PORT_NAME: &str = "http";
pub const HTTP_PORT: u16 = 9200;
pub const TRANSPORT_PORT_NAME: &str = "transport";
pub const TRANSPORT_PORT: u16 = 9300;

const CONFIG_VOLUME_NAME: &str = "config";
const DATA_VOLUME_NAME: &str = "data";

const LISTENER_VOLUME_NAME: &str = "listener";
const LISTENER_VOLUME_DIR: &str = "/stackable/listener";

const DEFAULT_OPENSEARCH_HOME: &str = "/stackable/opensearch";

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

        let listener_group_name = self.resource_names.listener_service_name();

        // Listener endpoints for the all rolegroups will use persistent
        // volumes so that load balancers can hard-code the target
        // addresses. This will be the case even when no class is set (and
        // the value defaults to cluster-internal) as the address should
        // still be consistent.
        let listener_volume_claim_template = listener_pvc(
            listener_group_name,
            &self.recommended_labels(),
            LISTENER_VOLUME_NAME.to_string(),
        );

        let pvcs: Option<Vec<PersistentVolumeClaim>> = Some(vec![
            data_volume_claim_template,
            listener_volume_claim_template,
        ]);

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
            volume_claim_templates: pvcs,
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
        // It is not possible to check the infallibility of the following statement at
        // compile-time. Instead, it is tested in `tests::test_build_node_role_label`.
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

        let env_vars = self.node_config.environment_variables();

        // Use `OPENSEARCH_HOME` from envOverrides or default to `DEFAULT_OPENSEARCH_HOME`.
        let opensearch_home = env_vars
            .get(EnvVarName::from_str_unsafe("OPENSEARCH_HOME"))
            .and_then(|env_var| env_var.value.clone())
            .unwrap_or(DEFAULT_OPENSEARCH_HOME.to_owned());
        // Use `OPENSEARCH_PATH_CONF` from envOverrides or default to `{OPENSEARCH_HOME}/config`,
        // i.e. depend on `OPENSEARCH_HOME`.
        let opensearch_path_conf = env_vars
            .get(EnvVarName::from_str_unsafe("OPENSEARCH_PATH_CONF"))
            .and_then(|env_var| env_var.value.clone())
            .unwrap_or(format!("{opensearch_home}/config"));

        ContainerBuilder::new("opensearch")
            .expect("should be a valid container name")
            .image_from_product_image(&product_image)
            .command(vec![format!(
                "{opensearch_home}/opensearch-docker-entrypoint.sh"
            )])
            .args(role_group_config.cli_overrides_to_vec())
            .add_env_vars(env_vars.into())
            .add_volume_mounts([
                VolumeMount {
                    mount_path: format!(
                        "{opensearch_path_conf}/{CONFIGURATION_FILE_OPENSEARCH_YML}"
                    ),
                    name: CONFIG_VOLUME_NAME.to_owned(),
                    read_only: Some(true),
                    sub_path: Some(CONFIGURATION_FILE_OPENSEARCH_YML.to_owned()),
                    ..VolumeMount::default()
                },
                VolumeMount {
                    mount_path: format!("{opensearch_home}/data"),
                    name: DATA_VOLUME_NAME.to_owned(),
                    ..VolumeMount::default()
                },
                VolumeMount {
                    mount_path: LISTENER_VOLUME_DIR.to_owned(),
                    name: LISTENER_VOLUME_NAME.to_owned(),
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

    pub fn build_listener(&self) -> listener::v1alpha1::Listener {
        let metadata =
            self.common_metadata(self.resource_names.listener_service_name(), Labels::new());

        let listener_class = self.role_group_config.config.listener_class.to_owned();

        listener::v1alpha1::Listener {
            metadata,
            spec: listener::v1alpha1::ListenerSpec {
                class_name: Some(listener_class),
                ports: Some(self.listener_ports()),
                ..listener::v1alpha1::ListenerSpec::default()
            },
            status: None,
        }
    }

    /// We only use the http port here and intentionally omit
    /// the metrics one.
    fn listener_ports(&self) -> Vec<listener::v1alpha1::ListenerPort> {
        vec![listener::v1alpha1::ListenerPort {
            name: HTTP_PORT_NAME.to_string(),
            port: HTTP_PORT.into(),
            protocol: Some("TCP".to_string()),
        }]
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

#[cfg(test)]
mod tests {
    use strum::IntoEnumIterator;

    use crate::{controller::build::role_group_builder::RoleGroupBuilder, crd::v1alpha1};

    #[test]
    fn test_build_node_role_label() {
        for node_role in v1alpha1::NodeRole::iter() {
            RoleGroupBuilder::build_node_role_label(&node_role);
        }
    }
}
