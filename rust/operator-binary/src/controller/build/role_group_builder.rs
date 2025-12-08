//! Builder for role-group resources

use std::{collections::BTreeMap, str::FromStr};

use stackable_operator::{
    builder::meta::ObjectMetaBuilder,
    crd::listener::{self},
    k8s_openapi::{
        DeepMerge,
        api::{
            apps::v1::{StatefulSet, StatefulSetSpec},
            core::v1::{
                Affinity, ConfigMap, ConfigMapVolumeSource, Container, ContainerPort,
                EmptyDirVolumeSource, PersistentVolumeClaim, PodSecurityContext, PodSpec,
                PodTemplateSpec, Probe, Service, ServicePort, ServiceSpec, TCPSocketAction, Volume,
                VolumeMount,
            },
        },
        apimachinery::pkg::{apis::meta::v1::LabelSelector, util::intstr::IntOrString},
    },
    kvp::{Annotation, Annotations, Label, Labels},
    product_logging::framework::{
        VECTOR_CONFIG_FILE, calculate_log_volume_size_limit, create_vector_shutdown_file_command,
        remove_vector_shutdown_file_command,
    },
    utils::COMMON_BASH_TRAP_FUNCTIONS,
};

use super::{
    node_config::{CONFIGURATION_FILE_OPENSEARCH_YML, NodeConfig},
    product_logging::config::{
        CONFIGURATION_FILE_LOG4J2_PROPERTIES, create_log4j2_config, vector_config_file_content,
    },
};
use crate::{
    constant,
    controller::{
        ContextNames, OpenSearchRoleGroupConfig, ValidatedCluster,
        build::product_logging::config::{
            MAX_OPENSEARCH_SERVER_LOG_FILES_SIZE, vector_config_file_extra_env_vars,
        },
    },
    crd::v1alpha1,
    framework::{
        builder::{
            meta::ownerreference_from_resource,
            pod::{
                container::{EnvVarName, new_container_builder},
                volume::{ListenerReference, listener_operator_volume_source_builder_build_pvc},
            },
        },
        kvp::label::{recommended_labels, role_group_selector, role_selector},
        product_logging::framework::{
            STACKABLE_LOG_DIR, ValidatedContainerLogConfigChoice, vector_container,
        },
        role_group_utils::ResourceNames,
        types::{
            kubernetes::{PersistentVolumeClaimName, ServiceAccountName, ServiceName, VolumeName},
            operator::RoleGroupName,
        },
    },
};

pub const HTTP_PORT_NAME: &str = "http";
pub const HTTP_PORT: u16 = 9200;
pub const TRANSPORT_PORT_NAME: &str = "transport";
pub const TRANSPORT_PORT: u16 = 9300;

constant!(CONFIG_VOLUME_NAME: VolumeName = "config");

constant!(LOG_CONFIG_VOLUME_NAME: VolumeName = "log-config");
constant!(DATA_VOLUME_NAME: VolumeName = "data");

constant!(LISTENER_VOLUME_NAME: PersistentVolumeClaimName = "listener");
const LISTENER_VOLUME_DIR: &str = "/stackable/listener";

constant!(LOG_VOLUME_NAME: VolumeName = "log");
const LOG_VOLUME_DIR: &str = "/stackable/log";

const DEFAULT_OPENSEARCH_HOME: &str = "/stackable/opensearch";

/// Builder for role-group resources
pub struct RoleGroupBuilder<'a> {
    service_account_name: ServiceAccountName,
    cluster: ValidatedCluster,
    node_config: NodeConfig,
    role_group_name: RoleGroupName,
    role_group_config: OpenSearchRoleGroupConfig,
    context_names: &'a ContextNames,
    resource_names: ResourceNames,
}

impl<'a> RoleGroupBuilder<'a> {
    pub fn new(
        service_account_name: ServiceAccountName,
        cluster: ValidatedCluster,
        role_group_name: RoleGroupName,
        role_group_config: OpenSearchRoleGroupConfig,
        context_names: &'a ContextNames,
        discovery_service_name: ServiceName,
    ) -> RoleGroupBuilder<'a> {
        RoleGroupBuilder {
            service_account_name,
            cluster: cluster.clone(),
            node_config: NodeConfig::new(
                cluster.clone(),
                role_group_name.clone(),
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

    /// Builds the [`ConfigMap`] containing the configuration files of the role-group
    /// [`StatefulSet`]
    pub fn build_config_map(&self) -> ConfigMap {
        let metadata = self
            .common_metadata(self.resource_names.role_group_config_map())
            .build();

        let mut data = BTreeMap::new();

        data.insert(
            CONFIGURATION_FILE_OPENSEARCH_YML.to_owned(),
            self.node_config.static_opensearch_config_file_content(),
        );

        if let ValidatedContainerLogConfigChoice::Automatic(log_config) =
            &self.role_group_config.config.logging.opensearch_container
        {
            data.insert(
                CONFIGURATION_FILE_LOG4J2_PROPERTIES.to_owned(),
                create_log4j2_config(log_config),
            );
        };

        if self
            .role_group_config
            .config
            .logging
            .is_vector_agent_enabled()
        {
            data.insert(VECTOR_CONFIG_FILE.to_owned(), vector_config_file_content());
        }

        ConfigMap {
            metadata,
            data: Some(data),
            ..ConfigMap::default()
        }
    }

    /// Builds the role-group [`StatefulSet`]
    pub fn build_stateful_set(&self) -> StatefulSet {
        let metadata = self
            .common_metadata(self.resource_names.stateful_set_name())
            .build();

        let template = self.build_pod_template();

        let data_volume_claim_template = self
            .role_group_config
            .config
            .resources
            .storage
            .data
            .build_pvc(DATA_VOLUME_NAME.as_ref(), Some(vec!["ReadWriteOnce"]));

        let listener_group_name = self.resource_names.listener_name();

        // Listener endpoints for the all rolegroups will use persistent
        // volumes so that load balancers can hard-code the target
        // addresses. This will be the case even when no class is set (and
        // the value defaults to cluster-internal) as the address should
        // still be consistent.
        let listener_volume_claim_template = listener_operator_volume_source_builder_build_pvc(
            &ListenerReference::Listener(listener_group_name),
            &self.recommended_labels(),
            &LISTENER_VOLUME_NAME,
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
            service_name: Some(self.resource_names.headless_service_name().to_string()),
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

    /// Builds the [`PodTemplateSpec`] for the role-group [`StatefulSet`]
    fn build_pod_template(&self) -> PodTemplateSpec {
        let mut node_role_labels = Labels::new();
        for node_role in self.role_group_config.config.node_roles.iter() {
            node_role_labels.insert(Self::build_node_role_label(node_role));
        }

        let metadata = ObjectMetaBuilder::new()
            .with_labels(self.recommended_labels())
            .with_labels(node_role_labels)
            .with_annotation(
                Annotation::try_from((
                    "kubectl.kubernetes.io/default-container".to_owned(),
                    v1alpha1::Container::OpenSearch.to_container_name(),
                ))
                .expect("should be a valid annotation"),
            )
            .build();

        let opensearch_container = self.build_opensearch_container();
        let vector_container = self
            .role_group_config
            .config
            .logging
            .vector_container
            .as_ref()
            .map(|vector_container_log_config| {
                vector_container(
                    &v1alpha1::Container::Vector.to_container_name(),
                    &self.cluster.image,
                    vector_container_log_config,
                    &self.resource_names,
                    &CONFIG_VOLUME_NAME,
                    &LOG_VOLUME_NAME,
                    vector_config_file_extra_env_vars(),
                )
            });

        let log_config_volume_config_map =
            if let ValidatedContainerLogConfigChoice::Custom(config_map_name) =
                &self.role_group_config.config.logging.opensearch_container
            {
                config_map_name.clone()
            } else {
                self.resource_names.role_group_config_map()
            };

        let volumes = vec![
            Volume {
                name: CONFIG_VOLUME_NAME.to_string(),
                config_map: Some(ConfigMapVolumeSource {
                    default_mode: Some(0o660),
                    name: self.resource_names.role_group_config_map().to_string(),
                    ..Default::default()
                }),
                ..Volume::default()
            },
            Volume {
                name: LOG_CONFIG_VOLUME_NAME.to_string(),
                config_map: Some(ConfigMapVolumeSource {
                    default_mode: Some(0o660),
                    name: log_config_volume_config_map.to_string(),
                    ..Default::default()
                }),
                ..Volume::default()
            },
            Volume {
                name: LOG_VOLUME_NAME.to_string(),
                empty_dir: Some(EmptyDirVolumeSource {
                    size_limit: Some(calculate_log_volume_size_limit(&[
                        MAX_OPENSEARCH_SERVER_LOG_FILES_SIZE,
                    ])),
                    ..EmptyDirVolumeSource::default()
                }),
                ..Volume::default()
            },
        ];

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
                containers: [Some(opensearch_container), vector_container]
                    .into_iter()
                    .flatten()
                    .collect(),
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
                service_account_name: Some(self.service_account_name.to_string()),
                termination_grace_period_seconds: Some(
                    self.role_group_config
                        .config
                        .termination_grace_period_seconds,
                ),
                volumes: Some(volumes),
                ..PodSpec::default()
            }),
        };

        pod_template.merge_from(self.role_group_config.pod_overrides.clone());

        pod_template
    }

    /// Returns the labels of OpenSearch nodes with the `cluster_manager` role.
    ///
    /// As described in [`super::role_builder::RoleBuilder::build_cluster_manager_service`], this
    /// function will be changed or deleted.
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

    /// Builds a label indicating the role of the OpenSearch node
    fn build_node_role_label(node_role: &v1alpha1::NodeRole) -> Label {
        // It is not possible to check the infallibility of the following statement at
        // compile-time. Instead, it is tested in `tests::test_build_node_role_label`.
        Label::try_from((
            format!("stackable.tech/opensearch-role.{node_role}"),
            "true".to_string(),
        ))
        .expect("should be a valid label")
    }

    /// Builds the container for the [`PodTemplateSpec`]
    fn build_opensearch_container(&self) -> Container {
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
            .get(&EnvVarName::from_str_unsafe("OPENSEARCH_HOME"))
            .and_then(|env_var| env_var.value.clone())
            .unwrap_or(DEFAULT_OPENSEARCH_HOME.to_owned());
        // Use `OPENSEARCH_PATH_CONF` from envOverrides or default to `OPENSEARCH_HOME/config`,
        // i.e. depend on `OPENSEARCH_HOME`.
        let opensearch_path_conf = env_vars
            .get(&EnvVarName::from_str_unsafe("OPENSEARCH_PATH_CONF"))
            .and_then(|env_var| env_var.value.clone())
            .unwrap_or(format!("{opensearch_home}/config"));

        let volume_mounts = [
            VolumeMount {
                mount_path: format!("{opensearch_path_conf}/{CONFIGURATION_FILE_OPENSEARCH_YML}"),
                name: CONFIG_VOLUME_NAME.to_string(),
                read_only: Some(true),
                sub_path: Some(CONFIGURATION_FILE_OPENSEARCH_YML.to_owned()),
                ..VolumeMount::default()
            },
            VolumeMount {
                mount_path: format!(
                    "{opensearch_path_conf}/{CONFIGURATION_FILE_LOG4J2_PROPERTIES}"
                ),
                name: LOG_CONFIG_VOLUME_NAME.to_string(),
                read_only: Some(true),
                sub_path: Some(CONFIGURATION_FILE_LOG4J2_PROPERTIES.to_owned()),
                ..VolumeMount::default()
            },
            VolumeMount {
                mount_path: format!("{opensearch_home}/data"),
                name: DATA_VOLUME_NAME.to_string(),
                ..VolumeMount::default()
            },
            VolumeMount {
                mount_path: LISTENER_VOLUME_DIR.to_owned(),
                name: LISTENER_VOLUME_NAME.to_string(),
                ..VolumeMount::default()
            },
            VolumeMount {
                mount_path: LOG_VOLUME_DIR.to_owned(),
                name: LOG_VOLUME_NAME.to_string(),
                ..VolumeMount::default()
            },
        ];

        new_container_builder(&v1alpha1::Container::OpenSearch.to_container_name())
            .image_from_product_image(&self.cluster.image)
            .command(vec![
                "/bin/bash".to_string(),
                "-x".to_string(),
                "-euo".to_string(),
                "pipefail".to_string(),
                "-c".to_string(),
            ])
            .args(vec![format!(
                "{COMMON_BASH_TRAP_FUNCTIONS}\n\
                {remove_vector_shutdown_file_command}\n\
                prepare_signal_handlers\n\
                if command --search containerdebug >/dev/null 2>&1; then\n\
                containerdebug --output={STACKABLE_LOG_DIR}/containerdebug-state.json --loop &\n\
                else\n\
                echo >&2 \"containerdebug not installed; Proceed without it.\"\n\
                fi\n\
                ./opensearch-docker-entrypoint.sh {extra_args} &\n\
                wait_for_termination $!\n\
                {create_vector_shutdown_file_command}",
                extra_args = self.role_group_config.cli_overrides_to_vec().join(" "),
                remove_vector_shutdown_file_command =
                    remove_vector_shutdown_file_command(STACKABLE_LOG_DIR),
                create_vector_shutdown_file_command =
                    create_vector_shutdown_file_command(STACKABLE_LOG_DIR),
            )])
            .add_env_vars(env_vars.into())
            .add_volume_mounts(volume_mounts)
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

    /// Builds the headless [`Service`] for the role-group
    pub fn build_headless_service(&self) -> Service {
        let metadata = self
            .common_metadata(self.resource_names.headless_service_name())
            .with_labels(Self::prometheus_labels())
            .with_annotations(Self::prometheus_annotations(
                self.node_config.tls_on_http_port_enabled(),
            ))
            .build();

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

    /// Common labels for Prometheus
    fn prometheus_labels() -> Labels {
        Labels::try_from([("prometheus.io/scrape", "true")]).expect("should be a valid label")
    }

    /// Common annotations for Prometheus
    ///
    /// These annotations can be used in a ServiceMonitor.
    ///
    /// see also <https://github.com/prometheus-community/helm-charts/blob/prometheus-27.32.0/charts/prometheus/values.yaml#L983-L1036>
    fn prometheus_annotations(tls_on_http_port_enabled: bool) -> Annotations {
        Annotations::try_from([
            (
                "prometheus.io/path".to_owned(),
                "/_prometheus/metrics".to_owned(),
            ),
            ("prometheus.io/port".to_owned(), HTTP_PORT.to_string()),
            (
                "prometheus.io/scheme".to_owned(),
                if tls_on_http_port_enabled {
                    "https".to_owned()
                } else {
                    "http".to_owned()
                },
            ),
            ("prometheus.io/scrape".to_owned(), "true".to_owned()),
        ])
        .expect("should be valid annotations")
    }

    /// Builds the [`listener::v1alpha1::Listener`] for the role-group
    ///
    /// The Listener exposes only the HTTP port.
    /// The Listener operator will create a Service per role-group.
    pub fn build_listener(&self) -> listener::v1alpha1::Listener {
        let metadata = self
            .common_metadata(self.resource_names.listener_name())
            .build();

        let listener_class = self.role_group_config.config.listener_class.to_owned();

        let ports = [listener::v1alpha1::ListenerPort {
            name: HTTP_PORT_NAME.to_string(),
            port: HTTP_PORT.into(),
            protocol: Some("TCP".to_string()),
        }];

        listener::v1alpha1::Listener {
            metadata,
            spec: listener::v1alpha1::ListenerSpec {
                class_name: Some(listener_class.to_string()),
                ports: Some(ports.to_vec()),
                ..listener::v1alpha1::ListenerSpec::default()
            },
            status: None,
        }
    }

    /// Common metadata for role-group resources
    fn common_metadata(&self, resource_name: impl Into<String>) -> ObjectMetaBuilder {
        let mut builder = ObjectMetaBuilder::new();

        builder
            .name(resource_name)
            .namespace(&self.cluster.namespace)
            .ownerreference(ownerreference_from_resource(
                &self.cluster,
                None,
                Some(true),
            ))
            .with_labels(self.recommended_labels());

        builder
    }

    /// Recommended labels for role-group resources
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

    /// Labels to select a [`Pod`] in the role-group
    ///
    /// [`Pod`]: stackable_operator::k8s_openapi::api::core::v1::Pod
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
    use std::{
        collections::{BTreeMap, HashMap},
        str::FromStr,
    };

    use pretty_assertions::assert_eq;
    use serde_json::json;
    use stackable_operator::{
        commons::{
            affinity::StackableAffinity, product_image_selection::ResolvedProductImage,
            resources::Resources,
        },
        k8s_openapi::api::core::v1::PodTemplateSpec,
        kvp::LabelValue,
        product_logging::spec::AutomaticContainerLogConfig,
        role_utils::GenericRoleConfig,
    };
    use strum::IntoEnumIterator;
    use uuid::uuid;

    use super::{
        CONFIG_VOLUME_NAME, DATA_VOLUME_NAME, LISTENER_VOLUME_NAME, LOG_CONFIG_VOLUME_NAME,
        LOG_VOLUME_NAME, RoleGroupBuilder,
    };
    use crate::{
        controller::{
            ContextNames, OpenSearchRoleGroupConfig, ValidatedCluster,
            ValidatedContainerLogConfigChoice, ValidatedLogging, ValidatedOpenSearchConfig,
        },
        crd::{NodeRoles, v1alpha1},
        framework::{
            builder::pod::container::EnvVarSet,
            product_logging::framework::VectorContainerLogConfig,
            role_utils::GenericProductSpecificCommonConfig,
            types::{
                kubernetes::{
                    ConfigMapName, ListenerClassName, NamespaceName, ServiceAccountName,
                    ServiceName,
                },
                operator::{
                    ClusterName, ControllerName, OperatorName, ProductName, ProductVersion,
                    RoleGroupName,
                },
            },
        },
    };

    #[test]
    fn test_constants() {
        // Test that the functions do not panic
        let _ = CONFIG_VOLUME_NAME;
        let _ = LOG_CONFIG_VOLUME_NAME;
        let _ = DATA_VOLUME_NAME;
        let _ = LISTENER_VOLUME_NAME;
        let _ = LOG_VOLUME_NAME;
    }

    fn context_names() -> ContextNames {
        ContextNames {
            product_name: ProductName::from_str_unsafe("opensearch"),
            operator_name: OperatorName::from_str_unsafe("opensearch.stackable.tech"),
            controller_name: ControllerName::from_str_unsafe("opensearchcluster"),
        }
    }

    fn validated_cluster() -> ValidatedCluster {
        let image = ResolvedProductImage {
            product_version: "3.1.0".to_owned(),
            app_version_label_value: LabelValue::from_str("3.1.0-stackable0.0.0-dev")
                .expect("should be a valid label value"),
            image: "oci.stackable.tech/sdp/opensearch:3.1.0-stackable0.0.0-dev".to_string(),
            image_pull_policy: "Always".to_owned(),
            pull_secrets: None,
        };

        let role_group_config = OpenSearchRoleGroupConfig {
            replicas: 1,
            config: ValidatedOpenSearchConfig {
                affinity: StackableAffinity::default(),
                listener_class: ListenerClassName::from_str_unsafe("cluster-internal"),
                logging: ValidatedLogging {
                    opensearch_container: ValidatedContainerLogConfigChoice::Automatic(
                        AutomaticContainerLogConfig::default(),
                    ),
                    vector_container: Some(VectorContainerLogConfig {
                        log_config: ValidatedContainerLogConfigChoice::Automatic(
                            AutomaticContainerLogConfig::default(),
                        ),
                        vector_aggregator_config_map_name: ConfigMapName::from_str_unsafe(
                            "vector-aggregator",
                        ),
                    }),
                },
                node_roles: NodeRoles(vec![
                    v1alpha1::NodeRole::ClusterManager,
                    v1alpha1::NodeRole::Data,
                    v1alpha1::NodeRole::Ingest,
                    v1alpha1::NodeRole::RemoteClusterClient,
                ]),
                resources: Resources::default(),
                termination_grace_period_seconds: 30,
            },
            config_overrides: HashMap::default(),
            env_overrides: EnvVarSet::default(),
            cli_overrides: BTreeMap::default(),
            pod_overrides: PodTemplateSpec::default(),
            product_specific_common_config: GenericProductSpecificCommonConfig::default(),
        };

        ValidatedCluster::new(
            image.clone(),
            ProductVersion::from_str_unsafe(&image.product_version),
            ClusterName::from_str_unsafe("my-opensearch-cluster"),
            NamespaceName::from_str_unsafe("default"),
            uuid!("0b1e30e6-326e-4c1a-868d-ad6598b49e8b"),
            GenericRoleConfig::default(),
            [(
                RoleGroupName::from_str_unsafe("default"),
                role_group_config.clone(),
            )]
            .into(),
        )
    }

    fn role_group_builder<'a>(context_names: &'a ContextNames) -> RoleGroupBuilder<'a> {
        let cluster = validated_cluster();

        let (role_group_name, role_group_config) = cluster
            .role_group_configs
            .first_key_value()
            .expect("should be set");

        let role_group_name = role_group_name.to_owned();
        let role_group_config = role_group_config.to_owned();

        RoleGroupBuilder::new(
            ServiceAccountName::from_str_unsafe("my-opensearch-cluster-serviceaccount"),
            cluster,
            role_group_name,
            role_group_config,
            context_names,
            ServiceName::from_str_unsafe("my-opensearch-cluster"),
        )
    }

    #[test]
    fn test_build_config_map() {
        let context_names = context_names();
        let role_group_builder = role_group_builder(&context_names);

        let mut config_map = serde_json::to_value(role_group_builder.build_config_map())
            .expect("should be serializable");

        // The content of log4j2.properties is already tested in the
        // `controller::build::product_logging::config` module.
        config_map["data"]["log4j2.properties"].take();
        // The content of opensearch.yml is already tested in the `controller::build::node_config`
        // module.
        config_map["data"]["opensearch.yml"].take();
        // vector.yaml is a static file and does not have to be repeated here.
        config_map["data"]["vector.yaml"].take();

        assert_eq!(
            json!({
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {
                    "labels": {
                        "app.kubernetes.io/component": "nodes",
                        "app.kubernetes.io/instance": "my-opensearch-cluster",
                        "app.kubernetes.io/managed-by": "opensearch.stackable.tech_opensearchcluster",
                        "app.kubernetes.io/name": "opensearch",
                        "app.kubernetes.io/role-group": "default",
                        "app.kubernetes.io/version": "3.1.0",
                        "stackable.tech/vendor": "Stackable"
                    },
                    "name": "my-opensearch-cluster-nodes-default",
                    "namespace": "default",
                    "ownerReferences": [
                        {
                            "apiVersion": "opensearch.stackable.tech/v1alpha1",
                            "controller": true,
                            "kind": "OpenSearchCluster",
                            "name": "my-opensearch-cluster",
                            "uid": "0b1e30e6-326e-4c1a-868d-ad6598b49e8b"
                        }
                    ]
                },
                "data": {
                    "log4j2.properties": null,
                    "opensearch.yml": null,
                    "vector.yaml": null
                }
            }),
            config_map
        );
    }

    #[test]
    fn test_build_stateful_set() {
        let context_names = context_names();
        let role_group_builder = role_group_builder(&context_names);

        let stateful_set = serde_json::to_value(role_group_builder.build_stateful_set())
            .expect("should be serializable");

        assert_eq!(
            json!({
                "apiVersion": "apps/v1",
                "kind": "StatefulSet",
                "metadata": {
                    "labels": {
                        "app.kubernetes.io/component": "nodes",
                        "app.kubernetes.io/instance": "my-opensearch-cluster",
                        "app.kubernetes.io/managed-by": "opensearch.stackable.tech_opensearchcluster",
                        "app.kubernetes.io/name": "opensearch",
                        "app.kubernetes.io/role-group": "default",
                        "app.kubernetes.io/version": "3.1.0",
                        "stackable.tech/vendor": "Stackable"
                    },
                    "name": "my-opensearch-cluster-nodes-default",
                    "namespace": "default",
                    "ownerReferences": [
                        {
                            "apiVersion": "opensearch.stackable.tech/v1alpha1",
                            "controller": true,
                            "kind": "OpenSearchCluster",
                            "name": "my-opensearch-cluster",
                            "uid": "0b1e30e6-326e-4c1a-868d-ad6598b49e8b"
                        }
                    ]
                },
                "spec": {
                    "podManagementPolicy": "Parallel",
                    "replicas": 1,
                    "selector": {
                        "matchLabels": {
                            "app.kubernetes.io/component": "nodes",
                            "app.kubernetes.io/instance": "my-opensearch-cluster",
                            "app.kubernetes.io/name": "opensearch",
                            "app.kubernetes.io/role-group": "default"
                        }
                    },
                    "serviceName": "my-opensearch-cluster-nodes-default-headless",
                    "template": {
                        "metadata": {
                            "annotations": {
                                "kubectl.kubernetes.io/default-container": "opensearch",
                            },
                            "labels": {
                                "app.kubernetes.io/component": "nodes",
                                "app.kubernetes.io/instance": "my-opensearch-cluster",
                                "app.kubernetes.io/managed-by": "opensearch.stackable.tech_opensearchcluster",
                                "app.kubernetes.io/name": "opensearch",
                                "app.kubernetes.io/role-group": "default",
                                "app.kubernetes.io/version": "3.1.0",
                                "stackable.tech/opensearch-role.cluster_manager": "true",
                                "stackable.tech/opensearch-role.data": "true",
                                "stackable.tech/opensearch-role.ingest": "true",
                                "stackable.tech/opensearch-role.remote_cluster_client": "true",
                                "stackable.tech/vendor": "Stackable"
                            }
                        },
                        "spec": {
                            "affinity": {},
                            "containers": [
                                {
                                    "args": [
                                        concat!(
                                            "\n",
                                            "prepare_signal_handlers()\n",
                                            "{\n",
                                            "    unset term_child_pid\n",
                                            "    unset term_kill_needed\n",
                                            "    trap 'handle_term_signal' TERM\n",
                                            "}\n",
                                            "\n",
                                            "handle_term_signal()\n",
                                            "{\n",
                                            "    if [ \"${term_child_pid}\" ]; then\n",
                                            "        kill -TERM \"${term_child_pid}\" 2>/dev/null\n",
                                            "    else\n",
                                            "        term_kill_needed=\"yes\"\n",
                                            "    fi\n",
                                            "}\n",
                                            "\n",
                                            "wait_for_termination()\n",
                                            "{\n",
                                            "    set +e\n",
                                            "    term_child_pid=$1\n",
                                            "    if [[ -v term_kill_needed ]]; then\n",
                                            "        kill -TERM \"${term_child_pid}\" 2>/dev/null\n",
                                            "    fi\n",
                                            "    wait ${term_child_pid} 2>/dev/null\n",
                                            "    trap - TERM\n",
                                            "    wait ${term_child_pid} 2>/dev/null\n",
                                            "    set -e\n",
                                            "}\n",
                                            "\n",
                                            "rm -f /stackable/log/_vector/shutdown\n",
                                            "prepare_signal_handlers\n",
                                            "if command --search containerdebug >/dev/null 2>&1; then\n",
                                            "containerdebug --output=/stackable/log/containerdebug-state.json --loop &\n",
                                            "else\n",
                                            "echo >&2 \"containerdebug not installed; Proceed without it.\"\n",
                                            "fi\n",
                                            "./opensearch-docker-entrypoint.sh  &\n",
                                            "wait_for_termination $!\n",
                                            "mkdir -p /stackable/log/_vector && touch /stackable/log/_vector/shutdown"
                                        )
                                    ],
                                    "command": [
                                        "/bin/bash",
                                        "-x",
                                        "-euo",
                                        "pipefail",
                                        "-c"
                                    ],
                                    "env": [
                                        {
                                            "name": "cluster.initial_cluster_manager_nodes",
                                            "value": ""
                                        },
                                        {
                                            "name": "discovery.seed_hosts",
                                            "value": "my-opensearch-cluster"
                                        },
                                        {
                                            "name": "node.name",
                                            "valueFrom": {
                                                "fieldRef": {
                                                    "fieldPath": "metadata.name"
                                                }
                                            }
                                        },
                                        {
                                            "name": "node.roles",
                                            "value": "cluster_manager,data,ingest,remote_cluster_client"
                                        }
                                    ],
                                    "image": "oci.stackable.tech/sdp/opensearch:3.1.0-stackable0.0.0-dev",
                                    "imagePullPolicy": "Always",
                                    "name": "opensearch",
                                    "ports": [
                                        {
                                            "containerPort": 9200,
                                            "name": "http"
                                        },
                                        {
                                            "containerPort": 9300,
                                            "name": "transport"
                                        }
                                    ],
                                    "readinessProbe": {
                                        "failureThreshold": 3,
                                        "periodSeconds": 5,
                                        "tcpSocket": {
                                            "port": "http"
                                        },
                                        "timeoutSeconds": 3
                                    },
                                    "resources": {},
                                    "startupProbe": {
                                        "failureThreshold": 30,
                                        "initialDelaySeconds": 5,
                                        "periodSeconds": 10,
                                        "tcpSocket": {
                                            "port": "http"
                                        },
                                        "timeoutSeconds": 3
                                    },
                                    "volumeMounts": [
                                        {
                                            "mountPath": "/stackable/opensearch/config/opensearch.yml",
                                            "name": "config",
                                            "readOnly": true,
                                            "subPath": "opensearch.yml"
                                        },
                                        {
                                            "mountPath": "/stackable/opensearch/config/log4j2.properties",
                                            "name": "log-config",
                                            "readOnly": true,
                                            "subPath": "log4j2.properties"
                                        },
                                        {
                                            "mountPath": "/stackable/opensearch/data",
                                            "name": "data"
                                        },
                                        {
                                            "mountPath": "/stackable/listener",
                                            "name": "listener"
                                        },
                                        {
                                            "mountPath": "/stackable/log",
                                            "name": "log"
                                        }
                                    ]
                                },
                                {
                                    "args": [
                                        concat!(
                                            "# Vector will ignore SIGTERM (as PID != 1) and must be shut down by writing a shutdown trigger file\n",
                                            "vector & vector_pid=$!\n",
                                            "if [ ! -f \"/stackable/log/_vector/shutdown\" ]; then\n",
                                            "mkdir -p /stackable/log/_vector\n",
                                            "inotifywait -qq --event create /stackable/log/_vector;\n",
                                            "fi\n",
                                            "sleep 1\n",
                                            "kill $vector_pid"
                                        ),
                                    ],
                                    "command": [
                                        "/bin/bash",
                                        "-x",
                                        "-euo",
                                        "pipefail",
                                        "-c"
                                    ],
                                    "env": [
                                        {
                                            "name": "CLUSTER_NAME",
                                            "value":"my-opensearch-cluster",
                                        },
                                        {
                                            "name": "LOG_DIR",
                                            "value": "/stackable/log",
                                        },
                                        {
                                            "name": "NAMESPACE",
                                            "valueFrom": {
                                                "fieldRef": {
                                                    "fieldPath": "metadata.namespace",
                                                },
                                            },
                                        },
                                        {
                                            "name": "OPENSEARCH_SERVER_LOG_FILE",
                                            "value": "opensearch_server.json",
                                        },
                                        {
                                            "name": "ROLE_GROUP_NAME",
                                            "value": "default",
                                        },
                                        {
                                            "name": "ROLE_NAME",
                                            "value": "nodes",
                                        },
                                        {
                                            "name": "VECTOR_AGGREGATOR_ADDRESS",
                                            "valueFrom": {
                                                "configMapKeyRef": {
                                                    "key": "ADDRESS",
                                                    "name": "vector-aggregator",
                                                },
                                            },
                                        },
                                        {
                                            "name": "VECTOR_CONFIG_YAML",
                                            "value": "/stackable/config/vector.yaml",
                                        },
                                        {
                                            "name": "VECTOR_FILE_LOG_LEVEL",
                                            "value": "info",
                                        },
                                        {
                                            "name": "VECTOR_LOG",
                                            "value": "info",
                                        },
                                    ],
                                    "image": "oci.stackable.tech/sdp/opensearch:3.1.0-stackable0.0.0-dev",
                                    "imagePullPolicy": "Always",
                                    "name": "vector",
                                    "resources": {
                                        "limits": {
                                            "cpu": "500m",
                                            "memory": "128Mi",
                                        },
                                        "requests": {
                                            "cpu": "250m",
                                            "memory": "128Mi",
                                        },
                                    },
                                    "volumeMounts": [
                                        {
                                            "mountPath": "/stackable/config/vector.yaml",
                                            "name": "config",
                                            "readOnly": true,
                                            "subPath": "vector.yaml",
                                        },
                                        {
                                            "mountPath": "/stackable/log",
                                            "name": "log",
                                        },
                                    ],
                                },
                            ],
                            "securityContext": {
                                "fsGroup": 1000
                            },
                            "serviceAccountName": "my-opensearch-cluster-serviceaccount",
                            "terminationGracePeriodSeconds": 30,
                            "volumes": [
                                {
                                    "configMap": {
                                        "defaultMode": 0o660,
                                        "name": "my-opensearch-cluster-nodes-default"
                                    },
                                    "name": "config"
                                },
                                {
                                    "configMap": {
                                        "defaultMode": 0o660,
                                        "name": "my-opensearch-cluster-nodes-default"
                                    },
                                    "name": "log-config"
                               },
                               {
                                    "emptyDir": {
                                        "sizeLimit": "30Mi"
                                    },
                                    "name": "log"
                               }
                            ]
                        }
                    },
                    "volumeClaimTemplates": [
                        {
                            "apiVersion": "v1",
                            "kind": "PersistentVolumeClaim",
                            "metadata": {
                                "name": "data"
                            },
                            "spec": {
                                "accessModes": [
                                    "ReadWriteOnce"
                                ],
                                "resources": {
                                    "requests": {}
                                }
                            }
                        },
                        {
                            "apiVersion": "v1",
                            "kind": "PersistentVolumeClaim",
                            "metadata": {
                                "annotations": {
                                    "listeners.stackable.tech/listener-name": "my-opensearch-cluster-nodes-default"
                                },
                                "labels": {
                                    "app.kubernetes.io/component": "nodes",
                                    "app.kubernetes.io/instance": "my-opensearch-cluster",
                                    "app.kubernetes.io/managed-by": "opensearch.stackable.tech_opensearchcluster",
                                    "app.kubernetes.io/name": "opensearch",
                                    "app.kubernetes.io/role-group": "default",
                                    "app.kubernetes.io/version": "3.1.0",
                                    "stackable.tech/vendor": "Stackable"
                                },
                                "name": "listener"
                            },
                            "spec": {
                                "accessModes": [
                                    "ReadWriteMany"
                                ],
                                "resources": {
                                    "requests": {
                                        "storage": "1"
                                    }
                                },
                                "storageClassName": "listeners.stackable.tech"
                            }
                        }
                    ]
                }
            }),
            stateful_set
        );
    }

    #[test]
    fn test_build_cluster_manager_labels() {
        let cluster_manager_labels =
            RoleGroupBuilder::cluster_manager_labels(&validated_cluster(), &context_names());

        assert_eq!(
            BTreeMap::from(
                [
                    ("app.kubernetes.io/component", "nodes"),
                    ("app.kubernetes.io/instance", "my-opensearch-cluster"),
                    ("app.kubernetes.io/name", "opensearch"),
                    ("stackable.tech/opensearch-role.cluster_manager", "true")
                ]
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
            ),
            cluster_manager_labels.into()
        );
    }

    #[test]
    fn test_build_headless_service() {
        let context_names = context_names();
        let role_group_builder = role_group_builder(&context_names);

        let headless_service = serde_json::to_value(role_group_builder.build_headless_service())
            .expect("should be serializable");

        assert_eq!(
            json!({
                "apiVersion": "v1",
                "kind": "Service",
                "metadata": {
                    "annotations": {
                        "prometheus.io/path": "/_prometheus/metrics",
                        "prometheus.io/port": "9200",
                        "prometheus.io/scheme": "http",
                        "prometheus.io/scrape": "true"
                    },
                    "labels": {
                        "app.kubernetes.io/component": "nodes",
                        "app.kubernetes.io/instance": "my-opensearch-cluster",
                        "app.kubernetes.io/managed-by": "opensearch.stackable.tech_opensearchcluster",
                        "app.kubernetes.io/name": "opensearch",
                        "app.kubernetes.io/role-group": "default",
                        "app.kubernetes.io/version": "3.1.0",
                        "prometheus.io/scrape": "true",
                        "stackable.tech/vendor": "Stackable"
                    },
                    "name": "my-opensearch-cluster-nodes-default-headless",
                    "namespace": "default",
                    "ownerReferences": [
                        {
                            "apiVersion": "opensearch.stackable.tech/v1alpha1",
                            "controller": true,
                            "kind": "OpenSearchCluster",
                            "name": "my-opensearch-cluster",
                            "uid": "0b1e30e6-326e-4c1a-868d-ad6598b49e8b"
                        }
                    ]
                },
                "spec": {
                    "clusterIP": "None",
                    "ports": [
                        {
                            "name": "http",
                            "port": 9200
                        },
                        {
                            "name": "transport",
                            "port": 9300
                        }
                    ],
                    "publishNotReadyAddresses": true,
                    "selector": {
                        "app.kubernetes.io/component": "nodes",
                        "app.kubernetes.io/instance": "my-opensearch-cluster",
                        "app.kubernetes.io/name": "opensearch",
                        "app.kubernetes.io/role-group": "default"
                    },
                    "type": "ClusterIP"
                }
            }),
            headless_service
        );
    }

    #[test]
    fn test_build_listener() {
        let context_names = context_names();
        let role_group_builder = role_group_builder(&context_names);

        let listener = serde_json::to_value(role_group_builder.build_listener())
            .expect("should be serializable");

        assert_eq!(
            json!({
                "apiVersion": "listeners.stackable.tech/v1alpha1",
                "kind": "Listener",
                "metadata": {
                    "labels": {
                        "app.kubernetes.io/component": "nodes",
                        "app.kubernetes.io/instance": "my-opensearch-cluster",
                        "app.kubernetes.io/managed-by": "opensearch.stackable.tech_opensearchcluster",
                        "app.kubernetes.io/name": "opensearch",
                        "app.kubernetes.io/role-group": "default",
                        "app.kubernetes.io/version": "3.1.0",
                        "stackable.tech/vendor": "Stackable"
                    },
                    "name": "my-opensearch-cluster-nodes-default",
                    "namespace": "default",
                    "ownerReferences": [
                        {
                            "apiVersion": "opensearch.stackable.tech/v1alpha1",
                            "controller": true,
                            "kind": "OpenSearchCluster",
                            "name": "my-opensearch-cluster",
                            "uid": "0b1e30e6-326e-4c1a-868d-ad6598b49e8b"
                        }
                    ]
                },
                "spec": {
                    "className": "cluster-internal",
                    "extraPodSelectorLabels": {},
                    "ports": [
                        {
                            "name": "http",
                            "port": 9200,
                            "protocol": "TCP"
                        }
                    ],
                    "publishNotReadyAddresses": null
                }
            }),
            listener
        );
    }

    #[test]
    fn test_build_node_role_label() {
        // Test that the function does not panic on all possible inputs
        for node_role in v1alpha1::NodeRole::iter() {
            RoleGroupBuilder::build_node_role_label(&node_role);
        }
    }

    #[test]
    fn test_prometheus_annotations() {
        // Test that the function does not panic on all possible inputs
        RoleGroupBuilder::prometheus_annotations(false);
        RoleGroupBuilder::prometheus_annotations(true);
    }
}
