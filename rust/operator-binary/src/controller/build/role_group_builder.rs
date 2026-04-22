//! Builder for role group resources

use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
};

use stackable_operator::{
    builder::{
        meta::ObjectMetaBuilder,
        pod::{
            container::FieldPathEnvVar,
            volume::{SecretFormat, SecretOperatorVolumeSourceBuilder, VolumeBuilder},
        },
    },
    commons::resources::{CpuLimits, MemoryLimits, Resources},
    constants::RESTART_CONTROLLER_ENABLED_LABEL,
    crd::listener::{self},
    k8s_openapi::{
        DeepMerge,
        api::{
            apps::v1::{StatefulSet, StatefulSetSpec},
            core::v1::{
                Affinity, ConfigMap, ConfigMapVolumeSource, Container, ContainerPort,
                EmptyDirVolumeSource, KeyToPath, PodSecurityContext, PodSpec, PodTemplateSpec,
                Probe, SecretVolumeSource, Service, ServicePort, ServiceSpec, TCPSocketAction,
                Volume, VolumeMount,
            },
        },
        apimachinery::pkg::{
            api::resource::Quantity, apis::meta::v1::LabelSelector, util::intstr::IntOrString,
        },
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
        ContextNames, HTTP_PORT, HTTP_PORT_NAME, OpenSearchRoleGroupConfig, TRANSPORT_PORT,
        TRANSPORT_PORT_NAME, ValidatedCluster, ValidatedNodeRole, ValidatedSecurity,
        build::{
            product_logging::config::{
                MAX_OPENSEARCH_SERVER_LOG_FILES_SIZE, vector_config_file_extra_env_vars,
            },
            role_builder::security_config_map_name,
        },
    },
    crd::{ExtendedSecuritySettingsFileType, v1alpha1},
    framework::{
        builder::{
            meta::ownerreference_from_resource,
            pod::{
                container::{EnvVarName, EnvVarSet, new_container_builder},
                volume::{ListenerReference, listener_operator_volume_source_builder_build_pvc},
            },
            statefulset::{
                restarter_ignore_configmap_annotations, restarter_ignore_secret_annotations,
            },
        },
        kvp::label::{recommended_labels, role_group_selector, role_selector},
        product_logging::framework::{
            STACKABLE_LOG_DIR, ValidatedContainerLogConfigChoice, vector_container,
        },
        role_group_utils::ResourceNames,
        types::{
            kubernetes::{
                ConfigMapName, ListenerName, PersistentVolumeClaimName, SecretClassName,
                SecretName, ServiceAccountName, ServiceName, VolumeName,
            },
            operator::RoleGroupName,
        },
    },
};

constant!(CONFIG_VOLUME_NAME: VolumeName = "config");

constant!(LOG_CONFIG_VOLUME_NAME: VolumeName = "log-config");
constant!(DATA_VOLUME_NAME: VolumeName = "data");

// This is the main listener which is sometimes referenced by users in podOverrides, so keep its
// name simple.
constant!(ROLE_GROUP_LISTENER_VOLUME_NAME: PersistentVolumeClaimName = "listener");
const ROLE_GROUP_LISTENER_VOLUME_DIR: &str = "/stackable/listeners/role-group";

constant!(DISCOVERY_SERVICE_LISTENER_VOLUME_NAME: PersistentVolumeClaimName = "discovery-service-listener");
const DISCOVERY_SERVICE_LISTENER_VOLUME_DIR: &str = "/stackable/listeners/discovery-service";

constant!(TLS_SERVER_VOLUME_NAME: VolumeName = "tls-server");
constant!(TLS_SERVER_CA_VOLUME_NAME: VolumeName = "tls-server-ca");
const TLS_SERVER_CA_VOLUME_SIZE: &str = "1Mi";
constant!(TLS_INTERNAL_VOLUME_NAME: VolumeName = "tls-internal");
constant!(TLS_ADMIN_CERT_VOLUME_NAME: VolumeName = "tls-admin-cert");
const TLS_ADMIN_CERT_VOLUME_SIZE: &str = "1Mi";

constant!(LOG_VOLUME_NAME: VolumeName = "log");
const LOG_VOLUME_DIR: &str = "/stackable/log";

const OPENSEARCH_KEYSTORE_FILE_NAME: &str = "opensearch.keystore";
const OPENSEARCH_INITIALIZED_KEYSTORE_DIRECTORY_NAME: &str = "initialized-keystore";
const OPENSEARCH_KEYSTORE_SECRETS_DIRECTORY: &str = "keystore-secrets";
constant!(OPENSEARCH_KEYSTORE_VOLUME_NAME: VolumeName = "keystore");
const OPENSEARCH_KEYSTORE_VOLUME_SIZE: &str = "1Mi";

/// Depending on the security settings, the role group builder operates in one of these modes.
#[derive(Clone, Debug)]
pub enum RoleGroupSecurityMode {
    /// The security plugin is enabled and all settings are initialized by an arbitrary role group.
    /// The security settings are mounted to the main container for all role groups.
    Initializing {
        settings: v1alpha1::SecuritySettings,
        tls_server_secret_class: Option<SecretClassName>,
        tls_internal_secret_class: SecretClassName,
    },

    /// The security plugin is enabled and some or all settings are initialized and updated by this
    /// role group.
    /// The admin certificate is created in the [`v1alpha1::Container::CreateAdminCertificate`]
    /// init container and the security settings are mounted to and updated in the
    /// [`v1alpha1::Container::UpdateSecurityConfig`] side-car container.
    Managing {
        settings: v1alpha1::SecuritySettings,
        tls_server_secret_class: SecretClassName,
        tls_internal_secret_class: SecretClassName,
    },

    /// The security plugin is enabled and the settings are managed by another role group.
    /// The security settings are not mounted.
    Participating {
        tls_server_secret_class: SecretClassName,
        tls_internal_secret_class: SecretClassName,
    },

    /// The security plugin is disabled.
    Disabled,
}

impl RoleGroupSecurityMode {
    /// Return the TLS server SecretClass if set
    pub fn tls_server_secret_class(&self) -> Option<SecretClassName> {
        if let RoleGroupSecurityMode::Initializing {
            tls_server_secret_class: Some(tls_server_secret_class),
            ..
        }
        | RoleGroupSecurityMode::Managing {
            tls_server_secret_class,
            ..
        }
        | RoleGroupSecurityMode::Participating {
            tls_server_secret_class,
            ..
        } = self
        {
            Some(tls_server_secret_class.clone())
        } else {
            None
        }
    }

    /// Return the TLS internal SecretClass if set
    pub fn tls_internal_secret_class(&self) -> Option<SecretClassName> {
        if let RoleGroupSecurityMode::Initializing {
            tls_internal_secret_class,
            ..
        }
        | RoleGroupSecurityMode::Managing {
            tls_internal_secret_class,
            ..
        }
        | RoleGroupSecurityMode::Participating {
            tls_internal_secret_class,
            ..
        } = self
        {
            Some(tls_internal_secret_class.clone())
        } else {
            None
        }
    }
}

/// Builder for role group resources
pub struct RoleGroupBuilder<'a> {
    service_account_name: ServiceAccountName,
    cluster: &'a ValidatedCluster,
    node_config: NodeConfig,
    role_group_name: RoleGroupName,
    role_group_config: OpenSearchRoleGroupConfig,
    context_names: &'a ContextNames,
    resource_names: ResourceNames,
    discovery_service_listener_name: ListenerName,
    security_mode: RoleGroupSecurityMode,
}

impl<'a> RoleGroupBuilder<'a> {
    pub fn new(
        service_account_name: ServiceAccountName,
        cluster: &'a ValidatedCluster,
        role_group_name: RoleGroupName,
        role_group_config: OpenSearchRoleGroupConfig,
        context_names: &'a ContextNames,
        seed_nodes_service_name: ServiceName,
        discovery_service_listener_name: ListenerName,
    ) -> RoleGroupBuilder<'a> {
        let resource_names = ResourceNames {
            cluster_name: cluster.name.clone(),
            role_name: ValidatedCluster::role_name(),
            role_group_name: role_group_name.clone(),
        };

        let security_mode = match cluster.security.clone() {
            ValidatedSecurity::ManagedByApi {
                settings,
                tls_server_secret_class,
                tls_internal_secret_class,
            } => RoleGroupSecurityMode::Initializing {
                settings,
                tls_server_secret_class,
                tls_internal_secret_class,
            },
            ValidatedSecurity::ManagedByOperator {
                managing_role_group,
                settings,
                tls_server_secret_class,
                tls_internal_secret_class,
            } if managing_role_group == role_group_name => RoleGroupSecurityMode::Managing {
                settings,
                tls_server_secret_class,
                tls_internal_secret_class,
            },
            ValidatedSecurity::ManagedByOperator {
                tls_server_secret_class,
                tls_internal_secret_class,
                ..
            } => RoleGroupSecurityMode::Participating {
                tls_server_secret_class,
                tls_internal_secret_class,
            },
            ValidatedSecurity::Disabled => RoleGroupSecurityMode::Disabled,
        };

        RoleGroupBuilder {
            service_account_name,
            cluster,
            node_config: NodeConfig::new(
                cluster.clone(),
                role_group_name.clone(),
                role_group_config.clone(),
                security_mode.clone(),
                seed_nodes_service_name,
                context_names.cluster_domain_name.clone(),
                resource_names.headless_service_name(),
            ),
            role_group_name: role_group_name.clone(),
            role_group_config,
            context_names,
            resource_names,
            discovery_service_listener_name,
            security_mode,
        }
    }

    /// Builds the [`ConfigMap`] containing the configuration files for the [`StatefulSet`] of the
    /// role group
    pub fn build_config_map(&self) -> ConfigMap {
        let metadata = self
            .common_metadata(self.resource_names.role_group_config_map())
            .build();

        let mut data = BTreeMap::new();

        data.insert(
            CONFIGURATION_FILE_OPENSEARCH_YML.to_owned(),
            self.node_config.opensearch_config_file_content(),
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

    /// Builds the [`StatefulSet`] of the role group
    pub fn build_stateful_set(&self) -> StatefulSet {
        let metadata = self
            .common_metadata(self.resource_names.stateful_set_name())
            .with_label(RESTART_CONTROLLER_ENABLED_LABEL.to_owned())
            .with_annotations(self.restarter_ignore_annotations())
            .build();

        let template = self.build_pod_template();

        let data_volume_claim_template = self
            .role_group_config
            .config
            .resources
            .storage
            .data
            .build_pvc(DATA_VOLUME_NAME.as_ref(), Some(vec!["ReadWriteOnce"]));

        // Listener endpoints for all rolegroups will use persistent volumes so that load balancers
        // can hard-code the target addresses. This will be the case even when no class is set (and
        // the value defaults to cluster-internal) as the address should still be consistent.
        let role_group_listener_volume_claim_template =
            listener_operator_volume_source_builder_build_pvc(
                &ListenerReference::Listener(self.resource_names.listener_name()),
                &self.recommended_labels(),
                &ROLE_GROUP_LISTENER_VOLUME_NAME,
            );

        let maybe_discovery_service_listener_volume_claim_template = self
            .role_group_config
            .config
            .discovery_service_exposed
            .then(|| {
                listener_operator_volume_source_builder_build_pvc(
                    &ListenerReference::Listener(self.discovery_service_listener_name.to_owned()),
                    &self.recommended_labels(),
                    &DISCOVERY_SERVICE_LISTENER_VOLUME_NAME,
                )
            });

        let pvcs = vec![
            Some(data_volume_claim_template),
            Some(role_group_listener_volume_claim_template),
            maybe_discovery_service_listener_volume_claim_template,
        ]
        .into_iter()
        .flatten()
        .collect();

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
            volume_claim_templates: Some(pvcs),
            ..StatefulSetSpec::default()
        };

        StatefulSet {
            metadata,
            spec: Some(spec),
            status: None,
        }
    }

    fn restarter_ignore_annotations(&self) -> Annotations {
        let (security_settings_config_maps, security_settings_secrets) =
            self.security_settings_resource_names();

        let mut annotations = restarter_ignore_configmap_annotations(security_settings_config_maps);
        annotations.extend(restarter_ignore_secret_annotations(
            security_settings_secrets,
        ));
        annotations
    }

    /// Builds the [`PodTemplateSpec`] for the [`StatefulSet`] of the role group
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

        let containers = [
            Some(self.build_opensearch_container()),
            self.build_maybe_vector_container(),
            self.build_maybe_security_config_container(),
        ]
        .into_iter()
        .flatten()
        .collect();

        let init_containers = [
            self.build_maybe_keystore_init_container(),
            self.build_maybe_admin_certificate_init_container(),
        ]
        .into_iter()
        .flatten()
        .collect();

        let volumes = [
            self.build_config_volumes(),
            self.build_log_volumes(),
            self.build_security_volumes(),
            self.build_keystore_volumes(),
        ]
        .into_iter()
        .flatten()
        .collect();

        let affinity = Affinity {
            node_affinity: self.role_group_config.config.affinity.node_affinity.clone(),
            pod_affinity: self.role_group_config.config.affinity.pod_affinity.clone(),
            pod_anti_affinity: self
                .role_group_config
                .config
                .affinity
                .pod_anti_affinity
                .clone(),
        };

        let node_selector = self
            .role_group_config
            .config
            .affinity
            .node_selector
            .clone()
            .map(|wrapped| wrapped.node_selector);

        let security_context = PodSecurityContext {
            fs_group: Some(1000),
            ..PodSecurityContext::default()
        };

        // The PodBuilder is not used because it re-validates the values which are already
        // validated. For instance, it would be necessary to convert the
        // termination_grace_period_seconds into a Duration, the PodBuilder parses the Duration,
        // converts it back into seconds and fails if this is not possible.
        let mut pod_template = PodTemplateSpec {
            metadata: Some(metadata),
            spec: Some(PodSpec {
                affinity: Some(affinity),
                containers,
                init_containers: Some(init_containers),
                node_selector,
                security_context: Some(security_context),
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
            &ValidatedNodeRole::ClusterManager,
        ));

        labels
    }

    /// Builds a label indicating the role of the OpenSearch node
    fn build_node_role_label(node_role: &ValidatedNodeRole) -> Label {
        // It is not possible to check the infallibility of the following statement at
        // compile-time. Instead, it is tested in `tests::test_build_node_role_label`.
        Label::try_from((
            format!("stackable.tech/opensearch-role.{node_role}"),
            "true".to_string(),
        ))
        .expect("should be a valid label")
    }

    /// Builds the [`v1alpha1::Container::InitKeystore`] init container for the [`PodTemplateSpec`]
    /// if keystores are defined
    fn build_maybe_keystore_init_container(&self) -> Option<Container> {
        if self.cluster.keystores.is_empty() {
            return None;
        }

        let opensearch_home = self.node_config.opensearch_home();
        let mut volume_mounts = vec![VolumeMount {
            mount_path: format!(
                "{opensearch_home}/{OPENSEARCH_INITIALIZED_KEYSTORE_DIRECTORY_NAME}"
            ),
            name: OPENSEARCH_KEYSTORE_VOLUME_NAME.to_string(),
            ..VolumeMount::default()
        }];

        for (index, keystore) in self.cluster.keystores.iter().enumerate() {
            volume_mounts.push(VolumeMount {
                mount_path: format!(
                    "{opensearch_home}/{OPENSEARCH_KEYSTORE_SECRETS_DIRECTORY}/{}",
                    keystore.key
                ),
                name: format!("keystore-{index}"),
                read_only: Some(true),
                sub_path: Some(keystore.secret_key_ref.key.to_string()),
                ..VolumeMount::default()
            });
        }

        let container =
            new_container_builder(&v1alpha1::Container::InitKeystore.to_container_name())
                .image_from_product_image(&self.cluster.image)
                .command(vec!["/bin/bash".to_owned(), "-c".to_owned()])
                .args(vec![include_str!("scripts/init-keystore.sh").to_owned()])
                .add_volume_mounts(volume_mounts)
                .expect("The mount paths are statically defined and there should be no duplicates.")
                .resources(self.role_group_config.config.resources.clone().into())
                .build();

        Some(container)
    }

    /// Builds the [`v1alpha1::Container::CreateAdminCertificate`] init container for the
    /// [`PodTemplateSpec`] if the security mode is [`RoleGroupSecurityMode::Managing`]
    fn build_maybe_admin_certificate_init_container(&self) -> Option<Container> {
        let RoleGroupSecurityMode::Managing { .. } = self.security_mode else {
            return None;
        };

        let env_vars = EnvVarSet::new()
            .with_value(
                &EnvVarName::from_str_unsafe("ADMIN_DN"),
                self.node_config.super_admin_dn(),
            )
            .with_field_path(
                &EnvVarName::from_str_unsafe("POD_NAME"),
                FieldPathEnvVar::Name,
            );

        let volume_mounts = vec![
            VolumeMount {
                mount_path: "/stackable/tls-server/ca.crt".to_owned(),
                name: TLS_SERVER_VOLUME_NAME.to_string(),
                sub_path: Some("ca.crt".to_owned()),
                read_only: Some(true),
                ..VolumeMount::default()
            },
            VolumeMount {
                mount_path: "/stackable/tls-admin-cert".to_owned(),
                name: TLS_ADMIN_CERT_VOLUME_NAME.to_string(),
                read_only: Some(false),
                ..VolumeMount::default()
            },
            VolumeMount {
                mount_path: "/stackable/tls-server-ca".to_owned(),
                name: TLS_SERVER_CA_VOLUME_NAME.to_string(),
                read_only: Some(false),
                ..VolumeMount::default()
            },
        ];

        let container =
            new_container_builder(&v1alpha1::Container::CreateAdminCertificate.to_container_name())
                .image_from_product_image(&self.cluster.image)
                .command(vec!["/bin/bash".to_string(), "-c".to_string()])
                .args(vec![
                    include_str!("scripts/create-admin-certificate.sh").to_owned(),
                ])
                .add_env_vars(env_vars.into())
                .add_volume_mounts(volume_mounts)
                .expect("The mount paths are statically defined and there should be no duplicates.")
                .resources(
                    Resources::<()> {
                        memory: MemoryLimits {
                            limit: Some(Quantity("128Mi".to_owned())),
                            ..MemoryLimits::default()
                        },
                        cpu: CpuLimits {
                            min: Some(Quantity("100m".to_owned())),
                            max: Some(Quantity("400m".to_owned())),
                        },
                        ..Resources::default()
                    }
                    .into(),
                )
                .build();

        Some(container)
    }

    /// Builds the [`v1alpha1::Container::OpenSearch`] container for the [`PodTemplateSpec`]
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

        let opensearch_home = self.node_config.opensearch_home();
        let opensearch_path_conf = self.node_config.opensearch_path_conf();

        let mut volume_mounts = vec![
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
                mount_path: ROLE_GROUP_LISTENER_VOLUME_DIR.to_owned(),
                name: ROLE_GROUP_LISTENER_VOLUME_NAME.to_string(),
                ..VolumeMount::default()
            },
            VolumeMount {
                mount_path: LOG_VOLUME_DIR.to_owned(),
                name: LOG_VOLUME_NAME.to_string(),
                ..VolumeMount::default()
            },
        ];

        if self.role_group_config.config.discovery_service_exposed {
            volume_mounts.push(VolumeMount {
                mount_path: DISCOVERY_SERVICE_LISTENER_VOLUME_DIR.to_owned(),
                name: DISCOVERY_SERVICE_LISTENER_VOLUME_NAME.to_string(),
                ..VolumeMount::default()
            });
        }

        if self.security_mode.tls_internal_secret_class().is_some() {
            volume_mounts.push(VolumeMount {
                mount_path: format!("{opensearch_path_conf}/tls/internal"),
                name: TLS_INTERNAL_VOLUME_NAME.to_string(),
                ..VolumeMount::default()
            });
        };

        if self.security_mode.tls_server_secret_class().is_some() {
            volume_mounts.push(VolumeMount {
                mount_path: format!("{opensearch_path_conf}/tls/server/tls.crt"),
                name: TLS_SERVER_VOLUME_NAME.to_string(),
                sub_path: Some("tls.crt".to_owned()),
                ..VolumeMount::default()
            });
            volume_mounts.push(VolumeMount {
                mount_path: format!("{opensearch_path_conf}/tls/server/tls.key"),
                name: TLS_SERVER_VOLUME_NAME.to_string(),
                sub_path: Some("tls.key".to_owned()),
                ..VolumeMount::default()
            });
            volume_mounts.push(VolumeMount {
                mount_path: format!("{opensearch_path_conf}/tls/server/ca.crt"),
                name: if let RoleGroupSecurityMode::Managing { .. } = self.security_mode {
                    TLS_SERVER_CA_VOLUME_NAME.to_string()
                } else {
                    TLS_SERVER_VOLUME_NAME.to_string()
                },
                sub_path: Some("ca.crt".to_owned()),
                ..VolumeMount::default()
            });
        };

        if let RoleGroupSecurityMode::Initializing { settings, .. } = &self.security_mode {
            // Mount the security configuration files using `subPath`, because the configuration
            // files are only used for initializing the security index and hot-reloading is not
            // required.
            volume_mounts.extend(self.security_config_volume_mounts(settings, true));
        };

        if !self.cluster.keystores.is_empty() {
            volume_mounts.push(VolumeMount {
                mount_path: format!("{opensearch_path_conf}/{OPENSEARCH_KEYSTORE_FILE_NAME}"),
                name: OPENSEARCH_KEYSTORE_VOLUME_NAME.to_string(),
                sub_path: Some(OPENSEARCH_KEYSTORE_FILE_NAME.to_owned()),
                read_only: Some(true),
                ..VolumeMount::default()
            })
        }

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
            .add_env_vars(self.node_config.environment_variables().into())
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

    /// Builds the security settings volume mounts for the [`v1alpha1::Container::OpenSearch`]
    /// container or the [`v1alpha1::Container::UpdateSecurityConfig`] container
    ///
    /// If `use_sub_path` is set to `true`, then the configuration files are directly mounted via
    /// `subPath` into the opensearch-security configuration directory. If it is set to `false`,
    /// then they are mounted into sub directories of the opensearch-security configuration
    /// directory without using `subPath`. Files mounted via `subPath` are not updated on changes
    /// in the ConfigMap or Secret volume. Therefore, hot-reloading works only without `subPath`,
    /// but links from the configuration directory into the sub directories are required.
    fn security_config_volume_mounts(
        &self,
        settings: &v1alpha1::SecuritySettings,
        use_sub_path: bool,
    ) -> Vec<VolumeMount> {
        let mut volume_mounts = vec![];

        let opensearch_path_conf = self.node_config.opensearch_path_conf();

        for file_type in settings {
            let mount_path;
            let sub_path;

            if use_sub_path {
                mount_path = format!(
                    "{opensearch_path_conf}/opensearch-security/{filename}",
                    filename = file_type.filename.to_owned()
                );
                sub_path = Some(file_type.filename.to_owned());
            } else {
                mount_path = format!(
                    "{opensearch_path_conf}/opensearch-security/{file_type}",
                    file_type = file_type.id
                );
                sub_path = None;
            }

            volume_mounts.push(VolumeMount {
                mount_path,
                name: Self::security_settings_file_type_volume_name(&file_type).to_string(),
                read_only: Some(true),
                sub_path,
                ..VolumeMount::default()
            });
        }

        volume_mounts
    }

    fn security_settings_file_type_volume_name(
        file_type: &ExtendedSecuritySettingsFileType,
    ) -> VolumeName {
        VolumeName::from_str(&format!("security-config-file-{}", file_type.id))
            .expect("should be a valid VolumeName")
    }

    /// Builds the [`v1alpha1::Container::Vector`] container for the [`PodTemplateSpec`] if it is
    /// enabled
    fn build_maybe_vector_container(&self) -> Option<Container> {
        let vector_container_log_config = self
            .role_group_config
            .config
            .logging
            .vector_container
            .as_ref()?;

        Some(vector_container(
            &v1alpha1::Container::Vector.to_container_name(),
            &self.cluster.image,
            vector_container_log_config,
            &self.resource_names,
            &CONFIG_VOLUME_NAME,
            &LOG_VOLUME_NAME,
            vector_config_file_extra_env_vars(),
        ))
    }

    /// Builds the [`v1alpha1::Container::UpdateSecurityConfig`] container for the
    /// [`PodTemplateSpec`] if the security mode is [`RoleGroupSecurityMode::Managing`]
    fn build_maybe_security_config_container(&self) -> Option<Container> {
        let RoleGroupSecurityMode::Managing { settings, .. } = &self.security_mode else {
            return None;
        };

        let opensearch_path_conf = self.node_config.opensearch_path_conf();

        let mut volume_mounts = vec![
            VolumeMount {
                mount_path: format!("{opensearch_path_conf}/tls/tls.crt"),
                name: TLS_ADMIN_CERT_VOLUME_NAME.to_string(),
                read_only: Some(true),
                sub_path: Some("tls.crt".to_owned()),
                ..VolumeMount::default()
            },
            VolumeMount {
                mount_path: format!("{opensearch_path_conf}/tls/tls.key"),
                name: TLS_ADMIN_CERT_VOLUME_NAME.to_string(),
                read_only: Some(true),
                sub_path: Some("tls.key".to_owned()),
                ..VolumeMount::default()
            },
            VolumeMount {
                mount_path: format!("{opensearch_path_conf}/tls/ca.crt"),
                name: TLS_SERVER_CA_VOLUME_NAME.to_string(),
                read_only: Some(true),
                sub_path: Some("ca.crt".to_owned()),
                ..VolumeMount::default()
            },
            VolumeMount {
                mount_path: LOG_VOLUME_DIR.to_owned(),
                name: LOG_VOLUME_NAME.to_string(),
                ..VolumeMount::default()
            },
        ];

        // Mount the security configuration files without using `subPath`, so that hot-reloading
        // works.
        volume_mounts.extend(self.security_config_volume_mounts(settings, false));

        let mut env_vars = EnvVarSet::new()
            .with_value(
                &EnvVarName::from_str_unsafe("OPENSEARCH_PATH_CONF"),
                opensearch_path_conf,
            )
            .with_field_path(
                &EnvVarName::from_str_unsafe("POD_NAME"),
                FieldPathEnvVar::Name,
            );

        for file_type in settings {
            let managed_by_operator =
                *file_type.managed_by == v1alpha1::SecuritySettingsFileTypeManagedBy::Operator;

            env_vars = env_vars.with_value(
                &Self::security_settings_file_type_managed_by_env_var(&file_type),
                managed_by_operator.to_string(),
            );
        }

        let container =
            new_container_builder(&v1alpha1::Container::UpdateSecurityConfig.to_container_name())
                .image_from_product_image(&self.cluster.image)
                .command(vec!["/bin/bash".to_string(), "-c".to_string()])
                .args(vec![
                    include_str!("scripts/update-security-config.sh").to_owned(),
                ])
                .add_env_vars(env_vars.into())
                .add_volume_mounts(volume_mounts)
                .expect("The mount paths are statically defined and there should be no duplicates.")
                .resources(
                    Resources::<()> {
                        memory: MemoryLimits {
                            limit: Some(Quantity("512Mi".to_owned())),
                            ..MemoryLimits::default()
                        },
                        cpu: CpuLimits {
                            min: Some(Quantity("100m".to_owned())),
                            max: Some(Quantity("400m".to_owned())),
                        },
                        ..Resources::default()
                    }
                    .into(),
                )
                .build();

        Some(container)
    }

    /// Environment variable which is used in the `update-security-config.sh` script to determine
    /// if a security settings file type is managed by the operator
    fn security_settings_file_type_managed_by_env_var(
        file_type: &ExtendedSecuritySettingsFileType,
    ) -> EnvVarName {
        EnvVarName::from_str_unsafe(&format!("MANAGE_{}", file_type.id.to_uppercase()))
    }

    /// Builds the config volumes for the [`PodTemplateSpec`]
    fn build_config_volumes(&self) -> Vec<Volume> {
        vec![Volume {
            name: CONFIG_VOLUME_NAME.to_string(),
            config_map: Some(ConfigMapVolumeSource {
                default_mode: Some(0o660),
                name: self.resource_names.role_group_config_map().to_string(),
                ..Default::default()
            }),
            ..Volume::default()
        }]
    }

    /// Builds the log volumes for the [`PodTemplateSpec`]
    fn build_log_volumes(&self) -> Vec<Volume> {
        let log_config_volume_config_map =
            if let ValidatedContainerLogConfigChoice::Custom(config_map_name) =
                &self.role_group_config.config.logging.opensearch_container
            {
                config_map_name.clone()
            } else {
                self.resource_names.role_group_config_map()
            };

        vec![
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
        ]
    }

    /// Builds the security volumes for the [`PodTemplateSpec`] depending on the
    /// [`RoleGroupSecurityMode`]
    fn build_security_volumes(&self) -> Vec<Volume> {
        let volumes = match &self.security_mode {
            RoleGroupSecurityMode::Initializing {
                settings,
                tls_server_secret_class,
                tls_internal_secret_class,
            } => vec![
                Some(self.build_security_internal_tls_volumes(tls_internal_secret_class)),
                tls_server_secret_class
                    .as_ref()
                    .map(|tls_server_secret_class| {
                        self.build_security_server_tls_volumes(tls_server_secret_class)
                    }),
                Some(self.build_security_settings_volumes(settings)),
            ]
            .into_iter()
            .flatten()
            .collect(),
            RoleGroupSecurityMode::Managing {
                settings,
                tls_server_secret_class,
                tls_internal_secret_class,
            } => vec![
                self.build_security_internal_tls_volumes(tls_internal_secret_class),
                self.build_security_server_tls_volumes(tls_server_secret_class),
                self.build_security_settings_volumes(settings),
                self.build_security_server_tls_ca_volumes(),
                self.build_security_admin_cert_volumes(),
            ],
            RoleGroupSecurityMode::Participating {
                tls_server_secret_class,
                tls_internal_secret_class,
            } => vec![
                self.build_security_internal_tls_volumes(tls_internal_secret_class),
                self.build_security_server_tls_volumes(tls_server_secret_class),
            ],
            RoleGroupSecurityMode::Disabled => vec![],
        };

        volumes.into_iter().flatten().collect()
    }

    /// Builds the internal TLS volumes for the [`PodTemplateSpec`]
    fn build_security_internal_tls_volumes(
        &self,
        tls_internal_secret_class: &SecretClassName,
    ) -> Vec<Volume> {
        let mut volume_source_builder =
            SecretOperatorVolumeSourceBuilder::new(tls_internal_secret_class);

        volume_source_builder
            .with_pod_scope()
            .with_listener_volume_scope(ROLE_GROUP_LISTENER_VOLUME_NAME.to_string())
            .with_format(SecretFormat::TlsPem)
            .with_auto_tls_cert_lifetime(self.role_group_config.config.requested_secret_lifetime)
            .with_auto_tls_cert_domain_components_in_subject_dn(true);

        if self
            .role_group_config
            .config
            .node_roles
            .contains(&ValidatedNodeRole::ClusterManager)
        {
            volume_source_builder.with_service_scope(&self.node_config.seed_nodes_service_name);
        }

        let volume_source = volume_source_builder
            .build()
            .expect("volume should be built without parse errors");

        vec![
            VolumeBuilder::new(TLS_INTERNAL_VOLUME_NAME.to_string())
                .ephemeral(volume_source)
                .build(),
        ]
    }

    /// Builds the server TLS volumes for the [`PodTemplateSpec`] if a TLS server secret class is
    /// defined
    fn build_security_server_tls_volumes(
        &self,
        tls_server_secret_class: &SecretClassName,
    ) -> Vec<Volume> {
        let mut volume_source_builder =
            SecretOperatorVolumeSourceBuilder::new(tls_server_secret_class);

        volume_source_builder
            .with_pod_scope()
            .with_listener_volume_scope(ROLE_GROUP_LISTENER_VOLUME_NAME.to_string())
            .with_format(SecretFormat::TlsPem)
            .with_auto_tls_cert_lifetime(self.role_group_config.config.requested_secret_lifetime)
            .with_auto_tls_cert_domain_components_in_subject_dn(true);

        if self.role_group_config.config.discovery_service_exposed {
            volume_source_builder
                .with_listener_volume_scope(DISCOVERY_SERVICE_LISTENER_VOLUME_NAME.to_string());
        }

        let volume_source = volume_source_builder
            .build()
            .expect("volume should be built without parse errors");

        vec![
            VolumeBuilder::new(TLS_SERVER_VOLUME_NAME.to_string())
                .ephemeral(volume_source)
                .build(),
        ]
    }

    /// Builds the server TLS CA volumes for the [`PodTemplateSpec`]
    /// It is not checked if these volumes are required in this role group.
    fn build_security_server_tls_ca_volumes(&self) -> Vec<Volume> {
        vec![Volume {
            name: TLS_SERVER_CA_VOLUME_NAME.to_string(),
            empty_dir: Some(EmptyDirVolumeSource {
                size_limit: Some(Quantity(TLS_SERVER_CA_VOLUME_SIZE.to_owned())),
                ..EmptyDirVolumeSource::default()
            }),
            ..Volume::default()
        }]
    }

    fn security_settings_resource_names(&self) -> (BTreeSet<ConfigMapName>, BTreeSet<SecretName>) {
        let mut config_map_names = BTreeSet::new();
        let mut secret_names = BTreeSet::new();

        if let RoleGroupSecurityMode::Initializing { settings, .. }
        | RoleGroupSecurityMode::Managing { settings, .. } = &self.security_mode
        {
            for file_type in settings {
                match &file_type.content {
                    v1alpha1::SecuritySettingsFileTypeContent::Value(_) => {
                        config_map_names.insert(security_config_map_name(&self.cluster.name));
                    }
                    v1alpha1::SecuritySettingsFileTypeContent::ValueFrom(
                        v1alpha1::SecuritySettingsFileTypeContentValueFrom::ConfigMapKeyRef(
                            v1alpha1::ConfigMapKeyRef { name, .. },
                        ),
                    ) => {
                        config_map_names.insert(name.clone());
                    }
                    v1alpha1::SecuritySettingsFileTypeContent::ValueFrom(
                        v1alpha1::SecuritySettingsFileTypeContentValueFrom::SecretKeyRef(
                            v1alpha1::SecretKeyRef { name, .. },
                        ),
                    ) => {
                        secret_names.insert(name.clone());
                    }
                };
            }
        }

        (config_map_names, secret_names)
    }

    /// Builds the security settings volumes for the [`PodTemplateSpec`]
    /// It is not checked if these volumes are required in this role group.
    fn build_security_settings_volumes(
        &self,
        settings: &v1alpha1::SecuritySettings,
    ) -> Vec<Volume> {
        let mut volumes = vec![];

        for file_type in settings {
            let volume_name = Self::security_settings_file_type_volume_name(&file_type).to_string();

            let volume = match &file_type.content {
                v1alpha1::SecuritySettingsFileTypeContent::Value(_) => Volume {
                    name: volume_name,
                    config_map: Some(ConfigMapVolumeSource {
                        items: Some(vec![KeyToPath {
                            key: file_type.filename.to_owned(),
                            mode: Some(0o660),
                            path: file_type.filename.to_owned(),
                        }]),
                        name: security_config_map_name(&self.cluster.name).to_string(),
                        ..Default::default()
                    }),
                    ..Volume::default()
                },
                v1alpha1::SecuritySettingsFileTypeContent::ValueFrom(
                    v1alpha1::SecuritySettingsFileTypeContentValueFrom::ConfigMapKeyRef(
                        v1alpha1::ConfigMapKeyRef { name, key },
                    ),
                ) => Volume {
                    name: volume_name,
                    config_map: Some(ConfigMapVolumeSource {
                        items: Some(vec![KeyToPath {
                            key: key.to_string(),
                            mode: Some(0o660),
                            path: file_type.filename.to_owned(),
                        }]),
                        name: name.to_string(),
                        ..ConfigMapVolumeSource::default()
                    }),
                    ..Volume::default()
                },
                v1alpha1::SecuritySettingsFileTypeContent::ValueFrom(
                    v1alpha1::SecuritySettingsFileTypeContentValueFrom::SecretKeyRef(
                        v1alpha1::SecretKeyRef { name, key },
                    ),
                ) => Volume {
                    name: volume_name,
                    secret: Some(SecretVolumeSource {
                        items: Some(vec![KeyToPath {
                            key: key.to_string(),
                            mode: Some(0o660),
                            path: file_type.filename.to_owned(),
                        }]),
                        secret_name: Some(name.to_string()),
                        ..SecretVolumeSource::default()
                    }),
                    ..Volume::default()
                },
            };

            volumes.push(volume);
        }

        volumes
    }

    /// Builds the admin certificate volumes for the [`PodTemplateSpec`]
    /// It is not checked if these volumes are required in this role group.
    fn build_security_admin_cert_volumes(&self) -> Vec<Volume> {
        vec![Volume {
            name: TLS_ADMIN_CERT_VOLUME_NAME.to_string(),
            empty_dir: Some(EmptyDirVolumeSource {
                size_limit: Some(Quantity(TLS_ADMIN_CERT_VOLUME_SIZE.to_owned())),
                ..EmptyDirVolumeSource::default()
            }),
            ..Volume::default()
        }]
    }

    /// Builds the keystore volumes for the [`PodTemplateSpec`]
    fn build_keystore_volumes(&self) -> Vec<Volume> {
        let mut volumes = vec![];

        if !self.cluster.keystores.is_empty() {
            volumes.push(Volume {
                name: OPENSEARCH_KEYSTORE_VOLUME_NAME.to_string(),
                empty_dir: Some(EmptyDirVolumeSource {
                    size_limit: Some(Quantity(OPENSEARCH_KEYSTORE_VOLUME_SIZE.to_owned())),
                    ..EmptyDirVolumeSource::default()
                }),
                ..Volume::default()
            })
        }

        for (index, keystore) in self.cluster.keystores.iter().enumerate() {
            volumes.push(Volume {
                name: format!("keystore-{index}"),
                secret: Some(SecretVolumeSource {
                    default_mode: Some(0o660),
                    secret_name: Some(keystore.secret_key_ref.name.to_string()),
                    items: Some(vec![KeyToPath {
                        key: keystore.secret_key_ref.key.to_string(),
                        path: keystore.secret_key_ref.key.to_string(),
                        ..KeyToPath::default()
                    }]),
                    ..SecretVolumeSource::default()
                }),
                ..Volume::default()
            });
        }

        volumes
    }

    /// Builds the headless [`Service`] for the role group
    pub fn build_headless_service(&self) -> Service {
        let metadata = self
            .common_metadata(self.resource_names.headless_service_name())
            .with_labels(Self::prometheus_labels())
            .with_annotations(Self::prometheus_annotations(
                self.security_mode.tls_server_secret_class().is_some(),
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

    /// Builds the [`listener::v1alpha1::Listener`] for the role group
    ///
    /// The Listener exposes only the HTTP port.
    /// The Listener operator will create a Service per role group.
    pub fn build_listener(&self) -> listener::v1alpha1::Listener {
        let metadata = self
            .common_metadata(self.resource_names.listener_name())
            .build();

        let listener_class = self.role_group_config.config.listener_class.to_owned();

        let ports = vec![listener::v1alpha1::ListenerPort {
            name: HTTP_PORT_NAME.to_owned(),
            port: HTTP_PORT.into(),
            protocol: Some("TCP".to_owned()),
        }];

        listener::v1alpha1::Listener {
            metadata,
            spec: listener::v1alpha1::ListenerSpec {
                class_name: Some(listener_class.to_string()),
                ports: Some(ports),
                ..listener::v1alpha1::ListenerSpec::default()
            },
            status: None,
        }
    }

    /// Common metadata for role group resources
    fn common_metadata(&self, resource_name: impl Into<String>) -> ObjectMetaBuilder {
        let mut builder = ObjectMetaBuilder::new();

        builder
            .name(resource_name)
            .namespace(&self.cluster.namespace)
            .ownerreference(ownerreference_from_resource(self.cluster, None, Some(true)))
            .with_labels(self.recommended_labels());

        builder
    }

    /// Recommended labels for role group resources
    fn recommended_labels(&self) -> Labels {
        recommended_labels(
            self.cluster,
            &self.context_names.product_name,
            &self.cluster.product_version,
            &self.context_names.operator_name,
            &self.context_names.controller_name,
            &ValidatedCluster::role_name(),
            &self.role_group_name,
        )
    }

    /// Labels to select a [`Pod`] in the role group
    ///
    /// [`Pod`]: stackable_operator::k8s_openapi::api::core::v1::Pod
    fn pod_selector(&self) -> Labels {
        role_group_selector(
            self.cluster,
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
    use rstest::rstest;
    use serde_json::json;
    use stackable_operator::{
        commons::{
            affinity::StackableAffinity, networking::DomainName,
            product_image_selection::ResolvedProductImage, resources::Resources,
        },
        k8s_openapi::api::core::v1::PodTemplateSpec,
        kvp::LabelValue,
        product_logging::spec::AutomaticContainerLogConfig,
        shared::time::Duration,
    };
    use strum::IntoEnumIterator;
    use uuid::uuid;

    use super::{
        CONFIG_VOLUME_NAME, DATA_VOLUME_NAME, LOG_CONFIG_VOLUME_NAME, LOG_VOLUME_NAME,
        ROLE_GROUP_LISTENER_VOLUME_NAME, RoleGroupBuilder,
    };
    use crate::{
        controller::{
            ContextNames, OpenSearchRoleGroupConfig, ValidatedCluster,
            ValidatedContainerLogConfigChoice, ValidatedLogging, ValidatedNodeRole,
            ValidatedOpenSearchConfig, ValidatedSecurity,
            build::role_group_builder::{
                DISCOVERY_SERVICE_LISTENER_VOLUME_NAME, OPENSEARCH_KEYSTORE_VOLUME_NAME,
                TLS_INTERNAL_VOLUME_NAME, TLS_SERVER_CA_VOLUME_NAME, TLS_SERVER_VOLUME_NAME,
            },
        },
        crd::{OpenSearchKeystoreKey, v1alpha1},
        framework::{
            builder::pod::container::EnvVarSet,
            product_logging::framework::VectorContainerLogConfig,
            role_utils::GenericProductSpecificCommonConfig,
            types::{
                kubernetes::{
                    ConfigMapKey, ConfigMapName, ListenerClassName, ListenerName, NamespaceName,
                    SecretClassName, SecretKey, SecretName, ServiceAccountName, ServiceName,
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
        let _ = ROLE_GROUP_LISTENER_VOLUME_NAME;
        let _ = DISCOVERY_SERVICE_LISTENER_VOLUME_NAME;
        let _ = TLS_SERVER_VOLUME_NAME;
        let _ = TLS_SERVER_CA_VOLUME_NAME;
        let _ = TLS_INTERNAL_VOLUME_NAME;
        let _ = LOG_VOLUME_NAME;
        let _ = OPENSEARCH_KEYSTORE_VOLUME_NAME;
    }

    #[test]
    fn test_security_settings_file_type_volume_name() {
        let security_settings = v1alpha1::SecuritySettings::default();

        for file_type in &security_settings {
            // Test that the function does not panic
            let _ = RoleGroupBuilder::security_settings_file_type_volume_name(&file_type);
        }
    }

    #[test]
    fn test_security_settings_file_type_managed_by_env_var() {
        let security_settings = v1alpha1::SecuritySettings::default();

        for file_type in &security_settings {
            // Test that the function does not panic
            let _ = RoleGroupBuilder::security_settings_file_type_managed_by_env_var(&file_type);
        }
    }

    fn context_names() -> ContextNames {
        ContextNames {
            product_name: ProductName::from_str_unsafe("opensearch"),
            operator_name: OperatorName::from_str_unsafe("opensearch.stackable.tech"),
            controller_name: ControllerName::from_str_unsafe("opensearchcluster"),
            cluster_domain_name: DomainName::from_str("cluster.local")
                .expect("should be a valid domain name"),
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum TestSecurityMode {
        Initializing,
        Managing,
        Participating,
        Disabled,
    }

    fn validated_cluster(security_mode: TestSecurityMode) -> ValidatedCluster {
        let image = ResolvedProductImage {
            product_version: "3.4.0".to_owned(),
            app_version_label_value: LabelValue::from_str("3.4.0-stackable0.0.0-dev")
                .expect("should be a valid label value"),
            image: "oci.stackable.tech/sdp/opensearch:3.4.0-stackable0.0.0-dev".to_string(),
            image_pull_policy: "Always".to_owned(),
            pull_secrets: None,
        };

        let role_group_config = OpenSearchRoleGroupConfig {
            replicas: 1,
            config: ValidatedOpenSearchConfig {
                affinity: StackableAffinity::default(),
                discovery_service_exposed: true,
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
                node_roles: [
                    ValidatedNodeRole::ClusterManager,
                    ValidatedNodeRole::Data,
                    ValidatedNodeRole::Ingest,
                    ValidatedNodeRole::RemoteClusterClient,
                ]
                .into(),
                requested_secret_lifetime: Duration::from_str("1d")
                    .expect("should be a valid duration"),
                resources: Resources::default(),
                termination_grace_period_seconds: 30,
            },
            config_overrides: HashMap::default(),
            env_overrides: EnvVarSet::default(),
            cli_overrides: BTreeMap::default(),
            pod_overrides: PodTemplateSpec::default(),
            product_specific_common_config: GenericProductSpecificCommonConfig::default(),
        };

        let security_settings = v1alpha1::SecuritySettings {
            config: v1alpha1::SecuritySettingsFileType {
                managed_by: v1alpha1::SecuritySettingsFileTypeManagedBy::Operator,
                content: v1alpha1::SecuritySettingsFileTypeContent::Value(
                    v1alpha1::SecuritySettingsFileTypeContentValue {
                        value: json!({
                            "_meta": {
                              "type": "config",
                              "config_version": 2
                            },
                            "config": {
                              "dynamic": {
                                "http": {},
                                "authc": {},
                                "authz": {}
                              }
                            }
                        }),
                    },
                ),
            },
            internal_users: v1alpha1::SecuritySettingsFileType {
                managed_by: v1alpha1::SecuritySettingsFileTypeManagedBy::Api,
                content: v1alpha1::SecuritySettingsFileTypeContent::ValueFrom(
                    v1alpha1::SecuritySettingsFileTypeContentValueFrom::SecretKeyRef(
                        v1alpha1::SecretKeyRef {
                            name: SecretName::from_str_unsafe("opensearch-security-config"),
                            key: SecretKey::from_str_unsafe("internal_users.yml"),
                        },
                    ),
                ),
            },
            roles: v1alpha1::SecuritySettingsFileType {
                managed_by: v1alpha1::SecuritySettingsFileTypeManagedBy::Api,
                content: v1alpha1::SecuritySettingsFileTypeContent::ValueFrom(
                    v1alpha1::SecuritySettingsFileTypeContentValueFrom::ConfigMapKeyRef(
                        v1alpha1::ConfigMapKeyRef {
                            name: ConfigMapName::from_str_unsafe("opensearch-security-config"),
                            key: ConfigMapKey::from_str_unsafe("roles.yml"),
                        },
                    ),
                ),
            },
            ..v1alpha1::SecuritySettings::default()
        };

        let security = match security_mode {
            TestSecurityMode::Initializing => ValidatedSecurity::ManagedByApi {
                settings: security_settings,
                tls_server_secret_class: Some(SecretClassName::from_str_unsafe("tls")),
                tls_internal_secret_class: SecretClassName::from_str_unsafe("tls"),
            },
            TestSecurityMode::Managing => ValidatedSecurity::ManagedByOperator {
                managing_role_group: RoleGroupName::from_str_unsafe("default"),
                settings: security_settings,
                tls_server_secret_class: SecretClassName::from_str_unsafe("tls"),
                tls_internal_secret_class: SecretClassName::from_str_unsafe("tls"),
            },
            TestSecurityMode::Participating => ValidatedSecurity::ManagedByOperator {
                managing_role_group: RoleGroupName::from_str_unsafe("other"),
                settings: security_settings,
                tls_server_secret_class: SecretClassName::from_str_unsafe("tls"),
                tls_internal_secret_class: SecretClassName::from_str_unsafe("tls"),
            },
            TestSecurityMode::Disabled => ValidatedSecurity::Disabled,
        };

        ValidatedCluster::new(
            image.clone(),
            ProductVersion::from_str_unsafe(&image.product_version),
            ClusterName::from_str_unsafe("my-opensearch-cluster"),
            NamespaceName::from_str_unsafe("default"),
            uuid!("0b1e30e6-326e-4c1a-868d-ad6598b49e8b"),
            v1alpha1::OpenSearchRoleConfig::default(),
            [(
                RoleGroupName::from_str_unsafe("default"),
                role_group_config.clone(),
            )]
            .into(),
            security,
            vec![v1alpha1::OpenSearchKeystore {
                key: OpenSearchKeystoreKey::from_str_unsafe("Keystore1"),
                secret_key_ref: v1alpha1::SecretKeyRef {
                    name: SecretName::from_str_unsafe("my-keystore-secret"),
                    key: SecretKey::from_str_unsafe("my-keystore-file"),
                },
            }],
            None,
        )
    }

    fn role_group_builder<'a>(
        cluster: &'a ValidatedCluster,
        context_names: &'a ContextNames,
    ) -> RoleGroupBuilder<'a> {
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
            ServiceName::from_str_unsafe("my-opensearch-cluster-seed-nodes"),
            ListenerName::from_str_unsafe("my-opensearch-cluster"),
        )
    }

    #[rstest]
    fn test_build_config_map() {
        let cluster = validated_cluster(TestSecurityMode::Disabled);
        let context_names = context_names();
        let role_group_builder = role_group_builder(&cluster, &context_names);

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
                        "app.kubernetes.io/version": "3.4.0",
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

    #[rstest]
    #[case::security_mode_initializing(TestSecurityMode::Initializing)]
    #[case::security_mode_managing(TestSecurityMode::Managing)]
    #[case::security_mode_participating(TestSecurityMode::Participating)]
    #[case::security_mode_disabled(TestSecurityMode::Disabled)]
    fn test_build_stateful_set(#[case] security_mode: TestSecurityMode) {
        let cluster = validated_cluster(security_mode);
        let context_names = context_names();
        let role_group_builder = role_group_builder(&cluster, &context_names);

        let stateful_set = serde_json::to_value(role_group_builder.build_stateful_set())
            .expect("should be serializable");

        let expected_annotations = match security_mode {
            TestSecurityMode::Initializing | TestSecurityMode::Managing => json!({
                "restarter.stackable.tech/ignore-configmap.0": "my-opensearch-cluster-security-config",
                "restarter.stackable.tech/ignore-configmap.1": "opensearch-security-config",
                "restarter.stackable.tech/ignore-secret.0": "opensearch-security-config",
            }),
            TestSecurityMode::Disabled | TestSecurityMode::Participating => json!({}),
        };

        let expected_opensearch_container_volume_mounts = match security_mode {
            TestSecurityMode::Initializing => json!([
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
                    "mountPath": "/stackable/listeners/role-group",
                    "name": "listener"
                },
                {
                    "mountPath": "/stackable/log",
                    "name": "log"
                },
                {
                    "mountPath": "/stackable/listeners/discovery-service",
                    "name": "discovery-service-listener"
                },
                {
                    "mountPath": "/stackable/opensearch/config/tls/internal",
                    "name": "tls-internal"
                },
                {
                    "mountPath": "/stackable/opensearch/config/tls/server",
                    "mountPath": "/stackable/opensearch/config/tls/server/tls.crt",
                    "name": "tls-server",
                    "subPath": "tls.crt"
                },
                {
                    "mountPath": "/stackable/opensearch/config/tls/server/tls.key",
                    "name": "tls-server",
                    "subPath": "tls.key"
                },
                {
                    "mountPath": "/stackable/opensearch/config/tls/server/ca.crt",
                    "name": "tls-server",
                    "subPath": "ca.crt"
                },
                {
                    "mountPath": "/stackable/opensearch/config/opensearch-security/action_groups.yml",
                    "name": "security-config-file-actiongroups",
                    "readOnly": true,
                    "subPath": "action_groups.yml"
                },
                {
                    "mountPath": "/stackable/opensearch/config/opensearch-security/allowlist.yml",
                    "name": "security-config-file-allowlist",
                    "readOnly": true,
                    "subPath": "allowlist.yml"
                },
                {
                    "mountPath": "/stackable/opensearch/config/opensearch-security/audit.yml",
                    "name": "security-config-file-audit",
                    "readOnly": true,
                    "subPath": "audit.yml"
                },
                {
                    "mountPath": "/stackable/opensearch/config/opensearch-security/config.yml",
                    "name": "security-config-file-config",
                    "readOnly": true,
                    "subPath": "config.yml"
                },
                {
                    "mountPath": "/stackable/opensearch/config/opensearch-security/internal_users.yml",
                    "name": "security-config-file-internalusers",
                    "readOnly": true,
                    "subPath": "internal_users.yml"
                },
                {
                    "mountPath": "/stackable/opensearch/config/opensearch-security/nodes_dn.yml",
                    "name": "security-config-file-nodesdn",
                    "readOnly": true,
                    "subPath": "nodes_dn.yml"
                },
                {
                    "mountPath": "/stackable/opensearch/config/opensearch-security/roles.yml",
                    "name": "security-config-file-roles",
                    "readOnly": true,
                    "subPath": "roles.yml"
                },
                {
                    "mountPath": "/stackable/opensearch/config/opensearch-security/roles_mapping.yml",
                    "name": "security-config-file-rolesmapping",
                    "readOnly": true,
                    "subPath": "roles_mapping.yml"
                },
                {
                    "mountPath": "/stackable/opensearch/config/opensearch-security/tenants.yml",
                    "name": "security-config-file-tenants",
                    "readOnly": true,
                    "subPath": "tenants.yml"
                },
                {
                    "mountPath": "/stackable/opensearch/config/opensearch.keystore",
                    "name": "keystore",
                    "readOnly": true,
                    "subPath": "opensearch.keystore"
                }
            ]),
            TestSecurityMode::Managing => json!([
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
                    "mountPath": "/stackable/listeners/role-group",
                    "name": "listener"
                },
                {
                    "mountPath": "/stackable/log",
                    "name": "log"
                },
                {
                    "mountPath": "/stackable/listeners/discovery-service",
                    "name": "discovery-service-listener"
                },
                {
                    "mountPath": "/stackable/opensearch/config/tls/internal",
                    "name": "tls-internal"
                },
                {
                    "mountPath": "/stackable/opensearch/config/tls/server",
                    "mountPath": "/stackable/opensearch/config/tls/server/tls.crt",
                    "name": "tls-server",
                    "subPath": "tls.crt"
                },
                {
                    "mountPath": "/stackable/opensearch/config/tls/server/tls.key",
                    "name": "tls-server",
                    "subPath": "tls.key"
                },
                {
                    "mountPath": "/stackable/opensearch/config/tls/server/ca.crt",
                    "name": "tls-server-ca",
                    "subPath": "ca.crt"
                },
                {
                    "mountPath": "/stackable/opensearch/config/opensearch.keystore",
                    "name": "keystore",
                    "readOnly": true,
                    "subPath": "opensearch.keystore"
                }
            ]),
            TestSecurityMode::Participating => json!([
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
                    "mountPath": "/stackable/listeners/role-group",
                    "name": "listener"
                },
                {
                    "mountPath": "/stackable/log",
                    "name": "log"
                },
                {
                    "mountPath": "/stackable/listeners/discovery-service",
                    "name": "discovery-service-listener"
                },
                {
                    "mountPath": "/stackable/opensearch/config/tls/internal",
                    "name": "tls-internal"
                },
                {
                    "mountPath": "/stackable/opensearch/config/tls/server",
                    "mountPath": "/stackable/opensearch/config/tls/server/tls.crt",
                    "name": "tls-server",
                    "subPath": "tls.crt"
                },
                {
                    "mountPath": "/stackable/opensearch/config/tls/server/tls.key",
                    "name": "tls-server",
                    "subPath": "tls.key"
                },
                {
                    "mountPath": "/stackable/opensearch/config/tls/server/ca.crt",
                    "name": "tls-server",
                    "subPath": "ca.crt"
                },
                {
                    "mountPath": "/stackable/opensearch/config/opensearch.keystore",
                    "name": "keystore",
                    "readOnly": true,
                    "subPath": "opensearch.keystore"
                }
            ]),
            TestSecurityMode::Disabled => json!([
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
                    "mountPath": "/stackable/listeners/role-group",
                    "name": "listener"
                },
                {
                    "mountPath": "/stackable/log",
                    "name": "log"
                },
                {
                    "mountPath": "/stackable/listeners/discovery-service",
                    "name": "discovery-service-listener"
                },
                {
                    "mountPath": "/stackable/opensearch/config/opensearch.keystore",
                    "name": "keystore",
                    "readOnly": true,
                    "subPath": "opensearch.keystore"
                }
            ]),
        };

        let expected_opensearch_container = json!({
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
                    "name": "_POD_NAME",
                    "valueFrom": {
                        "fieldRef": {
                            "fieldPath": "metadata.name"
                        }
                    }
                },
                {
                    "name": "discovery.seed_hosts",
                    "value": "my-opensearch-cluster-seed-nodes.default.svc.cluster.local"
                },
                {
                    "name": "http.publish_host",
                    "value": "$(_POD_NAME).my-opensearch-cluster-nodes-default-headless.default.svc.cluster.local"
                },
                {
                    "name": "network.publish_host",
                    "value": "$(_POD_NAME).my-opensearch-cluster-nodes-default-headless.default.svc.cluster.local"
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
                },
                {
                    "name": "transport.publish_host",
                    "value": "$(_POD_NAME).my-opensearch-cluster-nodes-default-headless.default.svc.cluster.local"
                },
            ],
            "image": "oci.stackable.tech/sdp/opensearch:3.4.0-stackable0.0.0-dev",
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
            "volumeMounts": expected_opensearch_container_volume_mounts
        });

        let expected_vector_container = json!({
            "args": [
                concat!(
                    "mkdir --parents /stackable/log/_vector-state\n",
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
                    "name": "DATA_DIR",
                    "value": "/stackable/log/_vector-state",
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
            "image": "oci.stackable.tech/sdp/opensearch:3.4.0-stackable0.0.0-dev",
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
        });

        let expected_update_security_config_container = json!({
            "args": [
                include_str!("scripts/update-security-config.sh")
            ],
            "command": [
                "/bin/bash",
                "-c",
            ],
            "env": [
                {
                    "name": "MANAGE_ACTIONGROUPS",
                    "value": "false",
                },
                {
                    "name": "MANAGE_ALLOWLIST",
                    "value": "false",
                },
                {
                    "name": "MANAGE_AUDIT",
                    "value": "false",
                },
                {
                    "name": "MANAGE_CONFIG",
                    "value": "true",
                },
                {
                    "name": "MANAGE_INTERNALUSERS",
                    "value": "false",
                },
                {
                    "name": "MANAGE_NODESDN",
                    "value": "false",
                },
                {
                    "name": "MANAGE_ROLES",
                    "value": "false",
                },
                {
                    "name": "MANAGE_ROLESMAPPING",
                    "value": "false",
                },
                {
                    "name": "MANAGE_TENANTS",
                    "value": "false",
                },
                {
                    "name": "OPENSEARCH_PATH_CONF",
                    "value": "/stackable/opensearch/config",
                },
                {
                    "name": "POD_NAME",
                    "valueFrom": {
                        "fieldRef": {
                            "fieldPath": "metadata.name",
                        },
                    },
                },
            ],
            "image": "oci.stackable.tech/sdp/opensearch:3.4.0-stackable0.0.0-dev",
            "imagePullPolicy": "Always",
            "name": "update-security-config",
            "resources": {
                "limits": {
                    "cpu": "400m",
                    "memory": "512Mi",
                },
                "requests": {
                    "cpu": "100m",
                    "memory": "512Mi",
                },
            },
            "volumeMounts": [
                {
                    "mountPath": "/stackable/opensearch/config/tls/tls.crt",
                    "name": "tls-admin-cert",
                    "readOnly": true,
                    "subPath": "tls.crt",
                },
                {
                    "mountPath": "/stackable/opensearch/config/tls/tls.key",
                    "name": "tls-admin-cert",
                    "readOnly": true,
                    "subPath": "tls.key",
                },
                {
                    "mountPath": "/stackable/opensearch/config/tls/ca.crt",
                    "name": "tls-server-ca",
                    "readOnly": true,
                    "subPath": "ca.crt",
                },
                {
                    "mountPath": "/stackable/log",
                    "name": "log",
                },
                {
                    "mountPath": "/stackable/opensearch/config/opensearch-security/actiongroups",
                    "name": "security-config-file-actiongroups",
                    "readOnly": true,
                },
                {
                    "mountPath": "/stackable/opensearch/config/opensearch-security/allowlist",
                    "name": "security-config-file-allowlist",
                    "readOnly": true,
                },
                {
                    "mountPath": "/stackable/opensearch/config/opensearch-security/audit",
                    "name": "security-config-file-audit",
                    "readOnly": true,
                },
                {
                    "mountPath": "/stackable/opensearch/config/opensearch-security/config",
                    "name": "security-config-file-config",
                    "readOnly": true,
                },
                {
                    "mountPath": "/stackable/opensearch/config/opensearch-security/internalusers",
                    "name": "security-config-file-internalusers",
                    "readOnly": true,
                },
                {
                    "mountPath": "/stackable/opensearch/config/opensearch-security/nodesdn",
                    "name": "security-config-file-nodesdn",
                    "readOnly": true,
                },
                {
                    "mountPath": "/stackable/opensearch/config/opensearch-security/roles",
                    "name": "security-config-file-roles",
                    "readOnly": true,
                },
                {
                    "mountPath": "/stackable/opensearch/config/opensearch-security/rolesmapping",
                    "name": "security-config-file-rolesmapping",
                    "readOnly": true,
                },
                {
                    "mountPath": "/stackable/opensearch/config/opensearch-security/tenants",
                    "name": "security-config-file-tenants",
                    "readOnly": true,
                },
            ],
        });

        let expected_containers = match security_mode {
            TestSecurityMode::Initializing => {
                json!([expected_opensearch_container, expected_vector_container])
            }
            TestSecurityMode::Managing => {
                json!([
                    expected_opensearch_container,
                    expected_vector_container,
                    expected_update_security_config_container
                ])
            }
            TestSecurityMode::Participating => {
                json!([expected_opensearch_container, expected_vector_container])
            }
            TestSecurityMode::Disabled => {
                json!([expected_opensearch_container, expected_vector_container])
            }
        };

        let expected_init_keystore_container = json!({
            "args": [
                include_str!("scripts/init-keystore.sh")
            ],
            "command": [
                "/bin/bash",
                "-c"
            ],
            "image": "oci.stackable.tech/sdp/opensearch:3.4.0-stackable0.0.0-dev",
            "imagePullPolicy": "Always",
            "name": "init-keystore",
            "resources": {},
            "volumeMounts": [
                {
                    "mountPath": "/stackable/opensearch/initialized-keystore",
                    "name": "keystore",
                },
                {
                    "mountPath": "/stackable/opensearch/keystore-secrets/Keystore1",
                    "name": "keystore-0",
                    "readOnly": true,
                    "subPath": "my-keystore-file"
                }
            ]
        });

        let expected_create_admin_certificate_container = json!({
            "args": [
                include_str!("scripts/create-admin-certificate.sh")
            ],
            "command": [
                "/bin/bash",
                "-c",
            ],
            "env": [
                {
                    "name": "ADMIN_DN",
                    "value": "CN=update-security-config.0b1e30e6-326e-4c1a-868d-ad6598b49e8b",
                },
                {
                    "name": "POD_NAME",
                    "valueFrom": {
                        "fieldRef": {
                            "fieldPath": "metadata.name",
                        },
                    },
                },
            ],
            "image": "oci.stackable.tech/sdp/opensearch:3.4.0-stackable0.0.0-dev",
            "imagePullPolicy": "Always",
            "name": "create-admin-certificate",
            "resources": {
                "limits": {
                    "cpu": "400m",
                    "memory": "128Mi",
                },
                "requests": {
                    "cpu": "100m",
                    "memory": "128Mi",
                },
            },
            "volumeMounts": [
                {
                    "mountPath": "/stackable/tls-server/ca.crt",
                    "name": "tls-server",
                    "readOnly": true,
                    "subPath": "ca.crt",
                },
                {
                    "mountPath": "/stackable/tls-admin-cert",
                    "name": "tls-admin-cert",
                    "readOnly": false,
                },
                {
                    "mountPath": "/stackable/tls-server-ca",
                    "name": "tls-server-ca",
                    "readOnly": false,
                },
            ],
        });

        let expected_init_containers = match security_mode {
            TestSecurityMode::Initializing => json!([expected_init_keystore_container]),
            TestSecurityMode::Managing => json!([
                expected_init_keystore_container,
                expected_create_admin_certificate_container
            ]),
            TestSecurityMode::Participating => json!([expected_init_keystore_container]),
            TestSecurityMode::Disabled => json!([expected_init_keystore_container]),
        };

        let expected_volumes = match security_mode {
            TestSecurityMode::Initializing => json!([
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
                },
                {
                    "ephemeral": {
                        "volumeClaimTemplate": {
                            "metadata": {
                                "annotations": {
                                    "secrets.stackable.tech/backend.autotls.cert.lifetime": "1d",
                                    "secrets.stackable.tech/class": "tls",
                                    "secrets.stackable.tech/format": "tls-pem",
                                    "secrets.stackable.tech/scope": "pod,listener-volume=listener,service=my-opensearch-cluster-seed-nodes"
                                }
                            },
                            "spec": {
                                "accessModes": [
                                    "ReadWriteOnce"
                                ],
                                "resources": {
                                    "requests": {
                                        "storage": "1"
                                    }
                                },
                                "storageClassName": "secrets.stackable.tech"
                            }
                        }
                    },
                    "name": "tls-internal"
                },
                {
                    "ephemeral": {
                        "volumeClaimTemplate": {
                            "metadata": {
                                "annotations": {
                                    "secrets.stackable.tech/backend.autotls.cert.lifetime": "1d",
                                    "secrets.stackable.tech/class": "tls",
                                    "secrets.stackable.tech/format": "tls-pem",
                                    "secrets.stackable.tech/scope": "pod,listener-volume=listener,listener-volume=discovery-service-listener"
                                }
                            },
                            "spec": {
                                "accessModes": [
                                    "ReadWriteOnce"
                                ],
                                "resources": {
                                    "requests": {
                                        "storage": "1"
                                    }
                                },
                                "storageClassName": "secrets.stackable.tech"
                            }
                        }
                    },
                    "name": "tls-server"
                },
                {
                    "configMap": {
                        "items": [
                            {
                                "key": "action_groups.yml",
                                "mode": 0o660,
                                "path": "action_groups.yml"
                            }
                        ],
                        "name": "my-opensearch-cluster-security-config"
                    },
                    "name": "security-config-file-actiongroups"
                },
                {
                    "configMap": {
                        "items": [
                            {
                                "key": "allowlist.yml",
                                "mode": 0o660,
                                "path": "allowlist.yml"
                            }
                        ],
                        "name": "my-opensearch-cluster-security-config"
                    },
                    "name": "security-config-file-allowlist"
                },
                {
                    "configMap": {
                        "items": [
                            {
                                "key": "audit.yml",
                                "mode": 0o660,
                                "path": "audit.yml"
                            }
                        ],
                        "name": "my-opensearch-cluster-security-config"
                    },
                    "name": "security-config-file-audit"
                },
                {
                    "configMap": {
                        "items": [
                            {
                                "key": "config.yml",
                                "mode": 0o660,
                                "path": "config.yml"
                            }
                        ],
                        "name": "my-opensearch-cluster-security-config"
                    },
                    "name": "security-config-file-config"
                },
                {
                    "name": "security-config-file-internalusers",
                    "secret": {
                        "items": [
                            {
                                "key": "internal_users.yml",
                                "mode": 0o660,
                                "path": "internal_users.yml"
                            }
                        ],
                        "secretName": "opensearch-security-config"
                    }
                },
                {
                    "configMap": {
                        "items": [
                            {
                                "key": "nodes_dn.yml",
                                "mode": 0o660,
                                "path": "nodes_dn.yml"
                            }
                        ],
                        "name": "my-opensearch-cluster-security-config"
                    },
                    "name": "security-config-file-nodesdn"
                },
                {
                    "configMap": {
                        "items": [
                            {
                                "key": "roles.yml",
                                "mode": 0o660,
                                "path": "roles.yml"
                            }
                        ],
                        "name": "opensearch-security-config"
                    },
                    "name": "security-config-file-roles"
                },
                {
                    "configMap": {
                        "items": [
                            {
                                "key": "roles_mapping.yml",
                                "mode": 0o660,
                                "path": "roles_mapping.yml"
                            }
                        ],
                        "name": "my-opensearch-cluster-security-config"
                    },
                    "name": "security-config-file-rolesmapping"
                },
                {
                    "configMap": {
                        "items": [
                            {
                                "key": "tenants.yml",
                                "mode": 0o660,
                                "path": "tenants.yml"
                            }
                        ],
                        "name": "my-opensearch-cluster-security-config"
                    },
                    "name": "security-config-file-tenants"
                },
                {
                    "emptyDir": {
                        "sizeLimit": "1Mi"
                    },
                    "name": "keystore"
                },
                {
                    "name": "keystore-0",
                    "secret": {
                        "defaultMode": 0o660,
                        "items": [
                            {
                                "key": "my-keystore-file",
                                "path": "my-keystore-file"
                            }
                        ],
                        "secretName": "my-keystore-secret"
                    }
                }
            ]),
            TestSecurityMode::Managing => json!([
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
                },
                {
                    "ephemeral": {
                        "volumeClaimTemplate": {
                            "metadata": {
                                "annotations": {
                                    "secrets.stackable.tech/backend.autotls.cert.lifetime": "1d",
                                    "secrets.stackable.tech/class": "tls",
                                    "secrets.stackable.tech/format": "tls-pem",
                                    "secrets.stackable.tech/scope": "pod,listener-volume=listener,service=my-opensearch-cluster-seed-nodes"
                                }
                            },
                            "spec": {
                                "accessModes": [
                                    "ReadWriteOnce"
                                ],
                                "resources": {
                                    "requests": {
                                        "storage": "1"
                                    }
                                },
                                "storageClassName": "secrets.stackable.tech"
                            }
                        }
                    },
                    "name": "tls-internal"
                },
                {
                    "ephemeral": {
                        "volumeClaimTemplate": {
                            "metadata": {
                                "annotations": {
                                    "secrets.stackable.tech/backend.autotls.cert.lifetime": "1d",
                                    "secrets.stackable.tech/class": "tls",
                                    "secrets.stackable.tech/format": "tls-pem",
                                    "secrets.stackable.tech/scope": "pod,listener-volume=listener,listener-volume=discovery-service-listener"
                                }
                            },
                            "spec": {
                                "accessModes": [
                                    "ReadWriteOnce"
                                ],
                                "resources": {
                                    "requests": {
                                        "storage": "1"
                                    }
                                },
                                "storageClassName": "secrets.stackable.tech"
                            }
                        }
                    },
                    "name": "tls-server"
                },
                {
                    "configMap": {
                        "items": [
                            {
                                "key": "action_groups.yml",
                                "mode": 0o660,
                                "path": "action_groups.yml"
                            }
                        ],
                        "name": "my-opensearch-cluster-security-config"
                    },
                    "name": "security-config-file-actiongroups"
                },
                {
                    "configMap": {
                        "items": [
                            {
                                "key": "allowlist.yml",
                                "mode": 0o660,
                                "path": "allowlist.yml"
                            }
                        ],
                        "name": "my-opensearch-cluster-security-config"
                    },
                    "name": "security-config-file-allowlist"
                },
                {
                    "configMap": {
                        "items": [
                            {
                                "key": "audit.yml",
                                "mode": 0o660,
                                "path": "audit.yml"
                            }
                        ],
                        "name": "my-opensearch-cluster-security-config"
                    },
                    "name": "security-config-file-audit"
                },
                {
                    "configMap": {
                        "items": [
                            {
                                "key": "config.yml",
                                "mode": 0o660,
                                "path": "config.yml"
                            }
                        ],
                        "name": "my-opensearch-cluster-security-config"
                    },
                    "name": "security-config-file-config"
                },
                {
                    "name": "security-config-file-internalusers",
                    "secret": {
                        "items": [
                            {
                                "key": "internal_users.yml",
                                "mode": 0o660,
                                "path": "internal_users.yml"
                            }
                        ],
                        "secretName": "opensearch-security-config"
                    }
                },
                {
                    "configMap": {
                        "items": [
                            {
                                "key": "nodes_dn.yml",
                                "mode": 0o660,
                                "path": "nodes_dn.yml"
                            }
                        ],
                        "name": "my-opensearch-cluster-security-config"
                    },
                    "name": "security-config-file-nodesdn"
                },
                {
                    "configMap": {
                        "items": [
                            {
                                "key": "roles.yml",
                                "mode": 0o660,
                                "path": "roles.yml"
                            }
                        ],
                        "name": "opensearch-security-config"
                    },
                    "name": "security-config-file-roles"
                },
                {
                    "configMap": {
                        "items": [
                            {
                                "key": "roles_mapping.yml",
                                "mode": 0o660,
                                "path": "roles_mapping.yml"
                            }
                        ],
                        "name": "my-opensearch-cluster-security-config"
                    },
                    "name": "security-config-file-rolesmapping"
                },
                {
                    "configMap": {
                        "items": [
                            {
                                "key": "tenants.yml",
                                "mode": 0o660,
                                "path": "tenants.yml"
                            }
                        ],
                        "name": "my-opensearch-cluster-security-config"
                    },
                    "name": "security-config-file-tenants"
                },
                {
                    "emptyDir": {
                        "sizeLimit": "1Mi",
                    },
                    "name": "tls-server-ca",
                },
                {
                    "emptyDir": {
                        "sizeLimit": "1Mi",
                    },
                    "name": "tls-admin-cert",
                },
                {
                    "emptyDir": {
                        "sizeLimit": "1Mi"
                    },
                    "name": "keystore"
                },
                {
                    "name": "keystore-0",
                    "secret": {
                        "defaultMode": 0o660,
                        "items": [
                            {
                                "key": "my-keystore-file",
                                "path": "my-keystore-file"
                            }
                        ],
                        "secretName": "my-keystore-secret"
                    }
                }
            ]),
            TestSecurityMode::Participating => json!([
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
                },
                {
                    "ephemeral": {
                        "volumeClaimTemplate": {
                            "metadata": {
                                "annotations": {
                                    "secrets.stackable.tech/backend.autotls.cert.lifetime": "1d",
                                    "secrets.stackable.tech/class": "tls",
                                    "secrets.stackable.tech/format": "tls-pem",
                                    "secrets.stackable.tech/scope": "pod,listener-volume=listener,service=my-opensearch-cluster-seed-nodes"
                                }
                            },
                            "spec": {
                                "accessModes": [
                                    "ReadWriteOnce"
                                ],
                                "resources": {
                                    "requests": {
                                        "storage": "1"
                                    }
                                },
                                "storageClassName": "secrets.stackable.tech"
                            }
                        }
                    },
                    "name": "tls-internal"
                },
                {
                    "ephemeral": {
                        "volumeClaimTemplate": {
                            "metadata": {
                                "annotations": {
                                    "secrets.stackable.tech/backend.autotls.cert.lifetime": "1d",
                                    "secrets.stackable.tech/class": "tls",
                                    "secrets.stackable.tech/format": "tls-pem",
                                    "secrets.stackable.tech/scope": "pod,listener-volume=listener,listener-volume=discovery-service-listener"
                                }
                            },
                            "spec": {
                                "accessModes": [
                                    "ReadWriteOnce"
                                ],
                                "resources": {
                                    "requests": {
                                        "storage": "1"
                                    }
                                },
                                "storageClassName": "secrets.stackable.tech"
                            }
                        }
                    },
                    "name": "tls-server"
                },
                {
                    "emptyDir": {
                        "sizeLimit": "1Mi"
                    },
                    "name": "keystore"
                },
                {
                    "name": "keystore-0",
                    "secret": {
                        "defaultMode": 0o660,
                        "items": [
                            {
                                "key": "my-keystore-file",
                                "path": "my-keystore-file"
                            }
                        ],
                        "secretName": "my-keystore-secret"
                    }
                }
            ]),
            TestSecurityMode::Disabled => json!([
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
                },
                {
                    "emptyDir": {
                        "sizeLimit": "1Mi"
                    },
                    "name": "keystore"
                },
                {
                    "name": "keystore-0",
                    "secret": {
                        "defaultMode": 0o660,
                        "items": [
                            {
                                "key": "my-keystore-file",
                                "path": "my-keystore-file"
                            }
                        ],
                        "secretName": "my-keystore-secret"
                    }
                }
            ]),
        };

        assert_eq!(
            json!({
                "apiVersion": "apps/v1",
                "kind": "StatefulSet",
                "metadata": {
                    "annotations": expected_annotations,
                    "labels": {
                        "app.kubernetes.io/component": "nodes",
                        "app.kubernetes.io/instance": "my-opensearch-cluster",
                        "app.kubernetes.io/managed-by": "opensearch.stackable.tech_opensearchcluster",
                        "app.kubernetes.io/name": "opensearch",
                        "app.kubernetes.io/role-group": "default",
                        "app.kubernetes.io/version": "3.4.0",
                        "stackable.tech/vendor": "Stackable",
                        "restarter.stackable.tech/enabled": "true"
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
                                "app.kubernetes.io/version": "3.4.0",
                                "stackable.tech/opensearch-role.cluster_manager": "true",
                                "stackable.tech/opensearch-role.data": "true",
                                "stackable.tech/opensearch-role.ingest": "true",
                                "stackable.tech/opensearch-role.remote_cluster_client": "true",
                                "stackable.tech/vendor": "Stackable"
                            }
                        },
                        "spec": {
                            "affinity": {},
                            "containers": expected_containers,
                            "initContainers": expected_init_containers,
                            "securityContext": {
                                "fsGroup": 1000
                            },
                            "serviceAccountName": "my-opensearch-cluster-serviceaccount",
                            "terminationGracePeriodSeconds": 30,
                            "volumes": expected_volumes,
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
                                    "app.kubernetes.io/version": "3.4.0",
                                    "stackable.tech/vendor": "Stackable"
                                },
                                "name": "listener"
                            },
                            "spec": {
                                "accessModes": [
                                    "ReadWriteMany",
                                ],
                                "resources": {
                                    "requests": {
                                        "storage": "1",
                                    },
                                },
                                "storageClassName": "listeners.stackable.tech",
                            },
                        },
                        {
                            "apiVersion": "v1",
                            "kind": "PersistentVolumeClaim",
                            "metadata": {
                                "annotations": {
                                    "listeners.stackable.tech/listener-name": "my-opensearch-cluster",
                                },
                                "labels": {
                                    "app.kubernetes.io/component": "nodes",
                                    "app.kubernetes.io/instance": "my-opensearch-cluster",
                                    "app.kubernetes.io/managed-by": "opensearch.stackable.tech_opensearchcluster",
                                    "app.kubernetes.io/name": "opensearch",
                                    "app.kubernetes.io/role-group": "default",
                                    "app.kubernetes.io/version": "3.4.0",
                                    "stackable.tech/vendor": "Stackable",
                                },
                                "name": "discovery-service-listener",
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

    #[rstest]
    #[case::security_mode_initializing(TestSecurityMode::Initializing)]
    #[case::security_mode_managing(TestSecurityMode::Managing)]
    #[case::security_mode_participating(TestSecurityMode::Participating)]
    #[case::security_mode_disabled(TestSecurityMode::Disabled)]
    fn test_build_cluster_manager_labels(#[case] security_mode: TestSecurityMode) {
        let cluster_manager_labels = RoleGroupBuilder::cluster_manager_labels(
            &validated_cluster(security_mode),
            &context_names(),
        );

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

    #[rstest]
    #[case::security_mode_initializing(TestSecurityMode::Initializing)]
    #[case::security_mode_managing(TestSecurityMode::Managing)]
    #[case::security_mode_participating(TestSecurityMode::Participating)]
    #[case::security_mode_disabled(TestSecurityMode::Disabled)]
    fn test_build_headless_service(#[case] security_mode: TestSecurityMode) {
        let cluster = validated_cluster(security_mode);
        let context_names = context_names();
        let role_group_builder = role_group_builder(&cluster, &context_names);

        let headless_service = serde_json::to_value(role_group_builder.build_headless_service())
            .expect("should be serializable");

        let expected_scheme = if security_mode == TestSecurityMode::Disabled {
            json!("http")
        } else {
            json!("https")
        };

        assert_eq!(
            json!({
                "apiVersion": "v1",
                "kind": "Service",
                "metadata": {
                    "annotations": {
                        "prometheus.io/path": "/_prometheus/metrics",
                        "prometheus.io/port": "9200",
                        "prometheus.io/scheme": expected_scheme,
                        "prometheus.io/scrape": "true"
                    },
                    "labels": {
                        "app.kubernetes.io/component": "nodes",
                        "app.kubernetes.io/instance": "my-opensearch-cluster",
                        "app.kubernetes.io/managed-by": "opensearch.stackable.tech_opensearchcluster",
                        "app.kubernetes.io/name": "opensearch",
                        "app.kubernetes.io/role-group": "default",
                        "app.kubernetes.io/version": "3.4.0",
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

    #[rstest]
    #[case::security_mode_initializing(TestSecurityMode::Initializing)]
    #[case::security_mode_managing(TestSecurityMode::Managing)]
    #[case::security_mode_participating(TestSecurityMode::Participating)]
    #[case::security_mode_disabled(TestSecurityMode::Disabled)]
    fn test_build_listener(#[case] security_mode: TestSecurityMode) {
        let cluster = validated_cluster(security_mode);
        let context_names = context_names();
        let role_group_builder = role_group_builder(&cluster, &context_names);

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
                        "app.kubernetes.io/version": "3.4.0",
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
                    "objectOverrides": [],
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
        for node_role in ValidatedNodeRole::iter() {
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
