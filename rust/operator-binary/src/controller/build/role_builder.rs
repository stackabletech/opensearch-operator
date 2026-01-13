//! Builder for role resources

use std::str::FromStr;

use stackable_operator::{
    builder::meta::ObjectMetaBuilder,
    crd::listener,
    k8s_openapi::{
        Resource,
        api::{
            core::v1::{ConfigMap, Service, ServiceAccount, ServicePort, ServiceSpec},
            policy::v1::PodDisruptionBudget,
            rbac::v1::{ClusterRole, RoleBinding, RoleRef, Subject},
        },
    },
    kube::api::ObjectMeta,
    kvp::{
        Label, Labels,
        consts::{STACKABLE_VENDOR_KEY, STACKABLE_VENDOR_VALUE},
    },
};

use crate::{
    controller::{
        ContextNames, ValidatedCluster,
        build::role_group_builder::{
            HTTP_PORT, HTTP_PORT_NAME, RoleGroupBuilder, TRANSPORT_PORT, TRANSPORT_PORT_NAME,
        },
    },
    framework::{
        NameIsValidLabelValue,
        builder::{
            meta::ownerreference_from_resource, pdb::pod_disruption_budget_builder_with_role,
        },
        role_utils::ResourceNames,
        types::{
            kubernetes::{ConfigMapName, ListenerName, ServiceName},
            operator::ClusterName,
        },
    },
};

const PDB_DEFAULT_MAX_UNAVAILABLE: u16 = 1;

/// Builder for role resources
pub struct RoleBuilder<'a> {
    cluster: ValidatedCluster,
    context_names: &'a ContextNames,
    resource_names: ResourceNames,
}

impl<'a> RoleBuilder<'a> {
    pub fn new(cluster: ValidatedCluster, context_names: &'a ContextNames) -> RoleBuilder<'a> {
        RoleBuilder {
            cluster: cluster.clone(),
            context_names,
            resource_names: ResourceNames {
                cluster_name: cluster.name.clone(),
                product_name: context_names.product_name.clone(),
            },
        }
    }

    /// Creates role-group builders which are initialized with the role-level context
    pub fn role_group_builders(&self) -> Vec<RoleGroupBuilder<'_>> {
        self.cluster
            .role_group_configs
            .iter()
            .map(|(role_group_name, role_group_config)| {
                RoleGroupBuilder::new(
                    self.resource_names.service_account_name(),
                    self.cluster.clone(),
                    role_group_name.clone(),
                    role_group_config.clone(),
                    self.context_names,
                    seed_nodes_service_name(&self.cluster.name),
                    discovery_service_listener_name(&self.cluster.name),
                )
            })
            .collect()
    }

    /// Builds a ServiceAccount used by all role-groups
    pub fn build_service_account(&self) -> ServiceAccount {
        let metadata = self.common_metadata(self.resource_names.service_account_name());

        ServiceAccount {
            metadata,
            ..ServiceAccount::default()
        }
    }

    /// Builds a RoleBinding used by all role-groups
    pub fn build_role_binding(&self) -> RoleBinding {
        let metadata = self.common_metadata(self.resource_names.role_binding_name());

        RoleBinding {
            metadata,
            role_ref: RoleRef {
                api_group: ClusterRole::GROUP.to_owned(),
                kind: ClusterRole::KIND.to_owned(),
                name: self.resource_names.cluster_role_name().to_string(),
            },
            subjects: Some(vec![Subject {
                api_group: Some(ServiceAccount::GROUP.to_owned()),
                kind: ServiceAccount::KIND.to_owned(),
                name: self.resource_names.service_account_name().to_string(),
                namespace: Some(self.cluster.namespace.to_string()),
            }]),
        }
    }

    /// Builds a Service that references all nodes with the cluster_manager node role
    pub fn build_seed_nodes_service(&self) -> Service {
        let ports = vec![ServicePort {
            name: Some(TRANSPORT_PORT_NAME.to_owned()),
            port: TRANSPORT_PORT.into(),
            ..ServicePort::default()
        }];

        let metadata = self.common_metadata(seed_nodes_service_name(&self.cluster.name));

        let service_selector =
            RoleGroupBuilder::cluster_manager_labels(&self.cluster, self.context_names);

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

    /// Builds a Listener whose status is used to populate the discovery ConfigMap.
    pub fn build_discovery_service_listener(&self) -> listener::v1alpha1::Listener {
        let metadata = self.common_metadata(discovery_service_listener_name(&self.cluster.name));

        let listener_class = &self.cluster.role_config.discovery_service_listener_class;

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

    /// Builds the discovery ConfigMap if the discovery endpoint is already known.
    ///
    /// The discovery endpoint is derived from the status of the discovery service Listener. If the
    /// status is not set yet, the reconciliation process will occur again once the Listener status
    /// is updated, leading to the eventual creation of the discovery ConfigMap.
    pub fn build_discovery_config_map(&self) -> Option<ConfigMap> {
        let discovery_endpoint = self.cluster.discovery_endpoint.as_ref()?;

        let metadata = self.common_metadata(discovery_config_map_name(&self.cluster.name));

        let data = [
            (
                "OPENSEARCH_PROTOCOL".to_owned(),
                if self.cluster.tls_config.server_secret_class.is_some() {
                    "https".to_owned()
                } else {
                    "http".to_owned()
                },
            ),
            (
                "OPENSEARCH_HOST".to_owned(),
                discovery_endpoint.hostname.to_string(),
            ),
            (
                "OPENSEARCH_PORT".to_owned(),
                discovery_endpoint.port.to_string(),
            ),
        ];

        Some(ConfigMap {
            metadata,
            data: Some(data.into()),
            ..ConfigMap::default()
        })
    }

    /// Builds a [`PodDisruptionBudget`] used by all role-groups
    pub fn build_pdb(&self) -> Option<PodDisruptionBudget> {
        let pdb_config = &self.cluster.role_config.common.pod_disruption_budget;

        if pdb_config.enabled {
            let max_unavailable = pdb_config
                .max_unavailable
                .unwrap_or(PDB_DEFAULT_MAX_UNAVAILABLE);
            Some(
                pod_disruption_budget_builder_with_role(
                    &self.cluster,
                    &self.context_names.product_name,
                    &ValidatedCluster::role_name(),
                    &self.context_names.operator_name,
                    &self.context_names.controller_name,
                )
                .with_max_unavailable(max_unavailable)
                .build(),
            )
        } else {
            None
        }
    }

    /// Common metadata for role resources
    fn common_metadata(&self, resource_name: impl Into<String>) -> ObjectMeta {
        ObjectMetaBuilder::new()
            .name(resource_name)
            .namespace(&self.cluster.namespace)
            .ownerreference(ownerreference_from_resource(
                &self.cluster,
                None,
                Some(true),
            ))
            .with_labels(self.labels())
            .build()
    }

    /// Common labels for role resources
    fn labels(&self) -> Labels {
        // Well-known Kubernetes labels
        let mut labels = Labels::role_selector(
            &self.cluster,
            &self.context_names.product_name.to_label_value(),
            &ValidatedCluster::role_name().to_label_value(),
        )
        .unwrap();

        let managed_by = Label::managed_by(
            self.context_names.operator_name.as_ref(),
            self.context_names.controller_name.as_ref(),
        )
        .unwrap();
        let version = Label::version(self.cluster.product_version.as_ref()).unwrap();

        labels.insert(managed_by);
        labels.insert(version);

        // Stackable-specific labels
        labels
            .parse_insert((STACKABLE_VENDOR_KEY, STACKABLE_VENDOR_VALUE))
            .unwrap();

        labels
    }
}

fn seed_nodes_service_name(cluster_name: &ClusterName) -> ServiceName {
    const SUFFIX: &str = "-seed-nodes";

    // compile-time checks
    const _: () = assert!(
        ClusterName::MAX_LENGTH + SUFFIX.len() <= ServiceName::MAX_LENGTH,
        "The string `<cluster_name>-seed-nodes` must not exceed the limit of Service names."
    );
    let _ = ClusterName::IS_RFC_1035_LABEL_NAME;
    let _ = ClusterName::IS_VALID_LABEL_VALUE;

    ServiceName::from_str(&format!("{}{SUFFIX}", cluster_name.as_ref()))
        .expect("should be a valid Service name")
}

fn discovery_config_map_name(cluster_name: &ClusterName) -> ConfigMapName {
    // compile-time checks
    const _: () = assert!(
        ClusterName::MAX_LENGTH <= ConfigMapName::MAX_LENGTH,
        "The string `<cluster_name>` must not exceed the limit of ConfigMap names."
    );
    let _ = ClusterName::IS_RFC_1123_SUBDOMAIN_NAME;

    ConfigMapName::from_str(cluster_name.as_ref()).expect("should be a valid ConfigMap name")
}

pub fn discovery_service_listener_name(cluster_name: &ClusterName) -> ListenerName {
    // compile-time checks
    const _: () = assert!(
        ClusterName::MAX_LENGTH <= ListenerName::MAX_LENGTH,
        "The string `<cluster_name>` must not exceed the limit of Listener names."
    );
    let _ = ClusterName::IS_RFC_1123_SUBDOMAIN_NAME;

    ListenerName::from_str(cluster_name.as_ref()).expect("should be a valid Listener name")
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
            affinity::StackableAffinity,
            networking::DomainName,
            product_image_selection::{ProductImage, ResolvedProductImage},
            resources::Resources,
        },
        k8s_openapi::api::core::v1::PodTemplateSpec,
        kvp::LabelValue,
        product_logging::spec::AutomaticContainerLogConfig,
        shared::time::Duration,
    };
    use uuid::uuid;

    use super::RoleBuilder;
    use crate::{
        controller::{
            ContextNames, OpenSearchRoleGroupConfig, ValidatedCluster,
            ValidatedContainerLogConfigChoice, ValidatedDiscoveryEndpoint, ValidatedLogging,
            ValidatedOpenSearchConfig,
            build::role_builder::{
                discovery_config_map_name, discovery_service_listener_name, seed_nodes_service_name,
            },
        },
        crd::{NodeRoles, v1alpha1},
        framework::{
            builder::pod::container::EnvVarSet,
            role_utils::GenericProductSpecificCommonConfig,
            types::{
                common::Port,
                kubernetes::{
                    ConfigMapName, Hostname, ListenerClassName, ListenerName, NamespaceName,
                    ServiceName,
                },
                operator::{
                    ClusterName, ControllerName, OperatorName, ProductName, ProductVersion,
                    RoleGroupName,
                },
            },
        },
    };

    fn context_names() -> ContextNames {
        ContextNames {
            product_name: ProductName::from_str_unsafe("opensearch"),
            operator_name: OperatorName::from_str_unsafe("opensearch.stackable.tech"),
            controller_name: ControllerName::from_str_unsafe("opensearchcluster"),
            cluster_domain_name: DomainName::from_str("cluster.local")
                .expect("should be a valid domain name"),
        }
    }

    fn role_builder<'a>(context_names: &'a ContextNames) -> RoleBuilder<'a> {
        let image: ProductImage = serde_json::from_str(r#"{"productVersion": "3.1.0"}"#)
            .expect("should be a valid ProductImage");

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
                    vector_container: None,
                },
                node_roles: NodeRoles(vec![
                    v1alpha1::NodeRole::ClusterManager,
                    v1alpha1::NodeRole::Data,
                    v1alpha1::NodeRole::Ingest,
                    v1alpha1::NodeRole::RemoteClusterClient,
                ]),
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

        let cluster = ValidatedCluster::new(
            ResolvedProductImage {
                product_version: "3.1.0".to_owned(),
                app_version_label_value: LabelValue::from_str("3.1.0-stackable0.0.0-dev")
                    .expect("should be a valid label value"),
                image: "oci.stackable.tech/sdp/opensearch:3.1.0-stackable0.0.0-dev".to_string(),
                image_pull_policy: "Always".to_owned(),
                pull_secrets: None,
            },
            ProductVersion::from_str_unsafe(image.product_version()),
            ClusterName::from_str_unsafe("my-opensearch-cluster"),
            NamespaceName::from_str_unsafe("default"),
            uuid!("0b1e30e6-326e-4c1a-868d-ad6598b49e8b"),
            v1alpha1::OpenSearchRoleConfig {
                discovery_service_listener_class: ListenerClassName::from_str_unsafe(
                    "external-stable",
                ),
                ..v1alpha1::OpenSearchRoleConfig::default()
            },
            [(
                RoleGroupName::from_str_unsafe("default"),
                role_group_config.clone(),
            )]
            .into(),
            v1alpha1::OpenSearchTls::default(),
            vec![],
            Some(ValidatedDiscoveryEndpoint {
                hostname: Hostname::from_str_unsafe("1.2.3.4"),
                port: Port(12345),
            }),
        );

        RoleBuilder::new(cluster, context_names)
    }

    #[test]
    fn test_build_service_account() {
        let context_names = context_names();
        let role_builder = role_builder(&context_names);

        let service_account = serde_json::to_value(role_builder.build_service_account())
            .expect("should be serializable");

        assert_eq!(
            json!({
                "apiVersion": "v1",
                "kind": "ServiceAccount",
                "metadata": {
                    "labels": {
                        "app.kubernetes.io/component": "nodes",
                        "app.kubernetes.io/instance": "my-opensearch-cluster",
                        "app.kubernetes.io/managed-by": "opensearch.stackable.tech_opensearchcluster",
                        "app.kubernetes.io/name": "opensearch",
                        "app.kubernetes.io/version": "3.1.0",
                        "stackable.tech/vendor": "Stackable"
                    },
                    "name": "my-opensearch-cluster-serviceaccount",
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
                }
            }),
            service_account
        );
    }

    #[test]
    fn test_build_role_binding() {
        let context_names = context_names();
        let role_builder = role_builder(&context_names);

        let role_binding = serde_json::to_value(role_builder.build_role_binding())
            .expect("should be serializable");

        assert_eq!(
            json!({
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "RoleBinding",
                "metadata": {
                    "labels": {
                        "app.kubernetes.io/component": "nodes",
                        "app.kubernetes.io/instance": "my-opensearch-cluster",
                        "app.kubernetes.io/managed-by": "opensearch.stackable.tech_opensearchcluster",
                        "app.kubernetes.io/name": "opensearch",
                        "app.kubernetes.io/version": "3.1.0",
                        "stackable.tech/vendor": "Stackable"
                    },
                    "name": "my-opensearch-cluster-rolebinding",
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
                "roleRef": {
                    "apiGroup": "rbac.authorization.k8s.io",
                    "kind": "ClusterRole",
                    "name": "opensearch-clusterrole"
                },
                "subjects": [
                    {
                        "apiGroup": "",
                        "kind": "ServiceAccount",
                        "name": "my-opensearch-cluster-serviceaccount",
                        "namespace": "default"
                    }
                ]
            }),
            role_binding
        );
    }

    #[test]
    fn test_build_seed_nodes_service() {
        let context_names = context_names();
        let role_builder = role_builder(&context_names);

        let seed_nodes_service = serde_json::to_value(role_builder.build_seed_nodes_service())
            .expect("should be serializable");

        assert_eq!(
            json!({
                "apiVersion": "v1",
                "kind": "Service",
                "metadata": {
                    "labels": {
                        "app.kubernetes.io/component": "nodes",
                        "app.kubernetes.io/instance": "my-opensearch-cluster",
                        "app.kubernetes.io/managed-by": "opensearch.stackable.tech_opensearchcluster",
                        "app.kubernetes.io/name": "opensearch",
                        "app.kubernetes.io/version": "3.1.0",
                        "stackable.tech/vendor": "Stackable"
                    },
                    "name": "my-opensearch-cluster-seed-nodes",
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
                            "name": "transport",
                            "port": 9300
                        }
                    ],
                    "publishNotReadyAddresses": true,
                    "selector": {
                        "app.kubernetes.io/component": "nodes",
                        "app.kubernetes.io/instance": "my-opensearch-cluster",
                        "app.kubernetes.io/name": "opensearch",
                        "stackable.tech/opensearch-role.cluster_manager": "true"
                    },
                    "type": "ClusterIP"
                }
            }),
            seed_nodes_service
        );
    }

    #[test]
    fn test_build_discovery_service_listener() {
        let context_names = context_names();
        let role_builder = role_builder(&context_names);

        let discovery_service_listener =
            serde_json::to_value(role_builder.build_discovery_service_listener())
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
                        "app.kubernetes.io/version": "3.1.0",
                        "stackable.tech/vendor": "Stackable",
                    },
                    "name": "my-opensearch-cluster",
                    "namespace": "default",
                    "ownerReferences": [
                        {
                            "apiVersion": "opensearch.stackable.tech/v1alpha1",
                            "controller": true,
                            "kind": "OpenSearchCluster",
                            "name": "my-opensearch-cluster",
                            "uid": "0b1e30e6-326e-4c1a-868d-ad6598b49e8b",
                        },
                    ],
                },
                "spec": {
                    "className": "external-stable",
                    "extraPodSelectorLabels": {},
                    "ports": [
                        {
                            "name": "http",
                            "port": 9200,
                            "protocol": "TCP",
                        },
                    ],
                    "publishNotReadyAddresses": null,
                },
            }),
            discovery_service_listener
        );
    }

    #[test]
    fn test_build_discovery_config_map() {
        let context_names = context_names();
        let role_builder = role_builder(&context_names);

        let discovery_config_map = serde_json::to_value(role_builder.build_discovery_config_map())
            .expect("should be serializable");

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
                        "app.kubernetes.io/version": "3.1.0",
                        "stackable.tech/vendor": "Stackable",
                    },
                    "name": "my-opensearch-cluster",
                    "namespace": "default",
                    "ownerReferences": [
                        {
                            "apiVersion": "opensearch.stackable.tech/v1alpha1",
                            "controller": true,
                            "kind": "OpenSearchCluster",
                            "name": "my-opensearch-cluster",
                            "uid": "0b1e30e6-326e-4c1a-868d-ad6598b49e8b",
                        },
                    ],
                },
                "data": {
                    "OPENSEARCH_HOST": "1.2.3.4",
                    "OPENSEARCH_PORT": "12345",
                    "OPENSEARCH_PROTOCOL": "https",
                },
            }),
            discovery_config_map
        );
    }

    #[test]
    fn test_build_pdb() {
        let context_names = context_names();
        let role_builder = role_builder(&context_names);

        let pdb = serde_json::to_value(role_builder.build_pdb()).expect("should be serializable");

        assert_eq!(
            json!({
                "apiVersion": "policy/v1",
                "kind": "PodDisruptionBudget",
                "metadata": {
                    "labels": {
                        "app.kubernetes.io/component": "nodes",
                        "app.kubernetes.io/instance": "my-opensearch-cluster",
                        "app.kubernetes.io/managed-by": "opensearch.stackable.tech_opensearchcluster",
                        "app.kubernetes.io/name": "opensearch"
                    },
                    "name": "my-opensearch-cluster-nodes",
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
                    "maxUnavailable": 1,
                    "selector": {
                        "matchLabels": {
                            "app.kubernetes.io/component": "nodes",
                            "app.kubernetes.io/instance": "my-opensearch-cluster",
                            "app.kubernetes.io/name": "opensearch"
                        }
                    }
                }
            }),
            pdb
        );
    }

    #[test]
    fn test_seed_nodes_service_name() {
        let cluster_name = ClusterName::from_str_unsafe("test-cluster");

        assert_eq!(
            ServiceName::from_str_unsafe("test-cluster-seed-nodes"),
            seed_nodes_service_name(&cluster_name)
        );
    }

    #[test]
    fn test_discovery_config_map_name() {
        let cluster_name = ClusterName::from_str_unsafe("test-cluster");

        assert_eq!(
            ConfigMapName::from_str_unsafe("test-cluster"),
            discovery_config_map_name(&cluster_name)
        );
    }

    #[test]
    fn test_discovery_service_listener_name() {
        let cluster_name = ClusterName::from_str_unsafe("test-cluster");

        assert_eq!(
            ListenerName::from_str_unsafe("test-cluster"),
            discovery_service_listener_name(&cluster_name)
        );
    }
}
